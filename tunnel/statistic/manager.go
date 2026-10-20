package statistic

import (
	"os"
	stdatomic "sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		pid:           int32(os.Getpid()),
	}

	go DefaultManager.handle()
}

type Manager struct {
	connections   xsync.Map[string, Tracker]
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	pid           int32
	memory        uint64
	users         stdatomic.Pointer[UserManager]
	inbounds      xsync.Map[string, *InboundCounter]
	opened        stdatomic.Int64
	onLeave       stdatomic.Pointer[func(Tracker)]
}

// Users returns the per-user counters, creating them on first use.
func (m *Manager) Users() *UserManager {
	if um := m.users.Load(); um != nil {
		return um
	}
	um := NewUserManager()
	um.SetCloser(m.closeUserIf)
	m.users.CompareAndSwap(nil, um)
	return m.users.Load()
}

// CloseUser closes the tracked connections of an inbound user.
func (m *Manager) CloseUser(key UserKey) { m.closeUserIf(key, nil) }

// closeUserIf closes the tracked connections of an inbound user, each one only
// while still (when not nil) returns true.
func (m *Manager) closeUserIf(key UserKey, still func() bool) {
	m.Range(func(c Tracker) bool {
		if md := c.Info().Metadata; md != nil && md.InName == key.Inbound && md.InUser == key.User {
			if still != nil && !still() {
				return false
			}
			_ = c.Close()
		}
		return true
	})
}

func (m *Manager) Join(c Tracker) {
	m.opened.Add(1)
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
	if f := m.onLeave.Load(); f != nil {
		(*f)(c)
	}
}

// SetOnLeave sets a function called once for every tracked connection and UDP
// session when it ends, with its metadata (the inbound, the user and the
// sniffed host) and its totals: an embedding application can sum the traffic
// by destination without wrapping the connections, which would keep them from
// being spliced. It runs in the Close of the connection, so it must be quick.
// nil removes it.
func (m *Manager) SetOnLeave(f func(c Tracker)) {
	if f == nil {
		m.onLeave.Store(nil)
		return
	}
	m.onLeave.Store(&f)
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

// CloseUserConnections closes the connections of the given users of an
// inbound (metadata.InName and metadata.InUser) and returns how many it
// closed. An empty user name never matches.
func (m *Manager) CloseUserConnections(inbound string, users ...string) int {
	if len(users) == 0 {
		return 0
	}
	set := make(map[string]struct{}, len(users))
	for _, user := range users {
		if user != "" {
			set[user] = struct{}{}
		}
	}
	closed := 0
	m.Range(func(c Tracker) bool {
		if md := c.Info().Metadata; md != nil && md.InName == inbound {
			if _, ok := set[md.InUser]; ok {
				_ = c.Close()
				closed++
			}
		}
		return true
	})
	return closed
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)
	lastSweep := time.Now()

	for now := range ticker.C {
		m.uploadBlip.Store(m.uploadTemp.Swap(0))
		m.downloadBlip.Store(m.downloadTemp.Swap(0))
		if now.Sub(lastSweep) >= userSweepInterval {
			lastSweep = now
			if um := m.users.Load(); um != nil {
				um.Sweep()
			}
		}
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
