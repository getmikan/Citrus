package statistic

import (
	"io"
	"net"
	stdatomic "sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	"github.com/gofrs/uuid/v5"
)

type Tracker interface {
	ID() string
	Close() error
	Info() *TrackerInfo
	C.Connection
}

type TrackerInfo struct {
	UUID          uuid.UUID    `json:"id"`
	Metadata      *C.Metadata  `json:"metadata"`
	UploadTotal   atomic.Int64 `json:"upload"`
	DownloadTotal atomic.Int64 `json:"download"`
	Start         time.Time    `json:"start"`
	Chain         C.Chain      `json:"chains"`
	ProviderChain C.Chain      `json:"providerChains"`
	Rule          string       `json:"rule"`
	RulePayload   string       `json:"rulePayload"`
}

type tcpTracker struct {
	C.Conn `json:"-"`
	*TrackerInfo
	manager *Manager
	user    *UserCounter
	binding userBinding
	inbound *InboundCounter
	closed  stdatomic.Bool

	pushToManager bool `json:"-"`

	// allocated with the tracker rather than on their own or on every call
	info TrackerInfo
	id   string
	// the count functions UnwrapReader and UnwrapWriter hand out: the copy
	// loop asks for them more than once per connection
	downCounters [1]N.CountFunc
	upCounters   [1]N.CountFunc
}

func (tt *tcpTracker) ID() string {
	return tt.id
}

func (tt *tcpTracker) Info() *TrackerInfo {
	return tt.TrackerInfo
}

// countDown reports n downloaded bytes and, when the user has a speed limit,
// waits for its download bucket.
func (tt *tcpTracker) countDown(n int64) {
	if tt.pushToManager {
		tt.manager.PushDownloaded(n)
	}
	tt.inbound.addDown(n)
	if u := tt.user; u != nil {
		u.AddDown(n)
		if l := u.limit.Load(); l != nil {
			l.addDown(n, &tt.closed)
		}
	}
	tt.DownloadTotal.Add(n)
}

// countUp reports n uploaded bytes and, when the user has a speed limit,
// waits for its upload bucket.
func (tt *tcpTracker) countUp(n int64) {
	if tt.pushToManager {
		tt.manager.PushUploaded(n)
	}
	tt.inbound.addUp(n)
	if u := tt.user; u != nil {
		u.AddUp(n)
		if l := u.limit.Load(); l != nil {
			l.addUp(n, &tt.closed)
		}
	}
	tt.UploadTotal.Add(n)
}

// speedLimited reports whether the copy in that direction must go through
// Read/Write rather than splice: when the user has a speed limit, or a quota
// (a splice step could move a megabyte past it).
func (tt *tcpTracker) speedLimited(up bool) bool {
	if u := tt.user; u != nil {
		if l := u.limit.Load(); l != nil {
			return l.hasSpeed(up) || l.hasQuota()
		}
	}
	return false
}

// overQuota reports whether the user of a tracker has used up its quota.
func overQuota(u *UserCounter) bool {
	if u != nil {
		if l := u.limit.Load(); l != nil {
			return l.overQuota()
		}
	}
	return false
}

func (tt *tcpTracker) Read(b []byte) (int, error) {
	if overQuota(tt.user) {
		return 0, ErrQuotaExceeded
	}
	n, err := tt.Conn.Read(b)
	tt.countDown(int64(n))
	return n, err
}

func (tt *tcpTracker) ReadBuffer(buffer *buf.Buffer) (err error) {
	if overQuota(tt.user) {
		return ErrQuotaExceeded
	}
	err = tt.Conn.ReadBuffer(buffer)
	tt.countDown(int64(buffer.Len()))
	return
}

// UnwrapReader hands the copy loop the inner connection and a count function,
// so that it can splice. A user with a download speed limit gets a reader
// over the tracker instead: the copy goes through Read, a buffer at a time,
// and keeps to the rate smoothly, where a splice moves up to a megabyte per
// step. A limit set while a splice already runs is still honoured, by the
// count function, in steps of what the splice moved.
func (tt *tcpTracker) UnwrapReader() (io.Reader, []N.CountFunc) {
	if tt.speedLimited(false) {
		return trackerReader{tt}, nil
	}
	return tt.Conn, tt.downCounters[:1:1] // full: an append copies it
}

func (tt *tcpTracker) Write(b []byte) (int, error) {
	if overQuota(tt.user) {
		return 0, ErrQuotaExceeded
	}
	n, err := tt.Conn.Write(b)
	tt.countUp(int64(n))
	return n, err
}

func (tt *tcpTracker) WriteBuffer(buffer *buf.Buffer) (err error) {
	if overQuota(tt.user) {
		buffer.Release()
		return ErrQuotaExceeded
	}
	upload := int64(buffer.Len())
	err = tt.Conn.WriteBuffer(buffer)
	tt.countUp(upload)
	return
}

// UnwrapWriter is UnwrapReader for the upload direction.
func (tt *tcpTracker) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if tt.speedLimited(true) {
		return trackerWriter{tt}, nil
	}
	return tt.Conn, tt.upCounters[:1:1]
}

// trackerReader and trackerWriter expose only the reading or the writing
// methods of a tracker, so that the copy loop neither unwraps nor splices it.
type trackerReader struct{ t *tcpTracker }

func (r trackerReader) Read(b []byte) (int, error)          { return r.t.Read(b) }
func (r trackerReader) ReadBuffer(buffer *buf.Buffer) error { return r.t.ReadBuffer(buffer) }

// CreateReadWaiter keeps the read waiter of the connection (a socket waits
// for data before it takes a buffer) for a user with a limit: the reader
// counts and throttles what each wait returns, as Read does. Without it the
// copy reads through Read and holds a full pool buffer while the remote is
// silent, for as long as the connection stays open.
func (r trackerReader) CreateReadWaiter() (N.ReadWaiter, bool) {
	inner, counters := N.UnwrapCountReader(r.t.Conn, nil)
	if _, isCached := inner.(N.CachedReader); isCached {
		return nil, false // the copy reads the cached data through Read
	}
	waiter, ok := N.CreateReadWaiter(inner)
	if !ok {
		return nil, false
	}
	return &trackerReadWaiter{t: r.t, waiter: waiter, counters: counters}, true
}

type trackerReadWaiter struct {
	t        *tcpTracker
	waiter   N.ReadWaiter
	counters []N.CountFunc
}

func (w *trackerReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.waiter.InitializeReadWaiter(options)
}

func (w *trackerReadWaiter) WaitReadBuffer() (*buf.Buffer, error) {
	if overQuota(w.t.user) {
		return nil, ErrQuotaExceeded
	}
	buffer, err := w.waiter.WaitReadBuffer()
	if err != nil {
		return nil, err
	}
	n := int64(buffer.Len())
	for _, counter := range w.counters {
		counter(n)
	}
	w.t.countDown(n)
	return buffer, nil
}

type trackerWriter struct{ t *tcpTracker }

func (w trackerWriter) Write(b []byte) (int, error)          { return w.t.Write(b) }
func (w trackerWriter) WriteBuffer(buffer *buf.Buffer) error { return w.t.WriteBuffer(buffer) }

func (tt *tcpTracker) Close() error {
	if tt.closed.CompareAndSwap(false, true) {
		tt.manager.Leave(tt)
		tt.binding.release()
		tt.inbound.release()
	}
	return tt.Conn.Close()
}

func (tt *tcpTracker) Upstream() any {
	return tt.Conn
}

func NewTCPTracker(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *tcpTracker {
	return newTCPTracker(conn, manager, metadata, rule, uploadTotal, downloadTotal, pushToManager, bindUser(manager, metadata, pushToManager))
}

// NewTCPTrackerAdmitted tracks a connection admitted with Manager.Admit. The
// tracker takes the admission over and releases it when it is closed.
func NewTCPTrackerAdmitted(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, admission Admission) *tcpTracker {
	return newTCPTracker(conn, manager, metadata, rule, uploadTotal, downloadTotal, true, admission.binding)
}

func newTCPTracker(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool, binding userBinding) *tcpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	t := &tcpTracker{
		Conn:    conn,
		manager: manager,
		info: TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
		binding:       binding,
	}
	t.TrackerInfo = &t.info
	t.id = t.info.UUID.String()
	t.downCounters[0] = t.countDown
	t.upCounters[0] = t.countUp
	t.user = t.binding.counter
	t.inbound = manager.bindInbound(metadata, pushToManager)
	t.inbound.addUp(uploadTotal)
	t.inbound.addDown(downloadTotal)

	if pushToManager {
		if uploadTotal > 0 {
			manager.PushUploaded(uploadTotal)
		}
		if downloadTotal > 0 {
			manager.PushDownloaded(downloadTotal)
		}
	}
	t.user.addInitial(uploadTotal, downloadTotal)

	if rule != nil {
		t.TrackerInfo.Rule = rule.RuleType().String()
		t.TrackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(t)
	return t
}

type udpTracker struct {
	C.PacketConn `json:"-"`
	*TrackerInfo
	manager *Manager
	user    *UserCounter
	binding userBinding
	inbound *InboundCounter
	closed  stdatomic.Bool

	pushToManager bool `json:"-"`
}

func (ut *udpTracker) ID() string {
	return ut.UUID.String()
}

func (ut *udpTracker) Info() *TrackerInfo {
	return ut.TrackerInfo
}

func (ut *udpTracker) countDown(n int64) {
	if ut.pushToManager {
		ut.manager.PushDownloaded(n)
	}
	ut.inbound.addDown(n)
	if u := ut.user; u != nil {
		u.AddDown(n)
		if l := u.limit.Load(); l != nil {
			l.addDown(n, &ut.closed)
		}
	}
	ut.DownloadTotal.Add(n)
}

func (ut *udpTracker) countUp(n int64) {
	if ut.pushToManager {
		ut.manager.PushUploaded(n)
	}
	ut.inbound.addUp(n)
	if u := ut.user; u != nil {
		u.AddUp(n)
		if l := u.limit.Load(); l != nil {
			l.addUp(n, &ut.closed)
		}
	}
	ut.UploadTotal.Add(n)
}

func (ut *udpTracker) ReadFrom(b []byte) (int, net.Addr, error) {
	if overQuota(ut.user) {
		return 0, nil, ErrQuotaExceeded
	}
	n, addr, err := ut.PacketConn.ReadFrom(b)
	ut.countDown(int64(n))
	return n, addr, err
}

func (ut *udpTracker) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	if overQuota(ut.user) {
		return nil, nil, nil, ErrQuotaExceeded
	}
	data, put, addr, err = ut.PacketConn.WaitReadFrom()
	ut.countDown(int64(len(data)))
	return
}

func (ut *udpTracker) WriteTo(b []byte, addr net.Addr) (int, error) {
	if overQuota(ut.user) {
		return 0, ErrQuotaExceeded
	}
	n, err := ut.PacketConn.WriteTo(b, addr)
	ut.countUp(int64(n))
	return n, err
}

func (ut *udpTracker) Close() error {
	if ut.closed.CompareAndSwap(false, true) {
		ut.manager.Leave(ut)
		ut.binding.release()
		ut.inbound.release()
	}
	return ut.PacketConn.Close()
}

func (ut *udpTracker) Upstream() any {
	return ut.PacketConn
}

func NewUDPTracker(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *udpTracker {
	return newUDPTracker(conn, manager, metadata, rule, uploadTotal, downloadTotal, pushToManager, bindUser(manager, metadata, pushToManager))
}

// NewUDPTrackerAdmitted tracks a UDP session admitted with Manager.Admit. The
// tracker takes the admission over and releases it when it is closed.
func NewUDPTrackerAdmitted(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, admission Admission) *udpTracker {
	return newUDPTracker(conn, manager, metadata, rule, uploadTotal, downloadTotal, true, admission.binding)
}

func newUDPTracker(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool, binding userBinding) *udpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	ut := &udpTracker{
		PacketConn: conn,
		manager:    manager,
		TrackerInfo: &TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
		binding:       binding,
	}
	ut.user = ut.binding.counter
	ut.inbound = manager.bindInbound(metadata, pushToManager)
	ut.inbound.addUp(uploadTotal)
	ut.inbound.addDown(downloadTotal)

	if pushToManager {
		if uploadTotal > 0 {
			manager.PushUploaded(uploadTotal)
		}
		if downloadTotal > 0 {
			manager.PushDownloaded(downloadTotal)
		}
	}
	ut.user.addInitial(uploadTotal, downloadTotal)

	if rule != nil {
		ut.TrackerInfo.Rule = rule.RuleType().String()
		ut.TrackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(ut)
	return ut
}
