package kcptun

import (
	"net"
	"sync"
	"time"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/smux"
)

type Server struct {
	config   Config
	block    kcp.BlockCrypt
	sessions chan struct{}
}

func NewServer(config Config) *Server {
	config.FillDefaults()
	block := config.NewBlock()

	return &Server{
		config:   config,
		block:    block,
		sessions: make(chan struct{}, config.MaxSessions),
	}
}

func (s *Server) Serve(pc net.PacketConn, handler func(net.Conn)) error {
	lis, err := kcp.ServeConn(s.block, s.config.DataShard, s.config.ParityShard, pc)
	if err != nil {
		return err
	}
	defer lis.Close()
	_ = lis.SetDSCP(s.config.DSCP)
	_ = lis.SetReadBuffer(s.config.SockBuf)
	_ = lis.SetWriteBuffer(s.config.SockBuf)
	var active sync.Map
	defer active.Range(func(key, _ any) bool { _ = key.(*kcp.UDPSession).Close(); return true })
	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			return err
		}
		select {
		case s.sessions <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		active.Store(conn, struct{}{})
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(s.config.NoDelay, s.config.Interval, s.config.Resend, s.config.NoCongestion)
		conn.SetMtu(s.config.MTU)
		conn.SetWindowSize(s.config.SndWnd, s.config.RcvWnd)
		conn.SetACKNoDelay(s.config.AckNodelay)
		conn.SetRateLimit(uint32(s.config.RateLimit))

		var netConn net.Conn = conn
		if !s.config.NoComp {
			netConn = NewCompStream(netConn)
		}

		go func() {
			defer func() { <-s.sessions }()
			defer active.Delete(conn)
			// stream multiplex
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = s.config.SmuxVer
			smuxConfig.MaxReceiveBuffer = s.config.SmuxBuf
			smuxConfig.MaxStreamBuffer = s.config.StreamBuf
			smuxConfig.MaxFrameSize = s.config.FrameSize
			smuxConfig.KeepAliveInterval = time.Duration(s.config.KeepAlive) * time.Second
			if smuxConfig.KeepAliveInterval >= smuxConfig.KeepAliveTimeout {
				smuxConfig.KeepAliveTimeout = 3 * smuxConfig.KeepAliveInterval
			}

			mux, err := smux.Server(netConn, smuxConfig)
			if err != nil {
				_ = netConn.Close()
				return
			}
			defer mux.Close()
			streams := make(chan struct{}, s.config.MaxStreams)
			var streamsMu sync.Mutex
			liveStreams := make(map[*limitedStream]struct{})
			defer func() {
				streamsMu.Lock()
				all := make([]*limitedStream, 0, len(liveStreams))
				for stream := range liveStreams {
					all = append(all, stream)
				}
				streamsMu.Unlock()
				for _, stream := range all {
					_ = stream.Close()
				}
			}()

			for {
				stream, err := mux.AcceptStream()
				if err != nil {
					return
				}
				select {
				case streams <- struct{}{}:
					leased := &limitedStream{Conn: stream}
					leased.release = func() {
						streamsMu.Lock()
						delete(liveStreams, leased)
						streamsMu.Unlock()
						<-streams
					}
					streamsMu.Lock()
					liveStreams[leased] = struct{}{}
					streamsMu.Unlock()
					// Handlers may transfer ownership and return before the stream
					// closes, so capacity belongs to the connection, not the call.
					go handler(leased)
				default:
					_ = stream.Close()
				}
			}
		}()

	}
}

type limitedStream struct {
	net.Conn
	once     sync.Once
	release  func()
	closeErr error
}

func (c *limitedStream) Upstream() any { return c.Conn }
func (c *limitedStream) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.release() })
	return c.closeErr
}
