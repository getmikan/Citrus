package outbound

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/loopback"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDirectRejectsLoopThroughListener: DIRECT is asked to dial a listener
// that hands its connections back to DIRECT. The connection the listener
// accepts comes from DIRECT itself and must be refused, while a connection
// from the same source address to another destination must not be.
func TestDirectRejectsLoopThroughListener(t *testing.T) {
	d := NewDirect()
	if d.loopBack == nil {
		t.Skip("loopback detector disabled")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	listenAddr := ln.Addr().(*net.TCPAddr).AddrPort()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := d.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		DstIP:   listenAddr.Addr(),
		DstPort: listenAddr.Port(),
	})
	require.NoError(t, err)
	defer out.Close()

	var in net.Conn
	select {
	case in = <-accepted:
	case <-ctx.Done():
		t.Fatal("listener did not accept")
	}
	defer in.Close()

	// What an inbound records for the accepted connection.
	src := in.RemoteAddr().(*net.TCPAddr).AddrPort()
	inAddr := in.LocalAddr().(*net.TCPAddr).AddrPort()
	looped := &C.Metadata{
		NetWork: C.TCP,
		SrcIP:   src.Addr().Unmap(),
		SrcPort: src.Port(),
		InIP:    inAddr.Addr().Unmap(),
		InPort:  inAddr.Port(),
		Host:    "example.com",
		DstPort: 443,
	}
	_, err = d.DialContext(ctx, looped)
	assert.True(t, errors.Is(err, loopback.ErrReject), "looped connection must be rejected, got %v", err)

	// Same source address, but it arrived on another listener: not DIRECT's
	// connection (the kernel may reuse the ephemeral port for a different
	// destination).
	other := *looped
	other.InPort = listenAddr.Port() + 1
	assert.NoError(t, d.loopBack.CheckConn(&other))

	// Once DIRECT's connection is closed nothing is rejected.
	require.NoError(t, out.Close())
	assert.NoError(t, d.loopBack.CheckConn(looped))
}
