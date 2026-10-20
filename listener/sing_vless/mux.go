package sing_vless

import (
	"net"
	"sync"
)

// Expose only net.Conn, so a direct ExtendedWriter cannot bypass this lock.
type muxWriteConn struct {
	net.Conn
	writeMu sync.Mutex
}

func (c *muxWriteConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.Write(p)
}
