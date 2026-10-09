package guard

import (
	"errors"
	"net"
)

// ErrLimited is returned by a guarded Conn's Write when the bytes do not fit
// the peer's or the global budget. Nothing was written.
var ErrLimited = errors.New("guard: reply over budget")

// LimitFunc is called when a guarded Conn refuses a Write of size bytes.
type LimitFunc func(conn net.Conn, d Decision, size int)

// Conn charges every Write against the guard budget for the remote IP.
type Conn struct {
	net.Conn
	g       *Guard
	ip      net.IP
	onLimit LimitFunc
}

// tcpConn keeps the half-close and keepalive methods of a *net.TCPConn
// reachable through the wrapper.
type tcpConn struct {
	*Conn
	tcp *net.TCPConn
}

func (c *tcpConn) CloseWrite() error            { return c.tcp.CloseWrite() }
func (c *tcpConn) CloseRead() error             { return c.tcp.CloseRead() }
func (c *tcpConn) SetKeepAlive(keep bool) error { return c.tcp.SetKeepAlive(keep) }

// Wrap returns conn with its writes charged against g. A nil or disabled
// guard, or a conn without an IP remote address, is returned unchanged.
// onLimit may be nil.
func (g *Guard) Wrap(conn net.Conn, onLimit LimitFunc) net.Conn {
	if g == nil || !g.cfg.Enabled || conn == nil {
		return conn
	}
	var ip net.IP
	switch a := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		return conn
	}
	c := &Conn{Conn: conn, g: g, ip: ip, onLimit: onLimit}
	if tc, ok := conn.(*net.TCPConn); ok {
		return &tcpConn{Conn: c, tcp: tc}
	}
	return c
}

// Write sends p only if all of it fits the budget; otherwise it writes
// nothing and returns ErrLimited.
func (c *Conn) Write(p []byte) (int, error) {
	if d := c.g.Allow(c.ip, len(p)); !d.Allowed {
		if c.onLimit != nil {
			c.onLimit(c.Conn, d, len(p))
		}
		return 0, ErrLimited
	}
	return c.Conn.Write(p)
}

// Unwrap returns the underlying connection.
func (c *Conn) Unwrap() net.Conn { return c.Conn }
