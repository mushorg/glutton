package protocols

import (
	"bufio"
	"net"
	"time"
)

// BufferedConn provides an interface to peek at a connection
type BufferedConn struct {
	r        *bufio.Reader
	net.Conn // So that most methods are embedded
}

func newBufferedConn(c net.Conn) BufferedConn {
	return BufferedConn{bufio.NewReader(c), c}
}

func (b BufferedConn) peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// Peek reads `length` amount of data from the connection
func Peek(conn net.Conn, length int) ([]byte, BufferedConn, error) {
	bufConn := newBufferedConn(conn)
	if err := bufConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return nil, bufConn, err
	}
	snip, err := bufConn.peek(length)
	return snip, bufConn, err
}
