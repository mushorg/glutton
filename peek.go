package glutton

import (
	"bufio"
	"net"
)

// BufferedConn provides an interface to peek at a connection
type BufferedConn struct {
	r        *bufio.Reader
	net.Conn // So that most methods are embedded
}

func newBufferedConn(c net.Conn) BufferedConn {
	return BufferedConn{bufio.NewReader(c), c}
}

func newBufferedConnSize(c net.Conn, n int) BufferedConn {
	return BufferedConn{bufio.NewReaderSize(c, n), c}
}

func (b BufferedConn) peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// Peek reads `length` amount of data from the connection
func Peek(conn net.Conn, length int) (snip []byte, bufConn BufferedConn, err error) {
	bufConn = newBufferedConn(conn)
	snip, err = bufConn.peek(length)
	if err != nil {
		return
	}
	return
}
