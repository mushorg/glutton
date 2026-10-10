package protocols

import (
	"bufio"
	"bytes"
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

// peekLine peeks until the buffered bytes hold a newline or max bytes, so a
// short request line does not wait for the read deadline.
func (b BufferedConn) peekLine(max int) ([]byte, error) {
	for {
		snip, _ := b.r.Peek(min(b.r.Buffered(), max))
		if bytes.IndexByte(snip, '\n') >= 0 || len(snip) >= max {
			return snip, nil
		}
		// wait for at least one more byte
		if _, err := b.r.Peek(len(snip) + 1); err != nil {
			snip, _ = b.r.Peek(min(b.r.Buffered(), max))
			return snip, err
		}
	}
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
