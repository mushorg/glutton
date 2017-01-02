package glutton

import (
	"errors"
	"log"
	"net"
	"time"
)

type address struct {
	srcAddr net.Addr
	dstAddr net.Addr
}

type reader interface {
	Read(p []byte) (n int, err error)
}

type writer interface {
	Write(p []byte) (n int, err error)
}

type readerFrom interface {
	ReadFrom(r reader) (n int64, err error)
}

type writerTo interface {
	WriteTo(w writer) (n int64, err error)
}

const timeout = 3

var (
	id         int64 // id is used to relate logs in a connection
	Error      error
	EOF        = errors.New("EOF")
	ShortWrite = errors.New("ShortWriteError")
)

// TCPClient for proxy connections
func TCPClient(addr string) *net.TCPConn {

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Println("Error. ResolveTCPAddr failed:", err.Error())
		return nil
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Println("Error. Dial failed: Host either not active or not responding ", err.Error())
		return nil
	}

	return conn
}

// ProxyServer handles the proxy connections
func ProxyServer(id int64, srvConn, cliConn *net.TCPConn) (string, error) {
	serverClosed := make(chan struct{}, 1)
	clientClosed := make(chan struct{}, 1)

	go TCPBroker(srvConn, cliConn, clientClosed)
	go TCPBroker(cliConn, srvConn, serverClosed)

	var waitFor chan struct{}
	var closedBy string

	select {
	case <-clientClosed:
		closedBy = "Glutton"
		srvConn.SetLinger(0)
		srvConn.CloseRead()
		waitFor = serverClosed
	case <-serverClosed:
		closedBy = "Client"
		cliConn.CloseRead()
		waitFor = clientClosed
	}

	<-waitFor
	return closedBy, Error
}

// TCPBroker is handling a TCP connection
func TCPBroker(dst, src net.Conn, srcClosed chan struct{}) {

	_, err := transfer(dst, src, address{src.RemoteAddr(), dst.RemoteAddr()})

	if err != nil {
		Error = err
		log.Printf("Warning Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		Error = err
		log.Printf("Warning Close error: %s", err)
	}
	srcClosed <- struct{}{}
}

func transfer(dst writer, src reader, addr interface{}) (int64, error) {
	// v := addr.(address)
	if wt, ok := src.(writerTo); ok {
		return wt.WriteTo(dst)
	}

	if rt, ok := dst.(readerFrom); ok {
		return rt.ReadFrom(src)
	}

	buf := make([]byte, 32*1024)

	var written int64

	var err error

	for {
		src.(net.Conn).SetDeadline(time.Now().Add(timeout * time.Minute))
		nr, readErr := src.Read(buf)

		if nr > 0 {
			nw, writeErr := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if writeErr != nil {
				err = writeErr
				break
			}
			if nr != nw {
				err = ShortWrite
				break
			}
		}

		if readErr == EOF {
			err = EOF
			break
		}

		if readErr != nil {
			err = readErr
			break
		}
	}
	return written, err
}
