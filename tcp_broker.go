package glutton

import (
	"errors"
	"log"
	"net"
	"os"
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
func ProxyServer(srvConn, cliConn *net.TCPConn, file *os.File) {

	// f = file
	log.SetOutput(file)
	serverClosed := make(chan struct{}, 1)
	clientClosed := make(chan struct{}, 1)

	go TCPBroker(srvConn, cliConn, clientClosed)
	go TCPBroker(cliConn, srvConn, serverClosed)

	var waitFor chan struct{}
	select {
	case <-clientClosed:
		srvConn.SetLinger(0)
		srvConn.CloseRead()
		waitFor = serverClosed
	case <-serverClosed:
		cliConn.CloseRead()
		waitFor = clientClosed
	}

	<-waitFor
}

// TCPBroker is handling a TCP connection
func TCPBroker(dst, src net.Conn, srcClosed chan struct{}) {

	_, err := transfer(dst, src, address{src.RemoteAddr(), dst.RemoteAddr()})

	if err != nil {
		log.Printf("Warning Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		log.Printf("Warning Close error: %s", err)
	}
	srcClosed <- struct{}{}
}

func transfer(dst writer, src reader, addr interface{}) (int64, error) {
	v := addr.(address)
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
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[0:nr])
			log.Printf("[TCP] [%v -> %v] Payload: %v", v.srcAddr, v.dstAddr, string(buf[0:nr]))
			if nw > 0 {
				written += int64(nw)
			}
			if writeErr != nil {
				err = writeErr
				break
			}
			if nr != nw {
				err = errors.New("Short write")
				break
			}
		}
		if readErr == errors.New("EOF") {
			break
		}
		if readErr != nil {
			err = readErr
			break
		}

	}
	return written, err
}
