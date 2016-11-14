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

var ErrEOF = errors.New("[*] Error. EOF")

var ErrShortWrite = errors.New("[*] Error. short write")

func TCPClient(addr string) *net.TCPConn {

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		println("[*] Error. ResolveTCPAddr failed:", err.Error())
		return nil
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		println("[*] Error. Dial failed: Host either not active or not responding ", err.Error())
		return nil
	}

	return conn
}

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

func TCPBroker(dst, src net.Conn, srcClosed chan struct{}) {

	_, err := transfer(dst, src, address{src.RemoteAddr(), dst.RemoteAddr()})

	if err != nil {
		log.Printf("[*] Warning Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		log.Printf("[*] Warning Close error: %s", err)
	}
	srcClosed <- struct{}{}
}

func transfer(dst writer, src reader, addr interface{}) (written int64, err error) {
	v := addr.(address)
	if wt, ok := src.(writerTo); ok {
		return wt.WriteTo(dst)
	}

	if rt, ok := dst.(readerFrom); ok {
		return rt.ReadFrom(src)
	}

	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)
		log.Printf("[TCP] [%v -> %v] Payload: %v", v.srcAddr, v.dstAddr, string(buf[0:nr]))
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = ErrShortWrite
				break
			}
		}
		if er == ErrEOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}
