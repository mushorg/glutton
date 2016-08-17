package main

import (
	. "fmt"
	"github.com/hectane/go-nonblockingchan"
	"github.com/mushorg/glutton"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
)

func handleTCPClient(conn net.Conn, f *os.File, ch *nbc.NonBlockingChan) {
	log.SetOutput(f)

	// Splitting address to compare with conntrack logs
	tmp := conn.RemoteAddr().String()
	if tmp == "<nil>" {
		Println("Address:port == nil glutton_server.go conn.RemoteAddr().String()")
	}

	addr := strings.Split(tmp, ":")

	dp := glutton.GetTCPDesPort(addr, ch)

	if dp == -1 {
		Println("Packet dropped! [TCP] glutton_server.go desPort == -1")
		return
	}

	buf := make([]byte, 64000)
	for {
		n, err := conn.Read(buf[0:])
		if err != nil {
			return
		}
		log.Printf("[TCP] [ %v ] dport [%v] Message: %s", conn.RemoteAddr(), dp, string(buf[0:n]))
		_, err2 := conn.Write([]byte("Hello TCP Client:-)\n"))
		if err2 != nil {
			return
		}
	}

}

func tcpListener(f *os.File, ch *nbc.NonBlockingChan) {
	service := ":5000"

	addr, err := net.ResolveTCPAddr("tcp", service)
	glutton.CheckError(err)

	// Listener for incoming TCP connections
	listener, err := net.ListenTCP("tcp", addr)
	glutton.CheckError(err)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		// Goroutines to handle multiple connections
		go handleTCPClient(conn, f, ch)
	}
}

func handleUDPClient(conn *net.UDPConn, f *os.File, ch *nbc.NonBlockingChan) {
	log.SetOutput(f)
	b, oob := make([]byte, 64000), make([]byte, 4096)

	Println("Waiting")
	n, _, flags, addr, _ := conn.ReadMsgUDP(b, oob)

	tmp := addr.String()
	if tmp == "<nil>" {
		Println("Address:port == nil glutton_server.go addr.String()")
	}
	str := strings.Split(tmp, ":")
	dp := glutton.GetUDPDesPort(str, ch)
	if dp == -1 {
		log.Println("Packet dropped! [UDP] glutton_server.go desPort == -1")
		// return
	}

	if flags&syscall.MSG_TRUNC != 0 {
		log.Printf(" [UDP] [ %v ] [ %v ] [Truncated Read] Message: %s", addr, dp, string(b[0:n]))
	} else {
		log.Printf(" [UDP] [ %v ] [ %v ] Message: %s\n", addr, dp, string(b[0:n]))
	}
	conn.WriteToUDP([]byte("Hello UDP Client:-)\n"), addr)

}

func udpListener(f *os.File, ch *nbc.NonBlockingChan) {
	service := ":5000"

	addr, err := net.ResolveUDPAddr("udp", service)
	glutton.CheckError(err)

	// Listener for incoming UDP connections
	conn, err := net.ListenUDP("udp", addr)
	glutton.CheckError(err)

	for {
		Println("New Connection")
		handleUDPClient(conn, f, ch)
	}
}

func main() {
	Println("Starting server.....")
	f, err := os.OpenFile("logs.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Channel for tcp logging
	tcpCh := nbc.New()
	// Channel for udp logging
	udpCh := nbc.New()

	Println("Initializing TCP connections tracking...")
	go glutton.MonitorTCPConnections(tcpCh)

	// TODO: Implement UPD the next time.
	Println("Initializing UDP connections tracking...")
	go glutton.MonitorUDPConnections(udpCh)

	Println("Starting TCP Server...")
	go tcpListener(f, tcpCh)

	Println("Starting UDP Server...")
	udpListener(f, udpCh)
}
