package main

import (
	// "flag"
	"github.com/hectane/go-nonblockingchan"
	"github.com/mushorg/glutton"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
)

func handleTCPClient(conn net.Conn, f *os.File, ch *nbc.NonBlockingChan) {

	// Splitting address to compare with conntrack logs
	tmp := conn.RemoteAddr().String()
	if tmp == "<nil>" {
		println("Error: Address:port == nil glutton_server.go conn.RemoteAddr().String()")
		return
	}

	addr := strings.Split(tmp, ":")

	dp := glutton.GetTCPDesPort(addr, ch)

	if dp == -1 {
		println("Error: Packet dropped! [TCP] glutton_server.go desPort == -1")
		return
	}

	// TCP client for destination server
	proxyConn := TCPClient(glutton.GetClient(dp))
	if proxyConn == nil {
		return
	}

	log.Printf("Redirection: Connection Established [%v]", glutton.GetClient(dp))

	// Data Transfer between Connections
	ProxyServer(conn.(*net.TCPConn), proxyConn, f)

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

	b, oob := make([]byte, 64000), make([]byte, 4096)

	n, _, flags, addr, _ := conn.ReadMsgUDP(b, oob)

	tmp := addr.String()
	if tmp == "<nil>" {
		println("Error: Address:port == nil glutton_server.go addr.String()")
		return
	}
	str := strings.Split(tmp, ":")
	dp := glutton.GetUDPDesPort(str, ch)
	if dp == -1 {
		println("Error: Packet dropped! [UDP] glutton_server.go desPort == -1")
		return
	}

	// TODO Proxy handling for UDP Clients
	proxyConn := UDPClient(glutton.GetClient(dp))

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
		handleUDPClient(conn, f, ch)
	}
}

func main() {
	println("Starting server.....")

	// logPath := flag.String("log", "/dev/null", "Log path.")
	// flag.Parse()

	// f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)

	f, err := os.OpenFile("logs", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Channel for tcp logging
	tcpCh := nbc.New()
	// Channel for udp logging
	// udpCh := nbc.New()

	// Load config file for remote services
	glutton.LoadServices()

	println("Initializing TCP connections tracking...")
	go glutton.MonitorTCPConnections(tcpCh)

	// println("Initializing UDP connections tracking...")
	// go glutton.MonitorUDPConnections(udpCh)

	println("Starting TCP Server...")
	tcpListener(f, tcpCh)

	// println("Starting UDP Server...")
	// udpListener(f, udpCh)
}
