package glutton

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/hectane/go-nonblockingchan"
)

func handleTCPClient(conn net.Conn, f *os.File, ch *nbc.NonBlockingChan) {

	// Splitting address to compare with conntrack logs
	tmp := conn.RemoteAddr().String()
	if tmp == "<nil>" {
		println("[*] Error. Address:port == nil glutton_server.go conn.RemoteAddr().String()")
		return
	}

	addr := strings.Split(tmp, ":")

	dp := GetTCPDesPort(addr, ch)

	fmt.Printf("[*] New connection from %s to port %d\n", addr[0], dp)

	if dp == -1 {
		println("[*] Warning. Packet dropped! [TCP] glutton_server.go desPort == -1")
		return
	}

	// TCP client for destination server
	host := GetHost(dp)
	if len(host) < 2 {
		println("[*] Error. No host found. Packet dropped!")
		return
	}
	proxyConn := TCPClient(host)
	if proxyConn == nil {
		return
	}

	// Data Transfer between Connections
	ProxyServer(conn.(*net.TCPConn), proxyConn, f)

}

// TCPListener listens for new TCP connections
func TCPListener(f *os.File, ch *nbc.NonBlockingChan) {
	service := ":5000"

	addr, err := net.ResolveTCPAddr("tcp", service)
	CheckError("[*] ResolveTCPAddr Error.", err)

	// Listener for incoming TCP connections
	listener, err := net.ListenTCP("tcp", addr)
	CheckError("[*] Error in net.ListenTCP", err)

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

	for {
		var b [1500]byte
		n, addr, err := conn.ReadFromUDP(b[0:])
		if err != nil {
			return
		}

		c := Connection{conn, addr, ch, f, b, n}
		go UDPBroker(&c)
	}
}

// UDPListener listens for new UDP connections
func UDPListener(f *os.File, ch *nbc.NonBlockingChan) {
	service := ":5000"

	addr, err := net.ResolveUDPAddr("udp", service)
	CheckError("[*] Error in UDP address resolving", err)

	// Listener for incoming UDP connections
	conn, err := net.ListenUDP("udp", addr)
	CheckError("[*] Error in UDP listener", err)

	handleUDPClient(conn, f, ch)

}
