package glutton

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hectane/go-nonblockingchan"
)

var Counters Connections

func handleTCPClient(conn net.Conn, ch *nbc.NonBlockingChan, counter ConnCounter) {
	counter.connectionsState()

	// Splitting address to compare with conntrack logs
	srcAddr := conn.RemoteAddr().String()
	if srcAddr == "<nil>" {
		log.Println("Error. Address:port == nil glutton_server.go conn.RemoteAddr().String()")
		return
	}

	addr := strings.Split(srcAddr, ":")

	dp := GetTCPDesPort(addr, ch)

	if dp == -1 {
		log.Println("Warning. Packet dropped! [TCP] glutton_server.go desPort == -1")
		return
	}

	// TCP client for destination server
	handler := GetHandler(dp)
	if len(handler) < 2 {
		log.Println("No explicit handler found")
		handler = GetDefaultHandler()
		if handler == "" {
			log.Println("No default handler found. Packet dropped!")
			return
		}

	}

	if strings.HasPrefix(handler, "handle") {
		if strings.HasSuffix(handler, "telnet") {
			log.Printf("New connection from %s to port %d -> glutton:telnet\n", addr[0], dp)
			counter.incrCon()
			handleTelnet(time.Now().Unix(), conn)
			counter.decrCon()
		}
		if strings.HasSuffix(handler, "default") {
			log.Printf("New connection from %s to port %d -> glutton:default\n", addr[0], dp)
			counter.incrCon()
			handleDefault(conn)
			counter.decrCon()
		}
	}

	if strings.HasPrefix(handler, "proxy") {
		proxyConn := TCPClient(handler[6:])
		if proxyConn == nil {
			return
		}

		log.Printf("New connection from %s to port %d -> glutton:Proxy\n", addr[0], dp)
		counter.incrCon()

		// Data Transfer between Connections
		clossedBy, err := ProxyServer(time.Now().Unix(), conn.(*net.TCPConn), proxyConn)
		counter.connectionClosed(srcAddr, handler[6:], clossedBy, err)
	}
}

// TCPListener listens for new TCP connections
func TCPListener(ch *nbc.NonBlockingChan, wg *sync.WaitGroup) {
	defer wg.Done()

	Counters = Connections{}

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
		go handleTCPClient(conn, ch, &Counters)
	}
}

func handleUDPClient(conn *net.UDPConn, ch *nbc.NonBlockingChan) {

	for {
		var b [1500]byte
		n, addr, err := conn.ReadFromUDP(b[0:])
		if err != nil {
			return
		}

		c := UDPConn{conn, addr, ch, b, n}
		go c.UDPBroker(&Counters)
	}
}

// UDPListener listens for new UDP connections
func UDPListener(ch *nbc.NonBlockingChan, wg *sync.WaitGroup) {
	defer wg.Done()

	service := ":5000"

	addr, err := net.ResolveUDPAddr("udp", service)
	CheckError("[*] Error in UDP address resolving", err)

	// Listener for incoming UDP connections
	conn, err := net.ListenUDP("udp", addr)
	CheckError("[*] Error in UDP listener", err)

	handleUDPClient(conn, ch)

}
