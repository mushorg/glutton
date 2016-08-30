package main

import (
	"flag"
	"github.com/hectane/go-nonblockingchan"
	"github.com/mushorg/glutton"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func handleTCPClient(conn net.Conn, f *os.File, ch *nbc.NonBlockingChan) {

	// Splitting address to compare with conntrack logs
	tmp := conn.RemoteAddr().String()
	if tmp == "<nil>" {
		println("[*] Error. Address:port == nil glutton_server.go conn.RemoteAddr().String()")
		return
	}

	addr := strings.Split(tmp, ":")

	dp := glutton.GetTCPDesPort(addr, ch)

	if dp == -1 {
		println("[*] Warning. Packet dropped! [TCP] glutton_server.go desPort == -1")
		return
	}

	// TCP client for destination server
	host := glutton.GetHost(dp)
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

	for {
		var b [1500]byte
		n, addr, err := conn.ReadFromUDP(b[0:])
		if err != nil {
			return
		}

		c := Connection{conn, addr, ch, f, b, n}
		go brocker(&c)
	}
}

func udpListener(f *os.File, ch *nbc.NonBlockingChan) {
	service := ":5000"

	addr, err := net.ResolveUDPAddr("udp", service)
	glutton.CheckError(err)

	// Listener for incoming UDP connections
	conn, err := net.ListenUDP("udp", addr)
	glutton.CheckError(err)

	handleUDPClient(conn, f, ch)

}

func main() {
	println("\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n")
	print("%%													%%\n")
	print("%%		  %%%%%%   %%       %%      %%  %%%%%%%%%%  %%%%%%%%%%    %%%%%     %%%%     %%		%%\n")
	print("%%		%%         %%       %%      %%      %%          %%      %%     %%   %% %%    %%		%%\n")
	print("%%		%%    %%%  %%       %%      %%      %%          %%      %%     %%   %%   %%  %%		%%\n")
	print("%%		 %%%%%%%   %%%%%%%   %%%%%%%        %%          %%        %%%%%     %%     %%%%		%%\n")
	print("%%													%%\n")
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n")
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n")

	logPath := flag.String("log", "/dev/null", "Log path.")
	flag.Parse()

	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)

	// f, err := os.OpenFile("logs", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Channel for tcp logging
	tcpCh := nbc.New()
	//Channel for udp logging
	udpCh := nbc.New()

	// Load config file for remote services
	glutton.LoadServices()

	go glutton.MonitorTCPConnections(tcpCh)
	println("[*] Initializing TCP connections tracking..")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	go glutton.MonitorUDPConnections(udpCh)
	println("[*] Initializing UDP connections tracking...")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	println("[*] Starting TCP Server...")
	go tcpListener(f, tcpCh)

	println("[*] Starting UDP Server...")
	udpListener(f, udpCh)
}
