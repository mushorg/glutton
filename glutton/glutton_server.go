package main

import (
	"fmt"
	"github.com/hectane/go-nonblockingchan"
	"github.com/mushorg/glutton"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
)

func handleTCPClient(conn net.Conn, filePointer *os.File, channel *nbc.NonBlockingChan) {
	log.SetOutput(filePointer)

	//Spliting addresss to compare with conntrack logs
	packetInfo := strings.Split(conn.RemoteAddr().String(), ":")
	dport := glutton.getDesport(packetInfo, channel)

	if dport == -1 {
		log.Printf("Packet Droped! [TCP] [ %v ]", conn.RemoteAddr())
		return
	}

	buf := make([]byte, 64000)
	for {
		n, err := conn.Read(buf[0:])
		if err != nil {
			return
		}
		log.Printf("[TCP] [ %v ] dport [%v] Message: %s", conn.RemoteAddr(), dport, string(buf[0:n]))
		_, err2 := conn.Write([]byte("Hollo TCP Client:-)\n"))
		if err2 != nil {
			return
		}
	}

}

func tcpListener(filePointer *os.File, channel *nbc.NonBlockingChan) {
	service := ":5000"

	tcpAddr, err := net.ResolveTCPAddr("tcp", service)
	glutton.CheckError(err)

	//listener for incoming TCP connections
	listener, err := net.ListenTCP("tcp", tcpAddr)
	glutton.CheckError(err)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			continue
		}
		// //goroutines to handle multiple connections
		go handleTCPClient(tcpConn, filePointer, channel)
	}
}

func handleUDPClient(conn *net.UDPConn, filePointer *os.File) {
	log.SetOutput(filePointer)
	b, oob := make([]byte, 64000), make([]byte, 4096)
	n, _, flags, addr, _ := conn.ReadMsgUDP(b, oob)

	if flags&syscall.MSG_TRUNC != 0 {
		log.Printf(" [UDP] [ %v ] [Truncated Read] Message: %s", addr, string(b[0:n]))
	} else {
		log.Printf(" [UDP] [ %v ] Message: %s\n", addr, string(b[0:n]))
	}
	conn.WriteToUDP([]byte("Hollo UDP Client:-)\n"), addr)
}

func udpListener(filePointer *os.File) {
	service := ":5000"
	udpAddr, err := net.ResolveUDPAddr("udp", service)
	glutton.CheckError(err)

	//listener for incoming UDP connections
	conn, err := net.ListenUDP("udp", udpAddr)
	glutton.CheckError(err)

	for {
		handleUDPClient(conn, filePointer)
	}
}

func main() {
	fmt.Println("Starting server.....")
	filePointer, err := os.OpenFile("logs.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer filePointer.Close()

	//channel for tcp logging
	tcpChannel := nbc.New()
	//channel for udp logging
	udpChannel := nbc.New()

	fmt.Println("Initializaing TCP connections tracking...")
	go monitor_Connections("tcp", tcpChannel)

	fmt.Println("Initializaing UDP connections tracking...")
	go monitor_Connections("udp", tcpChannel)

	fmt.Println("Starting TCP Server...")
	go tcpListener(filePointer, tcpChannel)

	fmt.Println("Starting UDP Server...")
	udpListener(filePointer, udpChannel)
}
