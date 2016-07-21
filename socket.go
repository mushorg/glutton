package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"honnef.co/go/netdb"
)

// getProtocol(80, "tcp")
func getProtocol(port int, transport string) *netdb.Servent {
	prot := netdb.GetProtoByName(transport)
	return netdb.GetServByPort(port, prot)
}

func tcpListener(filePointer *os.File) {
	service := "localhost:5000"

	tcpAddr, err := net.ResolveTCPAddr("tcp", service)
	checkError(err)

	//listener for incoming TCP connections
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			continue
		}

		//goroutines to handle multiple connections
		go handleTCPClient(tcpConn, filePointer)
	}
}

func handleTCPClient(conn net.Conn, filePointer *os.File) {
	log.SetOutput(filePointer)
	buf := make([]byte, 64000)
	for {
		n, err := conn.Read(buf[0:])
		if err != nil {
			return
		}

		log.Printf(" [TCP] [ %v ] Message: %s", conn.RemoteAddr(), string(buf[0:n]))
		_, err2 := conn.Write([]byte("Hollo TCP Client:-)\n"))
		if err2 != nil {
			return
		}
	}
}

func udpListener(filePointer *os.File) {
	service := "localhost:5000"
	udpAddr, err := net.ResolveUDPAddr("udp", service)
	checkError(err)

	//listener for incoming UDP connections
	conn, err := net.ListenUDP("udp", udpAddr)
	checkError(err)

	for {
		handleUDPClient(conn, filePointer)
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

func checkError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}

func main() {
	fmt.Println("Starting server.....")
	filePointer, err := os.OpenFile("logs.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer filePointer.Close()

	go tcpListener(filePointer)
	udpListener(filePointer)
}
