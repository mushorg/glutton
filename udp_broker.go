package glutton

import (
	. "fmt"
	"github.com/hectane/go-nonblockingchan"
	"log"
	"net"
	"os"
	"strings"
)

type Connection struct {
	conn   *net.UDPConn
	addr   *net.UDPAddr
	ch     *nbc.NonBlockingChan
	f      *os.File
	buffer [1500]byte
	n      int
}

func brocker(c *Connection) {
	log.SetOutput(c.f)
	tmp := c.addr.String()
	if tmp == "<nil>" {
		println("[*] Error. Address:port == nil udp_brocker.go addr.String()")
		return
	}
	str := strings.Split(tmp, ":")
	dp := GetUDPDesPort(str, c.ch)
	if dp == -1 {
		println("[*] Warning. Packet dropped! [UDP] udp_brocker.go desPort == -1")
		return
	}
	host := GetHost(dp)
	if len(host) < 2 {
		println("[*] Error. [UDP] No host found. Packet dropped!")
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		println("[*] Error. udp_brocker() net.ResolveUDPAddr Could not resolve host address!")
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		println("[*] Error. udp_brocker() net.DialUDP Failed to connect to host!")
		return
	}

	_, err = conn.Write(c.buffer[0:c.n])
	if err != nil {
		println("[*] Error. udp_brocker() conn.Write() Failed to write on connection!")
		return
	}

	log.Printf("[%v -> %v] Payload: %v", c.addr, udpAddr, string(c.buffer[0:c.n]))

	var buf [1500]byte
	n, err := conn.Read(buf[0:])
	if err != nil {
		println("[*] Warning. udp_brocker() conn.Read() Failed to read from connection!")
		return
	}

	log.Printf("[%v <- %v] Payload: %v", c.addr, udpAddr, string(buf[0:n]))

	num, err := c.conn.WriteToUDP(buf[0:n], c.addr)
	if err != nil {
		Printf("[*] Error. [%v] %v", num, err)
	}

}
