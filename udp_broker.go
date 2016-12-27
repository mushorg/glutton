package glutton

import (
	"log"
	"net"
	"strings"

	"github.com/hectane/go-nonblockingchan"
)

// UDPConn struct for UDP connection
type UDPConn struct {
	conn   *net.UDPConn
	addr   *net.UDPAddr
	ch     *nbc.NonBlockingChan
	buffer [1500]byte
	n      int
}

// UDPBroker is handling and UDP connection
func (c *UDPConn) UDPBroker(counter ConnCounter) {
	defer c.conn.Close()

	srcAddr := c.addr.String()
	if srcAddr == "<nil>" {
		log.Println("Error. Address:port == nil udp_broker.go addr.String()")
		counter.reqDropped()
		return
	}
	str := strings.Split(srcAddr, ":")
	dp := GetUDPDesPort(str, c.ch)
	if dp == -1 {
		//		log.Println("Warning. Packet dropped! [UDP] udp_broker.go desPort == -1")
		counter.reqDropped()
	}
	host := GetHandler(dp)
	if len(host) < 2 {
		//log.Println("[UDP] No host found. Packet dropped!")
		log.Printf("[UDP] [%v -> UDP:%v] Payload: %v", c.addr, dp, string(c.buffer[0:c.n]))
		counter.reqDropped()
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		log.Println("Error. udp_broker() net.ResolveUDPAddr Could not resolve host address!")
		counter.reqDropped()
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Println("Error. udp_broker() net.DialUDP Failed to connect to host!")
		counter.reqDropped()
		return
	}

	_, err = conn.Write(c.buffer[0:c.n])
	if err != nil {
		log.Println("Error. udp_broker() conn.Write() Failed to write on connection!")
		counter.reqDropped()
		return
	}

	log.Printf("[UDP] [%v -> %v] Payload: %v", c.addr, udpAddr, string(c.buffer[0:c.n]))

	var buf [1500]byte
	n, err := conn.Read(buf[0:])
	if err != nil {
		log.Println("Warning. udp_broker() conn.Read() Failed to read from connection!")
		counter.reqDropped()
		return
	}

	log.Printf("[UDP] [%v <- %v] Payload: %v", c.addr, udpAddr, string(buf[0:n]))

	num, err := c.conn.WriteToUDP(buf[0:n], c.addr)
	if err != nil {
		log.Printf("Error. [%v] %v\n", num, err)
	}
	counter.reqAccepted()
}
