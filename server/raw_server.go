package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	for {
		b := make([]byte, 4096)
		log.Println("reading from conn")
		n, err := f.Read(b)
		if err != nil {
			log.Println("error reading packet: ", err)
			return
		}
		// Decode a packet
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeIPv4, gopacket.Default)

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			log.Println(ip.SrcIP)
			tcp := packet.TransportLayer().(*layers.TCP)

			if tcp.SYN {
				tcpLayer := &layers.TCP{
					SrcPort: tcp.DstPort,
					DstPort: tcp.SrcPort,
					ACK:     true,
					SYN:     true,
					Seq:     tcp.Seq,
					Ack:     tcp.Ack + 1,
				}
				log.Printf("%+v", tcp)
				log.Printf("%+v", tcpLayer)
				buffer := gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(
					buffer,
					gopacket.SerializeOptions{},
					&layers.IPv4{
						DstIP: ip.SrcIP,
						SrcIP: net.IP{},
					},
					tcpLayer,
					//gopacket.Payload([]byte{10, 20, 30}),
				)
				log.Printf("Sendinf ACK to %s", ip.SrcIP.String())
				var srcIP [4]byte
				copy(srcIP[:], ip.SrcIP[:4])
				addr := syscall.SockaddrInet4{
					Port: int(tcp.SrcPort),
					Addr: srcIP,
				}
				err = syscall.Sendto(fd, buffer.Bytes(), 0, &addr)
				if err != nil {
					log.Fatal("Sendto:", err)
				}
			}
		}
	}
}
