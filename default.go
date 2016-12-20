package glutton

import (
	"io"
	"log"
	"net"
)

func handleDefault(conn net.Conn) error {
	defer conn.Close()
	log.Println("Handling connection with default handler...")
	buf := make([]byte, 0, 81920)
	tbuf := make([]byte, 1024)

	for {
		n, err := conn.Read(tbuf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %s", err)
			}
			break
		}
		buf = append(buf, tbuf[:n]...)
	}
	log.Printf("Data read: %q\n", string(buf))
	return nil
}
