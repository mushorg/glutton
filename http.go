package glutton

import (
	"bufio"
	"log"
	"net"
	"net/http"
)

func handleHTTP(conn net.Conn) error {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Println(err)
		return err
	}
	log.Printf("%+v", req)
	if req.ContentLength > 0 {
		defer req.Body.Close()
		buf := new([]byte)
		req.Body.Read(*buf)
		log.Println(string(*buf))
	}
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	return nil
}
