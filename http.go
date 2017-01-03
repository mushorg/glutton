package glutton

import (
	"bufio"
	"bytes"
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
		buf := bytes.NewBuffer(make([]byte, 0, req.ContentLength))
		_, err = buf.ReadFrom(req.Body)
		if err != nil {
			log.Println(err)
			return err
		}
		body := buf.Bytes()
		log.Println(string(body))
	}
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	return nil
}
