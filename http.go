package glutton

import (
	"bufio"
	"bytes"
	"net"
	"net/http"

	log "github.com/Sirupsen/logrus"
)

// HandleHTTP takes a net.Conn and does basic HTTP communication
func HandleHTTP(conn net.Conn) {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Errorf("[glutton ] %v", err)
		return
	}
	if req.ContentLength > 0 {
		defer req.Body.Close()
		buf := bytes.NewBuffer(make([]byte, 0, req.ContentLength))
		_, err = buf.ReadFrom(req.Body)
		if err != nil {
			log.Errorf("[glutton ] %v", err)
			return
		}
		body := buf.Bytes()
		log.Printf("[glutton ]\n%s", string(body))
	}
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
}
