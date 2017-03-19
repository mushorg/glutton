package glutton

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"net/http"
)

// HandleHTTP takes a net.Conn and does basic HTTP communication
func (g *Glutton) HandleHTTP(conn net.Conn) {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		g.logger.Errorf("[http    ] %v", err)
		return
	}
	g.logger.Infof("[http    ] %+v", req)
	if req.ContentLength > 0 {
		defer req.Body.Close()
		buf := bytes.NewBuffer(make([]byte, 0, req.ContentLength))
		_, err = buf.ReadFrom(req.Body)
		if err != nil {
			g.logger.Errorf("[http    ] %v", err)
			return
		}
		body := buf.Bytes()
		g.logger.Infof("[http    ] http body:\n%s", hex.Dump(body[:]))
	}
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
}
