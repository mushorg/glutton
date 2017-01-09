package glutton

import (
	"bytes"
	"log"
	"net"

	"github.com/1lann/go-sip/server"
	"github.com/1lann/go-sip/sipnet"
)

func handleSIP(netConn net.Conn) {
	sipConn := &sipnet.Conn{
		Conn: netConn,
	}
	buf := []byte{}
	rd := bytes.NewReader(buf)
	req, err := sipnet.ReadRequest(rd)
	if err != nil {
		log.Println(err)
	}
	log.Printf("SIP method: %s", req.Method)
	switch req.Method {
	case sipnet.MethodRegister:
		log.Println("handling SIP register")
		server.HandleRegister(req, sipConn)
	case sipnet.MethodInvite:
		log.Println("handling SIP invite")
		server.HandleInvite(req, sipConn)
	case sipnet.MethodOptions:
		log.Println("handling SIP options")
		resp := sipnet.NewResponse()
		resp.StatusCode = sipnet.StatusOK
		resp.Header.Set("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE")
		resp.Header.Set("Accept", "application/sdp")
		resp.Header.Set("Accept-Encoding", "gzip")
		resp.Header.Set("Accept-Language", "en")
		resp.Header.Set("Content-Type", "application/sdp")
		resp.Body = req.Body
		resp.WriteTo(sipConn, req)
		break
	}
}
