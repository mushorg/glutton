package glutton

import (
	"bytes"
	"net"

	log "github.com/Sirupsen/logrus"

	"github.com/1lann/go-sip/server"
	"github.com/1lann/go-sip/sipnet"
)

// HandleSIP takes a net.Conn and does basic SIP communication
func HandleSIP(netConn net.Conn) {
	defer netConn.Close()
	sipConn := &sipnet.Conn{
		Conn: netConn,
	}
	buf := []byte{}
	rd := bytes.NewReader(buf)
	req, err := sipnet.ReadRequest(rd)
	if err != nil {
		log.Errorf("[sip     ] error: %v", err)
	}
	log.Printf("[sip     ] SIP method: %s", req.Method)
	switch req.Method {
	case sipnet.MethodRegister:
		log.Println("[sip     ] handling SIP register")
		server.HandleRegister(req, sipConn)
	case sipnet.MethodInvite:
		log.Println("[sip     ] handling SIP invite")
		server.HandleInvite(req, sipConn)
	case sipnet.MethodOptions:
		log.Println("[sip     ] handling SIP options")
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
