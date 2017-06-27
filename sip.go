package glutton

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/1lann/go-sip/server"
	"github.com/1lann/go-sip/sipnet"
)

// HandleSIP takes a net.Conn and does basic SIP communication
func (g *Glutton) HandleSIP(ctx context.Context, netConn net.Conn) (err error) {
	defer func() {
		err = netConn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[sip     ]  error: %v", err))
		}
	}()

	sipConn := &sipnet.Conn{
		Conn: netConn,
	}
	buf := []byte{}
	rd := bytes.NewReader(buf)
	req, err := sipnet.ReadRequest(rd)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[sip     ] error: %v", err))
	}
	if req == nil {
		g.logger.Info(fmt.Sprintf("[sip     ] failed to parse SIP req"))
		return nil
	}
	g.logger.Info(fmt.Sprintf("[sip     ] SIP method: %s", req.Method))
	switch req.Method {
	case sipnet.MethodRegister:
		g.logger.Info(fmt.Sprintf("[sip     ] handling SIP register"))
		server.HandleRegister(req, sipConn)
	case sipnet.MethodInvite:
		g.logger.Info(fmt.Sprintf("[sip     ] handling SIP invite"))
		server.HandleInvite(req, sipConn)
	case sipnet.MethodOptions:
		g.logger.Info(fmt.Sprintf("[sip     ] handling SIP options"))
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
	return nil
}
