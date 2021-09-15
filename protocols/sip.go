package protocols

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/1lann/go-sip/server"
	"github.com/1lann/go-sip/sipnet"
)

// HandleSIP takes a net.Conn and does basic SIP communication
func HandleSIP(ctx context.Context, netConn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := netConn.Close(); err != nil {
			logger.Error(fmt.Errorf("failed to close SIP connection: %w", err).Error())
		}
	}()

	sipConn := &sipnet.Conn{
		Conn: netConn,
	}
	buf := []byte{}
	rd := bytes.NewReader(buf)
	req, err := sipnet.ReadRequest(rd)
	if err != nil {
		return err
	}
	if req == nil {
		logger.Info("failed to parse SIP req")
		return nil
	}
	logger.Info(fmt.Sprintf(" SIP method: %s", req.Method))
	switch req.Method {
	case sipnet.MethodRegister:
		logger.Info("handling SIP register")
		server.HandleRegister(req, sipConn)
	case sipnet.MethodInvite:
		logger.Info("handling SIP invite")
		server.HandleInvite(req, sipConn)
	case sipnet.MethodOptions:
		logger.Info("handling SIP options")
		resp := sipnet.NewResponse()
		resp.StatusCode = sipnet.StatusOK
		resp.Header.Set("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE")
		resp.Header.Set("Accept", "application/sdp")
		resp.Header.Set("Accept-Encoding", "gzip")
		resp.Header.Set("Accept-Language", "en")
		resp.Header.Set("Content-Type", "application/sdp")
		resp.Body = req.Body
		resp.WriteTo(sipConn, req)
	}
	return nil
}
