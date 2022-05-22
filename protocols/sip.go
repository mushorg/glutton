package protocols

import (
	"context"
	"fmt"
	"net"

	"github.com/jart/gosip/dialog"
	"github.com/jart/gosip/sip"
	"go.uber.org/zap"
)

const maxBufferSize = 1024

// HandleSIP takes a net.Conn and does basic SIP communication
func HandleSIP(ctx context.Context, conn net.Conn, logger Logger, h Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error(fmt.Errorf("failed to close SIP connection: %w", err).Error())
		}
	}()

	buffer := make([]byte, maxBufferSize)

	_, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	req, err := sip.ParseMsg(buffer)
	if err != nil {
		return err
	}
	logger.Info(fmt.Sprintf("SIP method: %s", req.Method))
	switch req.Method {
	case sip.MethodRegister:
		logger.Info("handling SIP register")
		//server.HandleRegister(req, sipConn)
	case sip.MethodInvite:
		logger.Info("handling SIP invite")
		//server.HandleInvite(req, sipConn)
	case sip.MethodOptions:
		logger.Info("handling SIP options")
		msg := &sip.Msg{}
		resp := dialog.NewResponse(msg, sip.StatusOK)
		resp.Status = sip.StatusOK
		//resp.Header.Set("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE")
		//resp.Header.Set("Accept", "application/sdp")
		//resp.Header.Set("Accept-Encoding", "gzip")
		//resp.Header.Set("Accept-Language", "en")
		//resp.Header.Set("Content-Type", "application/sdp")
		//resp.Body = req.Body
		//resp.WriteTo(sipConn, req)
	}

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return err
	}
	if err := h.Produce(conn, md, buffer); err != nil {
		logger.Error("failed to produce message", zap.String("protocol", "sip"), zap.Error(err))
	}
	return nil
}
