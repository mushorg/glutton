package protocols

import (
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"go.uber.org/zap"
)

type Logger interface {
	Debug(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
}

type Honeypot interface {
	Produce(protocol string, conn net.Conn, md *connection.Metadata, payload []byte, decoded interface{}) error
	ConnectionByFlow([2]uint64) *connection.Metadata
	UpdateConnectionTimeout(ctx context.Context, conn net.Conn)
	MetadataByConnection(net.Conn) (*connection.Metadata, error)
}

type HandlerFunc func(ctx context.Context, conn net.Conn) error

// mapProtocolHandlers map protocol handlers to corresponding protocol
func MapProtocolHandlers(log Logger, h Honeypot) map[string]HandlerFunc {
	protocolHandlers := map[string]HandlerFunc{}
	protocolHandlers["smtp"] = func(ctx context.Context, conn net.Conn) error {
		return HandleSMTP(ctx, conn, log, h)
	}
	protocolHandlers["rdp"] = func(ctx context.Context, conn net.Conn) error {
		return HandleRDP(ctx, conn, log, h)
	}
	protocolHandlers["smb"] = func(ctx context.Context, conn net.Conn) error {
		return HandleSMB(ctx, conn, log, h)
	}
	protocolHandlers["ftp"] = func(ctx context.Context, conn net.Conn) error {
		return HandleFTP(ctx, conn, log, h)
	}
	protocolHandlers["sip"] = func(ctx context.Context, conn net.Conn) error {
		return HandleSIP(ctx, conn, log, h)
	}
	protocolHandlers["rfb"] = func(ctx context.Context, conn net.Conn) error {
		return HandleRFB(ctx, conn, log, h)
	}
	protocolHandlers["telnet"] = func(ctx context.Context, conn net.Conn) error {
		return HandleTelnet(ctx, conn, log, h)
	}
	protocolHandlers["mqtt"] = func(ctx context.Context, conn net.Conn) error {
		return HandleMQTT(ctx, conn, log, h)
	}
	protocolHandlers["bittorrent"] = func(ctx context.Context, conn net.Conn) error {
		return HandleBittorrent(ctx, conn, log, h)
	}
	protocolHandlers["memcache"] = func(ctx context.Context, conn net.Conn) error {
		return HandleMemcache(ctx, conn, log, h)
	}
	protocolHandlers["jabber"] = func(ctx context.Context, conn net.Conn) error {
		return HandleJabber(ctx, conn, log, h)
	}
	protocolHandlers["adb"] = func(ctx context.Context, conn net.Conn) error {
		return HandleADB(ctx, conn, log, h)
	}
	protocolHandlers["default"] = func(ctx context.Context, conn net.Conn) error {
		snip, bufConn, err := Peek(conn, 4)
		if err != nil {
			if err := conn.Close(); err != nil {
				log.Error("failed to close connection", zap.Error(err))
			}
			return err
		}
		// poor mans check for HTTP request
		httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true, "CONN": true}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok {
			return HandleHTTP(ctx, bufConn, log, h)
		}
		// poor mans check for RDP header
		if bytes.Equal(snip, []byte{0x03, 0x00, 0x00, 0x2b}) {
			return HandleRDP(ctx, bufConn, log, h)
		}
		// fallback TCP handler
		return HandleTCP(ctx, bufConn, log, h)
	}
	return protocolHandlers
}
