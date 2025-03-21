package protocols

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp"
	"github.com/mushorg/glutton/protocols/udp"
)

type TCPHandlerFunc func(ctx context.Context, conn net.Conn, md connection.Metadata) error

type UDPHandlerFunc func(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata) error

// MapUDPProtocolHandlers map protocol handlers to corresponding protocol
func MapUDPProtocolHandlers(log interfaces.Logger, h interfaces.Honeypot) map[string]UDPHandlerFunc {
	protocolHandlers := map[string]UDPHandlerFunc{}
	protocolHandlers["udp"] = func(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata) error {
		return udp.HandleUDP(ctx, srcAddr, dstAddr, data, md, log, h)
	}
	return protocolHandlers
}

// MapTCPProtocolHandlers map protocol handlers to corresponding protocol
func MapTCPProtocolHandlers(log interfaces.Logger, h interfaces.Honeypot) map[string]TCPHandlerFunc {
	protocolHandlers := map[string]TCPHandlerFunc{}
	protocolHandlers["smtp"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleSMTP(ctx, conn, md, log, h)
	}
	protocolHandlers["rdp"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleRDP(ctx, conn, md, log, h)
	}
	protocolHandlers["smb"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleSMB(ctx, conn, md, log, h)
	}
	protocolHandlers["ftp"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleFTP(ctx, conn, md, log, h)
	}
	protocolHandlers["sip"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleSIP(ctx, conn, md, log, h)
	}
	protocolHandlers["rfb"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleRFB(ctx, conn, md, log, h)
	}
	protocolHandlers["telnet"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleTelnet(ctx, conn, md, log, h)
	}
	protocolHandlers["mqtt"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleMQTT(ctx, conn, md, log, h)
	}
	protocolHandlers["iscsi"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleISCSI(ctx, conn, md, log, h)
	}
	protocolHandlers["bittorrent"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleBittorrent(ctx, conn, md, log, h)
	}
	protocolHandlers["memcache"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleMemcache(ctx, conn, md, log, h)
	}
	protocolHandlers["jabber"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleJabber(ctx, conn, md, log, h)
	}
	protocolHandlers["adb"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleADB(ctx, conn, md, log, h)
	}
	protocolHandlers["mongodb"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return tcp.HandleMongoDB(ctx, conn, md, log, h)
	}
	protocolHandlers["tcp"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		snip, bufConn, err := Peek(conn, 4)
		if err != nil {
			if err := conn.Close(); err != nil {
				log.Error("failed to close connection", producer.ErrAttr(err))
			}
			log.Debug("failed to peek connection", producer.ErrAttr(err))
			return nil
		}
		// poor mans check for HTTP request
		httpMap := map[string]bool{
			"GET ": true,
			"POST": true,
			"HEAD": true,
			"OPTI": true,
			"CONN": true,
			"PRI ": true,
		}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok {
			return tcp.HandleHTTP(ctx, bufConn, md, log, h)
		}
		// poor mans check for RDP header
		if bytes.Equal(snip, []byte{0x03, 0x00, 0x00, 0x2b}) {
			return tcp.HandleRDP(ctx, bufConn, md, log, h)
		}
		// poor mans check for MongoDB header (checking msg length and validating opcodes)
		messageLength := binary.LittleEndian.Uint32(snip)
		if messageLength > 0 && messageLength <= 48*1024*1024 {
			moreSample, bufConn, err := Peek(bufConn, 16)
			if err != nil {
				if err := conn.Close(); err != nil {
					log.Error("failed to close connection", producer.ErrAttr(err))
				}
				log.Debug("failed to peek connection", producer.ErrAttr(err))
				return nil
			}
			if len(moreSample) == 16 {
				opCode := binary.LittleEndian.Uint32(moreSample[12:16])
				validOpCodes := map[uint32]bool{
					1:    true, // OP_REPLY
					2001: true, // OP_UPDATE
					2002: true, // OP_INSERT
					2004: true, // OP_QUERY
					2005: true, // OP_GET_MORE
					2006: true, // OP_DELETE
					2007: true, // OP_KILL_CURSORS
					2012: true, // OP_COMPRESSED
					2013: true, // OP_MSG
				}
				if _, ok := validOpCodes[opCode]; ok {
					return tcp.HandleMongoDB(ctx, bufConn, md, log, h)
				}
			}
		}
		// fallback TCP handler
		return tcp.HandleTCP(ctx, bufConn, md, log, h)
	}
	return protocolHandlers
}
