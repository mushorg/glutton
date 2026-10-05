package protocols

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/spicy"
	spicyHandlers "github.com/mushorg/glutton/protocols/spicy/handlers"
	"github.com/mushorg/glutton/protocols/tcp"
	"github.com/mushorg/glutton/protocols/tcp/mctp"
	"github.com/mushorg/glutton/protocols/udp"
	"github.com/spf13/viper"
)

// peek enough of the HTTP request line to detect /mcp or /sse
const mcpRequestLinePeek = 96

const (
	// mctpPeekLen covers the "REMOTE " method prefix of an MCTP request line.
	mctpPeekLen     = len("REMOTE ")
	mctpPeekTimeout = 200 * time.Millisecond
)

type TCPHandlerFunc func(ctx context.Context, conn net.Conn, md connection.Metadata) error

type UDPHandlerFunc func(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata) error

type tcpHandler func(context.Context, net.Conn, connection.Metadata, interfaces.Logger, interfaces.Honeypot) error

type udpHandler func(context.Context, *net.UDPAddr, *net.UDPAddr, []byte, connection.Metadata, interfaces.Logger, interfaces.Honeypot) error

func bindTCP(fn tcpHandler, log interfaces.Logger, h interfaces.Honeypot) TCPHandlerFunc {
	return func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		return fn(ctx, conn, md, log, h)
	}
}

func bindUDP(fn udpHandler, log interfaces.Logger, h interfaces.Honeypot) UDPHandlerFunc {
	return func(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata) error {
		return fn(ctx, srcAddr, dstAddr, data, md, log, h)
	}
}

// MapUDPProtocolHandlers map protocol handlers to corresponding protocol
func MapUDPProtocolHandlers(log interfaces.Logger, h interfaces.Honeypot) map[string]UDPHandlerFunc {
	return map[string]UDPHandlerFunc{
		"sip":       bindUDP(udp.HandleSIP, log, h),
		"openvpn":   bindUDP(udp.HandleOpenVPN, log, h),
		"mdns":      bindUDP(udp.HandleMDNS, log, h),
		"l2tp":      bindUDP(udp.HandleL2TP, log, h),
		"raknet":    bindUDP(udp.HandleRakNet, log, h),
		"kerberos":  bindUDP(udp.HandleKerberos, log, h),
		"coap":      bindUDP(udp.HandleCoAP, log, h),
		"proxy_udp": bindUDP(udp.HandleProxyUDP, log, h),
		"udp":       bindUDP(udp.HandleUDP, log, h),
	}
}

// MapTCPProtocolHandlers map protocol handlers to corresponding protocol
func MapTCPProtocolHandlers(log interfaces.Logger, h interfaces.Honeypot) map[string]TCPHandlerFunc {
	return map[string]TCPHandlerFunc{
		"smtp":       bindTCP(tcp.HandleSMTP, log, h),
		"rdp":        bindTCP(tcp.HandleRDP, log, h),
		"smb":        bindTCP(tcp.HandleSMB, log, h),
		"ftp":        bindTCP(tcp.HandleFTP, log, h),
		"sip":        bindTCP(tcp.HandleSIP, log, h),
		"rfb":        bindTCP(tcp.HandleRFB, log, h),
		"telnet":     bindTCP(tcp.HandleTelnet, log, h),
		"mqtt":       bindTCP(tcp.HandleMQTT, log, h),
		"iscsi":      bindTCP(tcp.HandleISCSI, log, h),
		"bittorrent": bindTCP(tcp.HandleBittorrent, log, h),
		"memcache":   bindTCP(tcp.HandleMemcache, log, h),
		"jabber":     bindTCP(tcp.HandleJabber, log, h),
		"adb":        bindTCP(tcp.HandleADB, log, h),
		"mongodb":    bindTCP(tcp.HandleMongoDB, log, h),
		"http":       bindTCP(tcp.HandleHTTP, log, h),
		"mcp":        bindTCP(tcp.HandleMCP, log, h),
		"modbus":     bindTCP(tcp.HandleModbus, log, h),
		"opcua":      bindTCP(tcp.HandleOPCUA, log, h),
		"dicom":      bindTCP(tcp.HandleDICOM, log, h),
		"mctp":       mctpOrTCP(log, h),
		"proxy_tcp":  bindTCP(tcp.HandleProxyTCP, log, h),
		"tcp":        catchAllTCP(log, h),
	}
}

func catchAllTCP(log interfaces.Logger, h interfaces.Honeypot) TCPHandlerFunc {
	return func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		// server-first ports (SSH, POP3, ...) greet before the client speaks,
		// so peeking for client bytes would stall them until the timeout
		if tcp.HasServerBanner(md.TargetPort) {
			return tcp.HandleTCP(ctx, conn, md, log, h)
		}
		snip, bufConn, err := peekOrClose(conn, conn, 4, log)
		if err != nil {
			return nil
		}
		if viper.GetBool("spicy.enabled") {
			if protocol, ok := parseTCPProtocol(snip, log); ok {
				switch protocol {
				case "http":
					return handleDetectedHTTP(ctx, bufConn, md, log, h)
				case "rdp":
					return tcp.HandleRDP(ctx, bufConn, md, log, h)
				}
			}
			more, bufConn, err := peekOrClose(conn, bufConn, 16, log)
			if err != nil {
				return nil
			}
			if protocol, ok := parseTCPProtocol(more, log); ok && protocol == "mongodb" {
				return tcp.HandleMongoDB(ctx, bufConn, md, log, h)
			}
		}
		return tcp.HandleTCP(ctx, bufConn, md, log, h)
	}
}

// mctpOrTCP serves the DVR port (tcp/9000): MCTP requests go to the MCTP
// handler; anything else (FastCGI, MinIO, Portainer probes, ...) falls back to
// the generic TCP handler so it is still stored.
func mctpOrTCP(log interfaces.Logger, h interfaces.Honeypot) TCPHandlerFunc {
	return func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			log.Debug("failed to set connection timeout", producer.ErrAttr(err))
			return conn.Close()
		}
		bufConn := newBufferedConn(conn)
		// wait (up to the connection timeout) for the client to speak first
		if _, err := bufConn.peek(1); err != nil {
			log.Debug("failed to peek connection", producer.ErrAttr(err))
			return conn.Close()
		}
		// the request line normally arrives in the first segment
		if err := bufConn.SetReadDeadline(time.Now().Add(mctpPeekTimeout)); err != nil {
			log.Debug("failed to set peek deadline", producer.ErrAttr(err))
		}
		if snip, err := bufConn.peek(mctpPeekLen); err == nil && mctp.LooksLikeMCTP(snip) {
			return tcp.HandleMCTP(ctx, bufConn, md, log, h)
		}
		return tcp.HandleTCP(ctx, bufConn, md, log, h)
	}
}

func handleDetectedHTTP(ctx context.Context, bufConn BufferedConn, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	reqLine, httpConn, peekErr := Peek(bufConn, mcpRequestLinePeek)
	if peekErr == nil && tcp.LooksLikeMCP(reqLine) {
		return tcp.HandleMCP(ctx, httpConn, md, log, h)
	}
	if peekErr == nil {
		bufConn = httpConn
	}
	return spicyHandlers.HandleHTTP(ctx, bufConn, md, log, h)
}

func peekOrClose(orig net.Conn, conn net.Conn, n int, log interfaces.Logger) ([]byte, BufferedConn, error) {
	snip, bufConn, err := Peek(conn, n)
	if err != nil {
		if cerr := orig.Close(); cerr != nil {
			log.Error("failed to close connection", producer.ErrAttr(cerr))
		}
		log.Debug("failed to peek connection", producer.ErrAttr(err))
	}
	return snip, bufConn, err
}

func parseTCPProtocol(sample []byte, log interfaces.Logger) (string, bool) {
	parsed, err := spicy.Parse("tcp", sample)
	if err != nil {
		log.Error("spicy tcp protocol parse error", producer.ErrAttr(err))
		return "", false
	}
	protocol, ok := parsed.Fields["protocol"].(string)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	return protocol, ok && protocol != ""
}
