package interfaces

import (
	"context"
	"net"

	"github.com/mushorg/glutton/connection"
)

type Logger interface {
	Debug(msg string, fields ...any)
	Info(msg string, fields ...any)
	Warn(msg string, fields ...any)
	Error(msg string, fields ...any)
}

type Honeypot interface {
	ProduceTCP(protocol string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error
	ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error
	// ReplyUDP sends a transparent UDP response to srcAddr, sourced from dstAddr
	// (the original destination of the request).
	ReplyUDP(srcAddr, dstAddr *net.UDPAddr, payload []byte) error
	// GuardConn charges writes on conn against the TCP reply budget of its
	// remote IP. Accepted connections are already guarded; use it for
	// connections a handler dials itself.
	GuardConn(conn net.Conn) net.Conn
	ConnectionByFlow([2]uint64) connection.Metadata
	UpdateConnectionTimeout(ctx context.Context, conn net.Conn) error
	MetadataByConnection(net.Conn) (connection.Metadata, error)
}

// UDPReplyReporter is implemented by a Honeypot that can tell whether a UDP
// reply left. ReplyUDP reports a reply dropped over the udp_reply_limit
// budget as sent, so handlers do not turn a flood into a log flood; a
// handler that records its writes uses ReplyUDPSent to flag the dropped ones
// instead of showing a reply the client never got.
type UDPReplyReporter interface {
	// ReplyUDPSent sends like ReplyUDP and reports false, with a nil error,
	// when the reply budget dropped the payload.
	ReplyUDPSent(srcAddr, dstAddr *net.UDPAddr, payload []byte) (sent bool, err error)
}
