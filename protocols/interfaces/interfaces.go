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
