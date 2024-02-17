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
	ConnectionByFlow([2]uint64) connection.Metadata
	UpdateConnectionTimeout(ctx context.Context, conn net.Conn) error
	MetadataByConnection(net.Conn) (connection.Metadata, error)
}
