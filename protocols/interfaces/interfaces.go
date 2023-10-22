package interfaces

import (
	"context"
	"net"

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
	ProduceTCP(protocol string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error
	ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error
	ConnectionByFlow([2]uint64) connection.Metadata
	UpdateConnectionTimeout(ctx context.Context, conn net.Conn) error
	MetadataByConnection(net.Conn) (connection.Metadata, error)
}
