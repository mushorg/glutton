package protocols

import (
	"context"
	"net"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
)

type Logger interface {
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
}

type Honeypot interface {
	Produce(conn net.Conn, md *freki.Metadata, payload []byte) error
	ConnectionByFlow([2]uint64) *freki.Metadata
	UpdateConnectionTimeout(ctx context.Context, conn net.Conn)
}
