package udp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/interfaces"

	"go.uber.org/zap"
)

func HandleUDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	log.Info(fmt.Sprintf("UDP payload:\n%s", hex.Dump(data[:len(data)%1024])))
	if err := h.ProduceUDP("udp", srcAddr, dstAddr, md, data[:len(data)%1024], nil); err != nil {
		log.Error("failed to produce UDP payload", zap.Error(err))
	}
	return nil
}
