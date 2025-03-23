package udp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

func HandleUDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	log.Info(fmt.Sprintf("UDP payload:\n%s", hex.Dump(data[:len(data)%1024])))
	if _, err := helpers.StorePayload(data[:len(data)%1024]); err != nil {
		log.Error("failed to store UDP payload", producer.ErrAttr(err))
	}
	if err := h.ProduceUDP("udp", srcAddr, dstAddr, md, data[:len(data)%1024], nil); err != nil {
		log.Error("failed to produce UDP payload", producer.ErrAttr(err))
	}
	return nil
}
