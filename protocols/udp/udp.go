package udp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
)

func storePayload(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	if err := os.MkdirAll("payloads", os.ModePerm); err != nil {
		return "", err
	}
	sha256Hash := hex.EncodeToString(sum[:])
	path := filepath.Join("payloads", sha256Hash)
	if _, err := os.Stat(path); err == nil {
		return "", nil
	}
	out, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer out.Close()
	_, err = out.Write(data)
	if err != nil {
		return "", err
	}
	return sha256Hash, nil
}

func HandleUDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	log.Info(fmt.Sprintf("UDP payload:\n%s", hex.Dump(data[:len(data)%1024])))
	_, err := storePayload(data[:len(data)%1024])
	if err != nil {
		log.Error("failed to store UDP payload", producer.ErrAttr(err))
	}
	if err := h.ProduceUDP("udp", srcAddr, dstAddr, md, data[:len(data)%1024], nil); err != nil {
		log.Error("failed to produce UDP payload", producer.ErrAttr(err))
	}
	return nil
}
