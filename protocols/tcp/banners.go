package tcp

import (
	"embed"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
)

//go:embed banners/*
var bannerFiles embed.FS

// SendBanner retrieves and sends service banner for the specified port.
func SendBanner(port uint16, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	bannerPath := fmt.Sprintf("banners/%d_tcp", port)
	banner, err := bannerFiles.Open(bannerPath)
	if err != nil {
		return fmt.Errorf("failed to get banner: %w", err)
	}
	defer banner.Close()

	bannerData, err := io.ReadAll(banner)
	if err != nil {
		return fmt.Errorf("failed to read banner content: %w", err)
	}
	if _, err := conn.Write(bannerData); err != nil {
		return fmt.Errorf("failed to write banner: %w", err)
	}
	if err = h.ProduceTCP("banner", conn, md, bannerData, nil); err != nil {
		logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "banner"))
	}
	return nil
}
