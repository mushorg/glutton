package tcp

import (
	"embed"
	"fmt"
	"net"
)

//go:embed banners/*
var bannerFiles embed.FS

func SendBanner(conn net.Conn, port uint16) error {
	bannerPath := fmt.Sprintf("banners/%d_tcp", port)
	banner, err := bannerFiles.ReadFile(bannerPath)
	if err != nil {
		return fmt.Errorf("failed to get banner: %w", err)
	}
	if _, err := conn.Write(banner); err != nil {
		return fmt.Errorf("failed to write banner: %w", err)
	}
	return nil
}
