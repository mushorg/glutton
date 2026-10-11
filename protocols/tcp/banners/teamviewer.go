package banners

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

// TeamViewer (tcp/5938, falling back to 443 and 80) frames start with the
// protocol 1.x magic 0x1724, a command byte and a little-endian u16 body
// length. Command codes are from bettercap packets/teamviewer.go.
const (
	tvCmdIdentify = 0x0a // CMD_IDENTIFY
	tvCmdPing     = 0x10 // CMD_PING
	tvCmdPingOK   = 0x11 // CMD_PINGOK
	tvHeaderLen   = 5
)

var tvMagic = []byte{0x17, 0x24}

// tvPingOK answers CMD_PING (Shodan, praetorian nerva) with an empty 4-byte body.
var tvPingOK = []byte{0x17, 0x24, tvCmdPingOK, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}

// isTVPing reports whether data is one complete TeamViewer CMD_PING frame.
func isTVPing(data []byte) bool {
	return len(data) >= tvHeaderLen && bytes.HasPrefix(data, tvMagic) && data[2] == tvCmdPing &&
		len(data) == tvHeaderLen+int(binary.LittleEndian.Uint16(data[3:5]))
}

// tvConnID fills the 4 bytes nmap wildcards in CMD_IDENTIFY, so sensors do
// not share a value; replaced in tests.
var tvConnID = func() [4]byte {
	var id [4]byte
	_, _ = rand.Read(id[:])
	return id
}

// tvIdentify is the CMD_IDENTIFY a TeamViewer listener sends a silent client
// (nmap match: p/TeamViewer/, NULL probe, \x68\x42 variant).
func tvIdentify() []byte {
	id := tvConnID()
	b := append([]byte{0x17, 0x24, tvCmdIdentify, 0x20, 0x00}, id[:]...)
	b = append(b, 0x68, 0x42, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0x11, 0x80)
	return append(b, make([]byte, 14)...)
}
