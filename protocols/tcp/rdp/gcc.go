package rdp

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Client data block types inside the GCC Conference Create Request
// (MS-RDPBCGR 2.2.1.3.1).
const (
	csCore     = 0xc001
	csSecurity = 0xc002
	csNet      = 0xc003

	// maxClientChannels bounds CS_NET; MS-RDPBCGR allows at most 31 static channels.
	maxClientChannels = 31
)

// ClientData is what the client announced in its MCS Connect-Initial GCC
// user data: CS_CORE, CS_SECURITY and CS_NET.
type ClientData struct {
	ClientName        string   `json:"client_name,omitempty"`
	ClientBuild       uint32   `json:"client_build,omitempty"`
	DesktopWidth      uint16   `json:"desktop_width,omitempty"`
	DesktopHeight     uint16   `json:"desktop_height,omitempty"`
	KeyboardLayout    uint32   `json:"keyboard_layout,omitempty"`
	HighColorDepth    uint16   `json:"high_color_depth,omitempty"`
	EncryptionMethods uint32   `json:"encryption_methods,omitempty"`
	Channels          []string `json:"channels,omitempty"`
}

// ParseClientData extracts the client data blocks from an MCS Connect-Initial.
// The blocks follow the H.221 key "Duca" and a PER length (MS-RDPBCGR 4.1.3).
// It returns nil when no blocks are found.
func ParseClientData(data []byte) *ClientData {
	i := bytes.Index(data, []byte("Duca"))
	if i < 0 {
		return nil
	}
	b := data[i+4:]
	n, hdr := perLength(b)
	if hdr == 0 {
		return nil
	}
	b = b[hdr:]
	if n < len(b) {
		b = b[:n]
	}

	var cd ClientData
	found := false
	for len(b) >= 4 {
		typ := binary.LittleEndian.Uint16(b[0:2])
		l := int(binary.LittleEndian.Uint16(b[2:4]))
		if l < 4 || l > len(b) {
			break
		}
		block := b[:l]
		switch typ {
		case csCore:
			found = parseCSCore(block, &cd) || found
		case csSecurity:
			if len(block) >= 8 {
				cd.EncryptionMethods = binary.LittleEndian.Uint32(block[4:8])
				found = true
			}
		case csNet:
			cd.Channels = parseCSNet(block)
			found = found || len(cd.Channels) > 0
		}
		b = b[l:]
	}
	if !found {
		return nil
	}
	return &cd
}

// parseCSCore reads TS_UD_CS_CORE (MS-RDPBCGR 2.2.1.3.2). The fields after
// imeFileName are optional; highColorDepth is read only when present.
func parseCSCore(b []byte, cd *ClientData) bool {
	if len(b) < 56 {
		return false
	}
	cd.DesktopWidth = binary.LittleEndian.Uint16(b[8:10])
	cd.DesktopHeight = binary.LittleEndian.Uint16(b[10:12])
	cd.KeyboardLayout = binary.LittleEndian.Uint32(b[16:20])
	cd.ClientBuild = binary.LittleEndian.Uint32(b[20:24])
	cd.ClientName = decodeUTF16Z(b[24:56])
	if len(b) >= 142 {
		cd.HighColorDepth = binary.LittleEndian.Uint16(b[140:142])
	}
	return true
}

// parseCSNet reads the channel names from TS_UD_CS_NET (MS-RDPBCGR 2.2.1.3.4).
func parseCSNet(b []byte) []string {
	if len(b) < 8 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(b[4:8]))
	if count > maxClientChannels {
		count = maxClientChannels
	}
	var names []string
	for off := 8; count > 0 && off+12 <= len(b); off += 12 {
		name := b[off : off+8]
		if j := bytes.IndexByte(name, 0); j >= 0 {
			name = name[:j]
		}
		names = append(names, string(name))
		count--
	}
	return names
}

// perLength decodes a PER length determinant (X.691 10.9): one byte below
// 0x80, else two bytes with the top bit set. hdr is 0 when b is too short.
func perLength(b []byte) (n, hdr int) {
	if len(b) < 1 {
		return 0, 0
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1
	}
	if len(b) < 2 {
		return 0, 0
	}
	return int(b[0]&0x3f)<<8 | int(b[1]), 2
}

// decodeUTF16Z decodes a UTF-16LE string and stops at the first NUL.
func decodeUTF16Z(b []byte) string {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	return strings.TrimSpace(string(utf16.Decode(u16)))
}
