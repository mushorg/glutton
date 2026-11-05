// Package tuya parses and builds frames of the Tuya local LAN protocol
// (tcp/6668) used by Tuya/Smart Life plugs, bulbs and other IoT devices.
//
// A frame (protocol 3.1-3.4) is a 16-byte big-endian header, a body, and a
// footer:
//
//	000055aa | seq u32 | cmd u32 | len u32 | body | crc32 u32 | 0000aa55
//
// len counts everything after the header (body, checksum and suffix). Frames
// sent by a device carry a 4-byte return code before the body. The CRC32
// (IEEE) covers the header and body. Protocol 3.4 replaces the CRC with a
// 32-byte HMAC; those frames are recorded but their checksum is not verified.
// Bodies are AES-encrypted with a per-device key; this package never tries to
// decrypt them.
//
// Layout and command numbers follow the open-source tinytuya (MIT) and
// tuyapi (MIT) client libraries.
package tuya

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// HeaderLen is the fixed header size.
	HeaderLen = 16
	// footerLen is the CRC32 plus the suffix.
	footerLen = 8

	// CmdHeartbeat is the keep-alive command.
	CmdHeartbeat uint32 = 0x09
	// CmdDPQuery asks the device for its data-point status.
	CmdDPQuery uint32 = 0x0a

	// ChecksumOK marks a frame whose CRC32 matches.
	ChecksumOK = "crc32-ok"
	// ChecksumMismatch marks a frame whose trailer is not a matching CRC32
	// (bad checksum, or a 3.4 HMAC frame).
	ChecksumMismatch = "mismatch"
)

var (
	prefix = []byte{0x00, 0x00, 0x55, 0xaa}
	suffix = []byte{0x00, 0x00, 0xaa, 0x55}

	// ErrBadPrefix means the frame does not start with 000055aa.
	ErrBadPrefix = errors.New("tuya: bad prefix")
	// ErrBodyTooLarge means the announced length exceeds the capture cap.
	ErrBodyTooLarge = errors.New("tuya: body too large")
	// ErrBadLength means the announced length cannot hold the footer.
	ErrBadLength = errors.New("tuya: length shorter than footer")
)

var commandNames = map[uint32]string{
	0x01: "ap-config",
	0x02: "active",
	0x03: "sess-key-neg-start",
	0x04: "sess-key-neg-resp",
	0x05: "sess-key-neg-finish",
	0x06: "unbind",
	0x07: "control",
	0x08: "status",
	0x09: "heartbeat",
	0x0a: "dp-query",
	0x0b: "query-wifi",
	0x0c: "token-bind",
	0x0d: "control-new",
	0x0e: "enable-wifi",
	0x0f: "wifi-info",
	0x10: "dp-query-new",
	0x11: "scene-execute",
	0x12: "update-dps",
	0x13: "udp-new",
	0x14: "ap-config-new",
	0x25: "board-info",
	0x40: "lan-ext-stream",
}

// CommandName is the leaf operation name for a command number.
func CommandName(cmd uint32) string {
	if name, ok := commandNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("cmd-0x%02x", cmd)
}

// Frame is one parsed client frame.
type Frame struct {
	Seq      uint32
	Command  uint32
	Length   uint32
	Version  string // "3.x" when the body starts with a plaintext version tag
	Checksum string // ChecksumOK or ChecksumMismatch
}

// ReadFrame reads one header plus the announced remainder. raw holds the bytes
// consumed so far even on error, so a partial frame can still be recorded. A
// length larger than maxBody is read up to the cap and returned truncated with
// ErrBodyTooLarge.
func ReadFrame(r io.Reader, maxBody int) (f Frame, raw []byte, truncated bool, err error) {
	header := make([]byte, HeaderLen)
	n, err := io.ReadFull(r, header)
	if err != nil {
		return f, header[:n], false, err
	}
	raw = header
	if !bytes.Equal(header[:4], prefix) {
		return f, raw, false, ErrBadPrefix
	}
	f.Seq = binary.BigEndian.Uint32(header[4:8])
	f.Command = binary.BigEndian.Uint32(header[8:12])
	f.Length = binary.BigEndian.Uint32(header[12:16])
	if f.Length < footerLen {
		return f, raw, false, ErrBadLength
	}

	toRead := int64(f.Length)
	if toRead > int64(maxBody) {
		toRead = int64(maxBody)
		truncated = true
	}
	rest := make([]byte, toRead)
	n, err = io.ReadFull(r, rest)
	raw = append(raw, rest[:n]...)
	if err != nil {
		return f, raw, truncated, err
	}
	if truncated {
		return f, raw, true, ErrBodyTooLarge
	}
	body := rest[:len(rest)-footerLen]
	f.Version = version(body)
	f.Checksum = ChecksumMismatch
	footer := rest[len(rest)-footerLen:]
	if bytes.Equal(footer[4:], suffix) &&
		binary.BigEndian.Uint32(footer[:4]) == crc32.ChecksumIEEE(raw[:HeaderLen+len(body)]) {
		f.Checksum = ChecksumOK
	}
	return f, raw, false, nil
}

// version returns the plaintext "3.x" tag that 3.2+ clients put before the
// encrypted body of most commands (DP_QUERY in 3.3 has none).
func version(body []byte) string {
	if len(body) >= 3 && body[0] == '3' && body[1] == '.' && body[2] >= '0' && body[2] <= '9' {
		return string(body[:3])
	}
	return ""
}

// BuildResponse builds a device frame that echoes seq and cmd, with a return
// code and a plaintext body, framed with a CRC32 footer.
func BuildResponse(seq, cmd, retcode uint32, body []byte) []byte {
	length := 4 + len(body) + footerLen
	out := make([]byte, 0, HeaderLen+length)
	out = append(out, prefix...)
	out = binary.BigEndian.AppendUint32(out, seq)
	out = binary.BigEndian.AppendUint32(out, cmd)
	out = binary.BigEndian.AppendUint32(out, uint32(length))
	out = binary.BigEndian.AppendUint32(out, retcode)
	out = append(out, body...)
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	return append(out, suffix...)
}

// UndecryptableBody is what real devices answer, in plaintext with return code
// 1, when a request body does not decrypt with their local key.
var UndecryptableBody = []byte("json obj data unvalid")
