// Package adb parses and builds Android Debug Bridge messages: the 24-byte
// header transport protocol adbd speaks on tcp/5555 and the file sync
// requests carried inside a "sync:" stream. Layouts follow AOSP's
// packages/modules/adb protocol.txt and SYNC.TXT.
package adb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Transport commands (little-endian ASCII).
const (
	CmdSYNC uint32 = 0x434e5953
	CmdCNXN uint32 = 0x4e584e43
	CmdAUTH uint32 = 0x48545541
	CmdOPEN uint32 = 0x4e45504f
	CmdOKAY uint32 = 0x59414b4f
	CmdCLSE uint32 = 0x45534c43
	CmdWRTE uint32 = 0x45545257
	CmdSTLS uint32 = 0x534c5453
)

const (
	// HeaderLen is the size of a transport message header.
	HeaderLen = 24
	// MaxPayload is the largest data_length adbd accepts (MAX_PAYLOAD).
	MaxPayload = 1024 * 1024
	// SyncDataMax is the largest DATA chunk in the sync protocol.
	SyncDataMax = 64 * 1024
	// SyncPathMax bounds the path carried by SEND/STAT/LIST/RECV.
	SyncPathMax = 1024
)

var (
	ErrBadMagic    = errors.New("adb: header magic mismatch")
	ErrTooLarge    = errors.New("adb: data length exceeds limit")
	ErrSyncRequest = errors.New("adb: invalid sync request")
)

var commandNames = map[uint32]string{
	CmdSYNC: "SYNC",
	CmdCNXN: "CNXN",
	CmdAUTH: "AUTH",
	CmdOPEN: "OPEN",
	CmdOKAY: "OKAY",
	CmdCLSE: "CLSE",
	CmdWRTE: "WRTE",
	CmdSTLS: "STLS",
}

// CommandName returns the four-letter name of a transport command, or its
// hex value when unknown.
func CommandName(cmd uint32) string {
	if name, ok := commandNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("0x%08x", cmd)
}

// Message is one transport message.
type Message struct {
	Command   uint32
	Arg0      uint32
	Arg1      uint32
	DataLen   uint32
	DataCheck uint32
	Magic     uint32
	Data      []byte
}

// Name returns the command name of the message.
func (m Message) Name() string {
	return CommandName(m.Command)
}

// ReadMessage reads one transport message from r. raw holds every byte
// consumed (header and data) even when err is non-nil. The header magic is
// validated and data_length is bounded by maxData before the body is read.
func ReadMessage(r io.Reader, maxData int) (Message, []byte, error) {
	hdr := make([]byte, HeaderLen)
	n, err := io.ReadFull(r, hdr)
	if err != nil {
		return Message{}, hdr[:n], err
	}
	m := Message{
		Command:   binary.LittleEndian.Uint32(hdr[0:]),
		Arg0:      binary.LittleEndian.Uint32(hdr[4:]),
		Arg1:      binary.LittleEndian.Uint32(hdr[8:]),
		DataLen:   binary.LittleEndian.Uint32(hdr[12:]),
		DataCheck: binary.LittleEndian.Uint32(hdr[16:]),
		Magic:     binary.LittleEndian.Uint32(hdr[20:]),
	}
	if m.Magic != m.Command^0xffffffff {
		return m, hdr, ErrBadMagic
	}
	if int64(m.DataLen) > int64(maxData) {
		return m, hdr, ErrTooLarge
	}
	raw := make([]byte, HeaderLen+int(m.DataLen))
	copy(raw, hdr)
	n, err = io.ReadFull(r, raw[HeaderLen:])
	raw = raw[:HeaderLen+n]
	m.Data = raw[HeaderLen:]
	return m, raw, err
}

// Checksum is the v1 data_check: the unsigned sum of the data bytes. Peers
// at version 0x01000001 and later ignore it, older ones verify it.
func Checksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

// Build encodes a transport message.
func Build(cmd, arg0, arg1 uint32, data []byte) []byte {
	b := make([]byte, HeaderLen+len(data))
	binary.LittleEndian.PutUint32(b[0:], cmd)
	binary.LittleEndian.PutUint32(b[4:], arg0)
	binary.LittleEndian.PutUint32(b[8:], arg1)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[16:], Checksum(data))
	binary.LittleEndian.PutUint32(b[20:], cmd^0xffffffff)
	copy(b[HeaderLen:], data)
	return b
}

// LooksLikeADB reports whether the first bytes of a TCP stream are an ADB
// client: a transport CNXN, or a host smart-socket request ("000chost:...").
func LooksLikeADB(snip []byte) bool {
	if len(snip) >= 4 && binary.LittleEndian.Uint32(snip) == CmdCNXN {
		return true
	}
	return len(snip) >= 8 && IsHexLength(snip[:4]) && bytes.HasPrefix(snip[4:], []byte("host"))
}

// IsHexLength reports whether b is the four ASCII hex digit length prefix
// of a host smart-socket request.
func IsHexLength(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	for _, c := range b[:4] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// SystemIdentity returns the "<type>:<serial>:<banner>" string carried in a
// CNXN, without the trailing NUL.
func SystemIdentity(data []byte) string {
	return strings.TrimRight(string(data), "\x00")
}

// SplitService splits an OPEN destination such as "shell:id" into the
// service name ("shell") and its argument ("id"). Options after a comma in
// the name ("shell,v2,raw") are dropped and trailing NULs are trimmed.
func SplitService(data []byte) (name, arg string) {
	s := strings.TrimRight(string(data), "\x00")
	name, arg, _ = strings.Cut(s, ":")
	name, _, _ = strings.Cut(name, ",")
	return name, arg
}

// AuthTypeName names the arg0 of an AUTH message.
func AuthTypeName(t uint32) string {
	switch t {
	case 1:
		return "TOKEN"
	case 2:
		return "SIGNATURE"
	case 3:
		return "RSAPUBLICKEY"
	}
	return fmt.Sprintf("%d", t)
}

// SyncRequest is one request of the sync protocol.
type SyncRequest struct {
	ID    string
	Path  string // SEND/STAT/LIST/RECV
	Mode  string // SEND: the ",<mode>" suffix of the path
	Data  []byte // DATA
	Mtime uint32 // DONE
}

// SyncParser reassembles sync requests from the WRTE payloads of a "sync:"
// stream; requests may be split across or batched within messages.
type SyncParser struct {
	buf []byte
}

// Feed appends data and returns every request completed by it. After an
// error the stream is out of sync and must be closed.
func (p *SyncParser) Feed(data []byte) ([]SyncRequest, error) {
	p.buf = append(p.buf, data...)
	var reqs []SyncRequest
	for len(p.buf) >= 8 {
		id := string(p.buf[:4])
		n := binary.LittleEndian.Uint32(p.buf[4:8])
		switch id {
		case "DONE", "QUIT":
			reqs = append(reqs, SyncRequest{ID: id, Mtime: n})
			p.buf = p.buf[8:]
			continue
		case "DATA":
			if n > SyncDataMax {
				return reqs, fmt.Errorf("%w: DATA length %d", ErrSyncRequest, n)
			}
		case "SEND", "STAT", "LIST", "RECV":
			if n > SyncPathMax {
				return reqs, fmt.Errorf("%w: %s path length %d", ErrSyncRequest, id, n)
			}
		default:
			return reqs, fmt.Errorf("%w: id %q", ErrSyncRequest, id)
		}
		if len(p.buf) < 8+int(n) {
			break
		}
		body := bytes.Clone(p.buf[8 : 8+n])
		p.buf = p.buf[8+n:]
		req := SyncRequest{ID: id}
		if id == "DATA" {
			req.Data = body
		} else {
			req.Path = string(body)
			if id == "SEND" {
				if i := strings.LastIndexByte(req.Path, ','); i >= 0 {
					req.Path, req.Mode = req.Path[:i], req.Path[i+1:]
				}
			}
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}

func syncHeader(id string, n uint32) []byte {
	b := make([]byte, 8)
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], n)
	return b
}

// SyncOkay is the reply to a completed SEND.
func SyncOkay() []byte {
	return syncHeader("OKAY", 0)
}

// SyncFail is a sync error reply carrying msg.
func SyncFail(msg string) []byte {
	return append(syncHeader("FAIL", uint32(len(msg))), msg...)
}

// SyncStat is the v1 STAT reply. All zeros means the path does not exist.
func SyncStat(mode, size, mtime uint32) []byte {
	b := make([]byte, 16)
	copy(b, "STAT")
	binary.LittleEndian.PutUint32(b[4:], mode)
	binary.LittleEndian.PutUint32(b[8:], size)
	binary.LittleEndian.PutUint32(b[12:], mtime)
	return b
}

// SyncListDone ends a LIST reply (an empty directory when sent alone).
func SyncListDone() []byte {
	b := make([]byte, 20)
	copy(b, "DONE")
	return b
}
