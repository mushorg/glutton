// Package minecraft parses and builds the small part of the Minecraft Java
// Edition protocol that a server-list ping and a login attempt touch.
// It performs no I/O beyond the io.Reader handed to ReadPacket.
package minecraft

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	// MaxPacketLen caps the declared length of an inbound packet.
	MaxPacketLen = 64 * 1024
	// MaxVarIntBytes is the longest legal VarInt encoding.
	MaxVarIntBytes = 5
	maxStringBytes = 1024

	// DefaultProtocol is the protocol number advertised when the client sends
	// none that is usable (e.g. -1 from a scanner).
	DefaultProtocol = 769
	// DefaultVersionName matches DefaultProtocol.
	DefaultVersionName = "1.21.4"

	// Handshake states (next state field).
	StateStatus = 1
	StateLogin  = 2

	// Packet IDs.
	IDHandshake   = 0x00
	IDStatusReq   = 0x00
	IDPing        = 0x01
	IDLoginStart  = 0x00
	IDStatusResp  = 0x00
	IDPong        = 0x01
	IDLoginDiscon = 0x00
)

var (
	ErrVarIntTooLong  = errors.New("minecraft: varint longer than 5 bytes")
	ErrPacketTooLarge = errors.New("minecraft: packet length out of range")
	ErrShortBody      = errors.New("minecraft: truncated packet body")
	ErrBadString      = errors.New("minecraft: invalid string")
)

// Packet is one length-prefixed frame. Raw holds every byte consumed from the
// wire (length prefix included), even when ReadPacket fails part-way.
type Packet struct {
	Raw  []byte
	ID   int32
	Body []byte
}

// Handshake is the first serverbound packet (ID 0x00).
type Handshake struct {
	ProtocolVersion int32
	Address         string
	Port            uint16
	NextState       int32
}

type recordingReader struct {
	r   io.Reader
	buf []byte
}

func (t *recordingReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.buf = append(t.buf, p[:n]...)
	return n, err
}

// ReadVarInt decodes a VarInt and returns it with the number of bytes used.
func ReadVarInt(r io.Reader) (int32, int, error) {
	var (
		v uint32
		b [1]byte
	)
	for i := 0; i < MaxVarIntBytes; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, i, err
		}
		v |= uint32(b[0]&0x7f) << (7 * uint(i))
		if b[0]&0x80 == 0 {
			return int32(v), i + 1, nil
		}
	}
	return 0, MaxVarIntBytes, ErrVarIntTooLong
}

// AppendVarInt appends the VarInt encoding of v to dst.
func AppendVarInt(dst []byte, v int32) []byte {
	u := uint32(v)
	for {
		if u&^0x7f == 0 {
			return append(dst, byte(u))
		}
		dst = append(dst, byte(u&0x7f)|0x80)
		u >>= 7
	}
}

// ReadPacket reads one packet, rejecting lengths outside 1..MaxPacketLen.
// The returned Packet.Raw is always safe to keep (it is a fresh slice).
func ReadPacket(r io.Reader) (Packet, error) {
	rec := &recordingReader{r: r}
	fail := func(err error) (Packet, error) { return Packet{Raw: rec.buf}, err }

	length, _, err := ReadVarInt(rec)
	if err != nil {
		return fail(err)
	}
	if length < 1 || length > MaxPacketLen {
		return fail(fmt.Errorf("%w: %d", ErrPacketTooLarge, length))
	}
	body := make([]byte, length)
	_, err = io.ReadFull(rec, body)
	if err != nil {
		return fail(err)
	}
	br := bytes.NewReader(body)
	id, used, err := ReadVarInt(br)
	if err != nil {
		return fail(err)
	}
	return Packet{Raw: rec.buf, ID: id, Body: body[used:]}, nil
}

func readString(br *bytes.Reader) (string, error) {
	n, _, err := ReadVarInt(br)
	if err != nil {
		return "", err
	}
	if n < 0 || n > maxStringBytes || int(n) > br.Len() {
		return "", ErrBadString
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(br, b); err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", ErrBadString
	}
	return string(b), nil
}

// ParseHandshake decodes the body of a Handshake packet.
func ParseHandshake(body []byte) (Handshake, error) {
	br := bytes.NewReader(body)
	var h Handshake
	var err error
	if h.ProtocolVersion, _, err = ReadVarInt(br); err != nil {
		return h, err
	}
	if h.Address, err = readString(br); err != nil {
		return h, err
	}
	var port [2]byte
	if _, err = io.ReadFull(br, port[:]); err != nil {
		return h, ErrShortBody
	}
	h.Port = binary.BigEndian.Uint16(port[:])
	if h.NextState, _, err = ReadVarInt(br); err != nil {
		return h, err
	}
	return h, nil
}

// ParseLoginStart returns the player name from a Login Start body. Any
// trailing fields (UUID in newer versions) are ignored.
func ParseLoginStart(body []byte) (string, error) {
	return readString(bytes.NewReader(body))
}

// ParsePing returns the 8-byte payload of a Ping packet.
func ParsePing(body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, ErrShortBody
	}
	return append([]byte(nil), body[:8]...), nil
}

// BuildPacket frames an ID and body with the length prefix.
func BuildPacket(id int32, body []byte) []byte {
	inner := AppendVarInt(nil, id)
	inner = append(inner, body...)
	out := AppendVarInt(nil, int32(len(inner)))
	return append(out, inner...)
}

func stringBody(s string) []byte {
	b := AppendVarInt(nil, int32(len(s)))
	return append(b, s...)
}

// BuildStatusResponse builds the Status Response (0x00). The client's protocol
// version is echoed when positive, otherwise DefaultProtocol is used.
func BuildStatusResponse(clientProtocol int32) []byte {
	proto := clientProtocol
	if proto <= 0 {
		proto = DefaultProtocol
	}
	js := fmt.Sprintf(`{"version":{"name":%q,"protocol":%d},"players":{"max":20,"online":0},"description":{"text":"A Minecraft Server"}}`,
		DefaultVersionName, proto)
	return BuildPacket(IDStatusResp, stringBody(js))
}

// BuildPong builds the Pong (0x01) echoing the 8 ping bytes.
func BuildPong(payload []byte) []byte {
	return BuildPacket(IDPong, payload)
}

// BuildLoginDisconnect builds a login-state Disconnect (0x00) with a JSON chat
// component.
func BuildLoginDisconnect() []byte {
	return BuildPacket(IDLoginDiscon, stringBody(`{"text":"You are not white-listed on this server!"}`))
}
