// Package nvms9000 parses and builds the TVT NVMS-9000 DVR management
// protocol (tcp/6036). The frame layout is inferred from one captured
// queryBasicCfg request, not taken from a spec:
//
//	"1111"            magic
//	u32 LE            bytes that follow this field
//	u32 LE            version/flags (04 00 00 01)
//	u32 LE            command id (0x091b on queryBasicCfg)
//	u32 LE            unknown (02 01 00 00)
//	u32 LE            body length
//	body              64-byte user, 64-byte operation, then an XML document
//
// The reply layout is not captured: replies echo the request header and carry
// only the XML document.
package nvms9000

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
)

const (
	// PrefixLen is the magic plus the length field.
	PrefixLen = 8
	// HeaderLen is the inner header that follows the prefix.
	HeaderLen = 16
	// MaxFrame bounds the bytes after the prefix that are read.
	MaxFrame = 64 * 1024
	// PeekLen is what LooksLikeNVMS needs to see.
	PeekLen = PrefixLen

	fieldLen = 64
)

// Magic starts every frame.
var Magic = []byte("1111")

var (
	ErrBadMagic = errors.New("nvms9000: bad magic")
	ErrBadLen   = errors.New("nvms9000: bad length")
	ErrTooLarge = errors.New("nvms9000: frame too large")
)

// Header is the inner header.
type Header struct {
	Version uint32
	Command uint32
	Unknown uint32
	BodyLen uint32
}

// Frame is one request or reply.
type Frame struct {
	Header Header
	Body   []byte
}

// Request is the body of a client frame.
type Request struct {
	Username  string
	Operation string
	XML       string
}

// LooksLikeNVMS reports whether b starts like an NVMS-9000 frame: the magic
// and a plausible length.
func LooksLikeNVMS(b []byte) bool {
	if len(b) < PrefixLen || !bytes.HasPrefix(b, Magic) {
		return false
	}
	n := binary.LittleEndian.Uint32(b[4:8])
	return n >= HeaderLen && n <= MaxFrame
}

// ReadFrame reads one frame from r and returns it with its raw wire bytes.
// raw holds whatever was read when err is not nil.
func ReadFrame(r io.Reader) (Frame, []byte, error) {
	raw := make([]byte, PrefixLen)
	n, err := io.ReadFull(r, raw)
	if err != nil {
		return Frame{}, raw[:n], err
	}
	if !bytes.HasPrefix(raw, Magic) {
		return Frame{}, raw, ErrBadMagic
	}
	size := binary.LittleEndian.Uint32(raw[4:8])
	if size < HeaderLen {
		return Frame{}, raw, ErrBadLen
	}
	if size > MaxFrame {
		return Frame{}, raw, ErrTooLarge
	}
	raw = append(raw, make([]byte, size)...)
	m, err := io.ReadFull(r, raw[PrefixLen:])
	if err != nil {
		return Frame{}, raw[:PrefixLen+m], err
	}
	h := raw[PrefixLen:]
	return Frame{
		Header: Header{
			Version: binary.LittleEndian.Uint32(h[0:4]),
			Command: binary.LittleEndian.Uint32(h[4:8]),
			Unknown: binary.LittleEndian.Uint32(h[8:12]),
			BodyLen: binary.LittleEndian.Uint32(h[12:16]),
		},
		Body: raw[PrefixLen+HeaderLen:],
	}, raw, nil
}

// Build returns a frame carrying body under hdr; BodyLen is set from body.
func Build(hdr Header, body []byte) []byte {
	out := make([]byte, 0, PrefixLen+HeaderLen+len(body))
	out = append(out, Magic...)
	out = binary.LittleEndian.AppendUint32(out, uint32(HeaderLen+len(body)))
	out = binary.LittleEndian.AppendUint32(out, hdr.Version)
	out = binary.LittleEndian.AppendUint32(out, hdr.Command)
	out = binary.LittleEndian.AppendUint32(out, hdr.Unknown)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(body)))
	return append(out, body...)
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ParseRequest splits a client body into its user and operation fields and
// the XML document. A body shorter than the two fixed fields is treated as
// bare XML.
func ParseRequest(body []byte) Request {
	if len(body) < 2*fieldLen {
		return Request{XML: strings.TrimSpace(cstr(body))}
	}
	return Request{
		Username:  cstr(body[:fieldLen]),
		Operation: cstr(body[fieldLen : 2*fieldLen]),
		XML:       strings.TrimSpace(cstr(body[2*fieldLen:])),
	}
}

func elemRegexp(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?s)<` + name + `>\s*(?:<!\[CDATA\[(.*?)\]\]>|([^<]*))\s*</` + name + `>`)
}

var (
	userElem = elemRegexp("userName")
	passElem = elemRegexp("password")
)

func elemText(re *regexp.Regexp, xml string) string {
	m := re.FindStringSubmatch(xml)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return m[1]
	}
	return html.UnescapeString(m[2])
}

// Credentials returns the userName and password elements of a login
// document, as the client sent them. The element names are a guess.
func Credentials(xml string) (user, pass string) {
	return elemText(userElem, xml), elemText(passElem, xml)
}

// Identity is the device persona in the basic config reply.
type Identity struct {
	Name     string
	Model    string
	Firmware string
	Serial   string
	MAC      string
}

// RandomIdentity returns an identity with a random serial and MAC so
// sensors do not share a fingerprint.
func RandomIdentity() Identity {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return Identity{
		Name:     "NVR",
		Model:    "TD-2316SS-B",
		Firmware: "1.3.4.2209",
		Serial:   fmt.Sprintf("%X", b[:6]),
		// unicast, globally administered
		MAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[6]&0xfc, b[7], b[8], b[9], b[10], b[11]),
	}
}

// BasicCfgXML is the reply to queryBasicCfg. Element names are a guess at
// the real device's, which was not captured.
func BasicCfgXML(id Identity) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<response version="1.0" systemType="NVMS-9000" status="success">` + "\n" +
		`<content>` + "\n" +
		`<basicInfo>` + "\n" +
		`<name><![CDATA[` + id.Name + `]]></name>` + "\n" +
		`<productModel><![CDATA[` + id.Model + `]]></productModel>` + "\n" +
		`<softwareVersion><![CDATA[` + id.Firmware + `]]></softwareVersion>` + "\n" +
		`<serialNumber><![CDATA[` + id.Serial + `]]></serialNumber>` + "\n" +
		`<macAddress><![CDATA[` + id.MAC + `]]></macAddress>` + "\n" +
		`</basicInfo>` + "\n" +
		`</content>` + "\n" +
		`</response>` + "\n"
}

// FailXML is the reply to every operation that is not emulated, including
// logins, which never succeed.
func FailXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<response version="1.0" systemType="NVMS-9000" status="fail">` + "\n" +
		`<errorCode>536870947</errorCode>` + "\n" +
		`</response>` + "\n"
}
