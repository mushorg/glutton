// Package spice parses the link stage of the SPICE remote display protocol
// (spice-protocol spice/protocol.h, spice-server reds.c): the client's
// SpiceLinkMess, the server's SpiceLinkReply carrying an RSA public key, the
// optional auth mechanism selection and the RSA-OAEP encrypted ticket
// (password), and builds the server replies.
package spice

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Magic is the link header magic, "REDQ" on the wire.
var Magic = []byte("REDQ")

const (
	VersionMajor = 2
	VersionMinor = 2

	// HeaderLen is the size of SpiceLinkHeader.
	HeaderLen = 16
	// LinkMessLen is the fixed part of SpiceLinkMess.
	LinkMessLen = 18
	// MaxLinkMess bounds the announced link message size; clients send a few
	// dozen bytes of caps.
	MaxLinkMess = 4096
	// PubKeyLen is SPICE_TICKET_PUBKEY_BYTES, the DER SubjectPublicKeyInfo
	// of an RSA-1024 key.
	PubKeyLen = 162
	// KeyBits is SPICE_TICKET_KEY_PAIR_LENGTH.
	KeyBits = 1024
	// TicketLen is the size of the encrypted ticket.
	TicketLen = KeyBits / 8
	// linkReplyLen is the fixed part of SpiceLinkReply.
	linkReplyLen = 4 + PubKeyLen + 12
)

// Link errors (spice-protocol enums.h, SpiceLinkErr).
const (
	LinkErrOK                  = 0
	LinkErrError               = 1
	LinkErrInvalidMagic        = 2
	LinkErrInvalidData         = 3
	LinkErrVersionMismatch     = 4
	LinkErrNeedSecured         = 5
	LinkErrNeedUnsecured       = 6
	LinkErrPermissionDenied    = 7
	LinkErrBadConnectionID     = 8
	LinkErrChannelNotAvailable = 9
)

// Common capability bits (SPICE_COMMON_CAP_*).
const (
	CapProtocolAuthSelection = 0
	CapAuthSpice             = 1
	CapAuthSASL              = 2
	CapMiniHeader            = 3
)

// Auth mechanisms sent in SpiceLinkAuthMechanism; they reuse the common
// capability numbers.
const (
	AuthSpice = CapAuthSpice
	AuthSASL  = CapAuthSASL
)

// ChannelMain is SPICE_CHANNEL_MAIN.
const ChannelMain = 1

var (
	ErrMagic    = errors.New("spice: invalid magic")
	ErrVersion  = errors.New("spice: unsupported major version")
	ErrSize     = errors.New("spice: invalid link message size")
	ErrLinkMess = errors.New("spice: malformed link message")
	ErrPubKey   = errors.New("spice: public key is not an RSA-1024 SubjectPublicKeyInfo")
)

// Header is SpiceLinkHeader.
type Header struct {
	Major, Minor uint32
	Size         uint32
}

// Version renders the header version as "major.minor".
func (h Header) Version() string {
	return strconv.FormatUint(uint64(h.Major), 10) + "." + strconv.FormatUint(uint64(h.Minor), 10)
}

// LooksLikeSPICE reports whether b starts with the link header magic.
func LooksLikeSPICE(b []byte) bool {
	return bytes.HasPrefix(b, Magic)
}

// ParseHeader decodes a SpiceLinkHeader. The header is returned with
// ErrVersion or ErrSize so callers can still record the version; the reply a
// server sends for each error is LinkErrorFor.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen || !LooksLikeSPICE(b) {
		return Header{}, ErrMagic
	}
	h := Header{
		Major: binary.LittleEndian.Uint32(b[4:8]),
		Minor: binary.LittleEndian.Uint32(b[8:12]),
		Size:  binary.LittleEndian.Uint32(b[12:16]),
	}
	if h.Major != VersionMajor {
		return h, ErrVersion
	}
	if h.Size < LinkMessLen || h.Size > MaxLinkMess {
		return h, ErrSize
	}
	return h, nil
}

// LinkErrorFor maps a parse error to the link error a server answers with.
func LinkErrorFor(err error) uint32 {
	switch {
	case errors.Is(err, ErrMagic):
		return LinkErrInvalidMagic
	case errors.Is(err, ErrVersion):
		return LinkErrVersionMismatch
	default:
		return LinkErrInvalidData
	}
}

// LinkMess is SpiceLinkMess with its capability words.
type LinkMess struct {
	ConnectionID uint32
	ChannelType  uint8
	ChannelID    uint8
	CommonCaps   []uint32
	ChannelCaps  []uint32
}

// HasCommonCap reports whether the client set common capability bit.
func (m LinkMess) HasCommonCap(bit uint) bool {
	return hasCap(m.CommonCaps, bit)
}

// ParseLinkMess decodes the link message body (Header.Size bytes). The
// caps must lie inside the body, as spice-server checks.
func ParseLinkMess(b []byte) (LinkMess, error) {
	if len(b) < LinkMessLen {
		return LinkMess{}, ErrLinkMess
	}
	m := LinkMess{
		ConnectionID: binary.LittleEndian.Uint32(b[0:4]),
		ChannelType:  b[4],
		ChannelID:    b[5],
	}
	numCommon := binary.LittleEndian.Uint32(b[6:10])
	numChannel := binary.LittleEndian.Uint32(b[10:14])
	offset := binary.LittleEndian.Uint32(b[14:18])
	total := uint64(numCommon) + uint64(numChannel)
	if total == 0 {
		return m, nil
	}
	if offset < LinkMessLen || uint64(offset)+total*4 > uint64(len(b)) {
		return m, ErrLinkMess
	}
	words := make([]uint32, total)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(b[offset+uint32(i)*4:])
	}
	m.CommonCaps, m.ChannelCaps = words[:numCommon], words[numCommon:]
	return m, nil
}

// BuildLinkReply builds the SpiceLinkHeader and SpiceLinkReply that accept
// a link message: error OK, the server's public key and its caps.
func BuildLinkReply(pubKey []byte, commonCaps, channelCaps []uint32) ([]byte, error) {
	if len(pubKey) != PubKeyLen {
		return nil, ErrPubKey
	}
	size := linkReplyLen + 4*(len(commonCaps)+len(channelCaps))
	b := appendHeader(make([]byte, 0, HeaderLen+size), uint32(size))
	b = binary.LittleEndian.AppendUint32(b, LinkErrOK)
	b = append(b, pubKey...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(commonCaps)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(channelCaps)))
	b = binary.LittleEndian.AppendUint32(b, linkReplyLen)
	for _, c := range append(append([]uint32(nil), commonCaps...), channelCaps...) {
		b = binary.LittleEndian.AppendUint32(b, c)
	}
	return b, nil
}

// BuildLinkError builds the header and reply spice-server sends when it
// refuses a link before authentication (reds_send_link_error): the error
// code and an all-zero key, no caps.
func BuildLinkError(code uint32) []byte {
	b := appendHeader(make([]byte, 0, HeaderLen+linkReplyLen), linkReplyLen)
	b = binary.LittleEndian.AppendUint32(b, code)
	b = append(b, make([]byte, PubKeyLen)...)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 0)
	return binary.LittleEndian.AppendUint32(b, linkReplyLen)
}

// BuildLinkResult builds the 4-byte result sent after the ticket.
func BuildLinkResult(code uint32) []byte {
	return binary.LittleEndian.AppendUint32(nil, code)
}

func appendHeader(b []byte, size uint32) []byte {
	b = append(b, Magic...)
	b = binary.LittleEndian.AppendUint32(b, VersionMajor)
	b = binary.LittleEndian.AppendUint32(b, VersionMinor)
	return binary.LittleEndian.AppendUint32(b, size)
}

// LinkReply is the decoded server reply, used by tests and tooling.
type LinkReply struct {
	Header      Header
	Error       uint32
	PubKey      []byte
	CommonCaps  []uint32
	ChannelCaps []uint32
	CapsOffset  uint32
}

// ParseLinkReply decodes a SpiceLinkHeader followed by a SpiceLinkReply.
func ParseLinkReply(b []byte) (LinkReply, error) {
	if len(b) < HeaderLen || !LooksLikeSPICE(b) {
		return LinkReply{}, ErrMagic
	}
	r := LinkReply{Header: Header{
		Major: binary.LittleEndian.Uint32(b[4:8]),
		Minor: binary.LittleEndian.Uint32(b[8:12]),
		Size:  binary.LittleEndian.Uint32(b[12:16]),
	}}
	body := b[HeaderLen:]
	if uint64(len(body)) != uint64(r.Header.Size) || len(body) < linkReplyLen {
		return r, ErrSize
	}
	r.Error = binary.LittleEndian.Uint32(body[0:4])
	r.PubKey = body[4 : 4+PubKeyLen]
	rest := body[4+PubKeyLen:]
	numCommon := binary.LittleEndian.Uint32(rest[0:4])
	numChannel := binary.LittleEndian.Uint32(rest[4:8])
	r.CapsOffset = binary.LittleEndian.Uint32(rest[8:12])
	total := uint64(numCommon) + uint64(numChannel)
	if uint64(r.CapsOffset)+total*4 > uint64(len(body)) {
		return r, ErrSize
	}
	for i := uint64(0); i < total; i++ {
		c := binary.LittleEndian.Uint32(body[uint64(r.CapsOffset)+i*4:])
		if i < uint64(numCommon) {
			r.CommonCaps = append(r.CommonCaps, c)
		} else {
			r.ChannelCaps = append(r.ChannelCaps, c)
		}
	}
	return r, nil
}

// MarshalPublicKey encodes pub the way spice-server does (i2d_PUBKEY) and
// checks it has the fixed SPICE key size.
func MarshalPublicKey(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if len(der) != PubKeyLen {
		return nil, ErrPubKey
	}
	return der, nil
}

// DecryptTicket decrypts an encrypted ticket (RSA-OAEP with SHA-1, no label)
// and returns the password up to its NUL terminator.
func DecryptTicket(priv *rsa.PrivateKey, ticket []byte) (string, error) {
	plain, err := rsa.DecryptOAEP(sha1.New(), nil, priv, ticket, nil)
	if err != nil {
		return "", err
	}
	if i := bytes.IndexByte(plain, 0); i >= 0 {
		plain = plain[:i]
	}
	return string(plain), nil
}

// EncryptTicket encrypts password as a SPICE client does; used by tests.
func EncryptTicket(pub *rsa.PublicKey, password string, random io.Reader) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), random, pub, append([]byte(password), 0), nil)
}

var channelNames = map[uint8]string{
	1: "main", 2: "display", 3: "inputs", 4: "cursor", 5: "playback", 6: "record",
	7: "tunnel", 8: "smartcard", 9: "usbredir", 10: "port", 11: "webdav",
}

// ChannelTypeName names a channel type, or returns its number.
func ChannelTypeName(t uint8) string {
	if n, ok := channelNames[t]; ok {
		return n
	}
	return strconv.Itoa(int(t))
}

var linkErrNames = map[uint32]string{
	LinkErrOK: "OK", LinkErrError: "Error", LinkErrInvalidMagic: "InvalidMagic",
	LinkErrInvalidData: "InvalidData", LinkErrVersionMismatch: "VersionMismatch",
	LinkErrNeedSecured: "NeedSecured", LinkErrNeedUnsecured: "NeedUnsecured",
	LinkErrPermissionDenied: "PermissionDenied", LinkErrBadConnectionID: "BadConnectionID",
	LinkErrChannelNotAvailable: "ChannelNotAvailable",
}

// LinkErrorName names a link error code, or returns its number.
func LinkErrorName(code uint32) string {
	if n, ok := linkErrNames[code]; ok {
		return n
	}
	return strconv.FormatUint(uint64(code), 10)
}

// AuthMechanismName names an auth mechanism, or returns its number.
func AuthMechanismName(m uint32) string {
	switch m {
	case AuthSpice:
		return "SPICE"
	case AuthSASL:
		return "SASL"
	}
	return strconv.FormatUint(uint64(m), 10)
}

// CapsHex renders capability words as comma-separated 8-digit hex.
func CapsHex(caps []uint32) string {
	parts := make([]string, len(caps))
	for i, c := range caps {
		parts[i] = fmt.Sprintf("%08x", c)
	}
	return strings.Join(parts, ",")
}

func hasCap(caps []uint32, bit uint) bool {
	i := bit / 32
	return int(i) < len(caps) && caps[i]&(1<<(bit%32)) != 0
}
