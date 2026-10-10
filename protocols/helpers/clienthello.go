package helpers

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// ClientHello is the fingerprint-relevant part of a TLS ClientHello. List
// fields keep the values as offered on the wire (GREASE included); the
// fingerprints drop GREASE as their specs require.
type ClientHello struct {
	Version      string   `json:"tls_version,omitempty"` // highest offered version, e.g. "TLS 1.3"
	CipherSuites []uint16 `json:"cipher_suites,omitempty"`
	Extensions   []uint16 `json:"extensions,omitempty"`
	Groups       []uint16 `json:"groups,omitempty"`
	SNI          string   `json:"sni,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	JA3          string   `json:"ja3,omitempty"`
	JA3N         string   `json:"ja3n,omitempty"` // JA3 with extensions sorted, stable across extension-order randomization
	JA4          string   `json:"ja4,omitempty"`
	JA4R         string   `json:"ja4_r,omitempty"` // JA4 with the sorted lists in clear instead of hashed
}

const (
	recordTypeHandshake      = 0x16
	recordHeaderLen          = 5
	handshakeTypeClientHello = 0x01
	handshakeHeaderLen       = 4
	extServerName            = 0x0000
	extSupportedGroups       = 0x000a
	extECPointFormats        = 0x000b
	extSignatureAlgorithms   = 0x000d
	extALPN                  = 0x0010
	extSupportedVersions     = 0x002b
	sniHostName              = 0
	maxHandshakeLen          = 1 << 16
)

// clientHello holds the parsed fields the fingerprints are computed from.
type clientHello struct {
	legacyVersion uint16
	ciphers       []uint16
	extensions    []uint16
	groups        []uint16
	points        []uint8
	sigAlgs       []uint16
	versions      []uint16
	sni           string
	alpn          []string
}

// ParseClientHello parses the ClientHello at the start of data, as captured
// raw from the wire (record framing included, possibly spread over several
// handshake records). The parser is lenient where crypto/tls is strict:
// duplicate extensions, an SNI with a trailing dot, or an extension whose
// body does not parse still yield a fingerprint, because odd hellos are what
// a honeypot wants to tell apart. It reports false when data does not hold a
// complete ClientHello up to its extensions block.
func ParseClientHello(data []byte) (*ClientHello, bool) {
	body, ok := clientHelloBody(data)
	if !ok {
		return nil, false
	}
	ch, ok := parseClientHelloBody(body)
	if !ok {
		return nil, false
	}

	hello := &ClientHello{
		CipherSuites: ch.ciphers,
		Extensions:   ch.extensions,
		Groups:       ch.groups,
		SNI:          ch.sni,
		ALPN:         ch.alpn,
	}
	version := ch.version()
	if version != 0 {
		hello.Version = tls.VersionName(version)
	}
	hello.JA3 = md5Hex(ja3String(ch, false))
	hello.JA3N = md5Hex(ja3String(ch, true))
	hello.JA4, hello.JA4R = ja4(version, ch)
	return hello, true
}

// clientHelloBody reassembles the first handshake message from the
// consecutive handshake records at the start of data and returns the
// ClientHello body (after the handshake header).
func clientHelloBody(data []byte) ([]byte, bool) {
	var hs []byte
	for len(data) >= recordHeaderLen && data[0] == recordTypeHandshake {
		n := int(data[3])<<8 | int(data[4])
		if len(data) < recordHeaderLen+n {
			return nil, false
		}
		hs = append(hs, data[recordHeaderLen:recordHeaderLen+n]...)
		data = data[recordHeaderLen+n:]
		if len(hs) < handshakeHeaderLen {
			continue
		}
		if hs[0] != handshakeTypeClientHello {
			return nil, false
		}
		msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if msgLen > maxHandshakeLen {
			return nil, false
		}
		if len(hs) >= handshakeHeaderLen+msgLen {
			return hs[handshakeHeaderLen : handshakeHeaderLen+msgLen], true
		}
	}
	return nil, false
}

// parseClientHelloBody reads the fixed fields strictly and the extensions
// leniently: a truncated extension list keeps the extensions before the
// break, and a malformed extension body only loses that extension's values.
func parseClientHelloBody(body []byte) (*clientHello, bool) {
	s := cryptobyte.String(body)
	ch := &clientHello{}
	var sessionID, ciphers, compression cryptobyte.String
	if !s.ReadUint16(&ch.legacyVersion) || !s.Skip(32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16LengthPrefixed(&ciphers) ||
		!s.ReadUint8LengthPrefixed(&compression) {
		return nil, false
	}
	ch.ciphers = readUint16s(ciphers)
	if s.Empty() {
		return ch, true // no extensions block, as SSL 3.0 / early TLS clients send
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		return nil, false
	}
	seen := make(map[uint16]bool)
	for !exts.Empty() {
		var typ uint16
		var ext cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&ext) {
			break
		}
		ch.extensions = append(ch.extensions, typ)
		if seen[typ] {
			continue // the first occurrence of a duplicated extension wins
		}
		seen[typ] = true
		ch.parseExtension(typ, ext)
	}
	return ch, true
}

func (ch *clientHello) parseExtension(typ uint16, ext cryptobyte.String) {
	var list cryptobyte.String
	switch typ {
	case extServerName:
		if !ext.ReadUint16LengthPrefixed(&list) {
			return
		}
		for !list.Empty() {
			var nameType uint8
			var name cryptobyte.String
			if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
				return
			}
			if nameType == sniHostName {
				ch.sni = string(name)
				return
			}
		}
	case extALPN:
		if !ext.ReadUint16LengthPrefixed(&list) {
			return
		}
		for !list.Empty() {
			var proto cryptobyte.String
			if !list.ReadUint8LengthPrefixed(&proto) {
				return
			}
			ch.alpn = append(ch.alpn, string(proto))
		}
	case extSupportedGroups:
		if ext.ReadUint16LengthPrefixed(&list) {
			ch.groups = readUint16s(list)
		}
	case extECPointFormats:
		if ext.ReadUint8LengthPrefixed(&list) {
			ch.points = []uint8(list)
		}
	case extSignatureAlgorithms:
		if ext.ReadUint16LengthPrefixed(&list) {
			ch.sigAlgs = readUint16s(list)
		}
	case extSupportedVersions:
		if ext.ReadUint8LengthPrefixed(&list) {
			ch.versions = readUint16s(list)
		}
	}
}

// readUint16s reads big-endian uint16 values until s runs out; an odd
// trailing byte is dropped.
func readUint16s(s cryptobyte.String) []uint16 {
	var out []uint16
	var v uint16
	for s.ReadUint16(&v) {
		out = append(out, v)
	}
	return out
}

// version is the highest offered version: the supported_versions maximum
// when the extension is present, legacy_version otherwise.
func (ch *clientHello) version() uint16 {
	if slices.Contains(ch.extensions, extSupportedVersions) {
		return maxVersion(ch.versions)
	}
	return ch.legacyVersion
}

func maxVersion(versions []uint16) uint16 {
	var v uint16
	for _, x := range versions {
		if !isGREASE(x) && x > v {
			v = x
		}
	}
	return v
}

// isGREASE matches the RFC 8701 reserved values 0x0a0a, 0x1a1a, ... 0xfafa.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func withoutGREASE(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinDec(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinHex(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ja3String is "version,ciphers,extensions,groups,point_formats". With
// sorted set it is the JA3N string: extensions in ascending order, so
// clients that shuffle their extensions (Chrome since 110) keep one value.
func ja3String(ch *clientHello, sorted bool) string {
	exts := withoutGREASE(ch.extensions)
	if sorted {
		slices.Sort(exts)
	}
	points := make([]string, len(ch.points))
	for i, p := range ch.points {
		points[i] = strconv.Itoa(int(p))
	}
	return strings.Join([]string{
		strconv.Itoa(int(ch.legacyVersion)),
		joinDec(withoutGREASE(ch.ciphers)),
		joinDec(exts),
		joinDec(withoutGREASE(ch.groups)),
		strings.Join(points, "-"),
	}, ",")
}

// ja4 builds the FoxIO JA4 fingerprint for a TCP ClientHello,
// t<ver><sni><#ciphers><#exts><alpn>_<sorted ciphers hash>_<sorted exts+sigalgs hash>,
// and its raw form JA4_r with the two hashed sections in clear.
func ja4(version uint16, ch *clientHello) (string, string) {
	ciphers := withoutGREASE(ch.ciphers)
	exts := withoutGREASE(ch.extensions)
	sni := "i"
	if slices.Contains(exts, extServerName) {
		sni = "d"
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(version), sni, min(len(ciphers), 99), min(len(exts), 99), ja4ALPN(ch.alpn))

	slices.Sort(ciphers)
	b := joinHex(ciphers)

	sorted := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != extServerName && e != extALPN {
			sorted = append(sorted, e)
		}
	}
	slices.Sort(sorted)
	c := joinHex(sorted)
	if sigs := withoutGREASE(ch.sigAlgs); len(sigs) > 0 {
		c += "_" + joinHex(sigs)
	}
	return a + "_" + ja4Hash(b, len(ciphers) == 0) + "_" + ja4Hash(c, len(exts) == 0), a + "_" + b + "_" + c
}

func ja4Version(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

// ja4ALPN is the first and last character of the first ALPN value, or the
// first and last hex digit of it when either character is not alphanumeric.
func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(p))
	return string([]byte{h[0], h[len(h)-1]})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func ja4Hash(s string, empty bool) string {
	if empty {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
