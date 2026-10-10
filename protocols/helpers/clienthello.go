package helpers

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ClientHello is the fingerprint-relevant part of a TLS ClientHello. List
// fields keep the values as offered on the wire (GREASE included); JA3 and JA4
// drop GREASE as their specs require.
type ClientHello struct {
	Version      string   `json:"tls_version,omitempty"` // highest offered version, e.g. "TLS 1.3"
	CipherSuites []uint16 `json:"cipher_suites,omitempty"`
	Extensions   []uint16 `json:"extensions,omitempty"`
	Groups       []uint16 `json:"groups,omitempty"`
	SNI          string   `json:"sni,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
	JA3          string   `json:"ja3,omitempty"`
	JA4          string   `json:"ja4,omitempty"`
}

const (
	extSupportedVersions = 0x002b
	extServerName        = 0x0000
	extALPN              = 0x0010
)

var errHelloParsed = errors.New("client hello parsed")

// ParseClientHello parses the ClientHello at the start of data, as captured
// raw from the wire (record framing included). It runs crypto/tls's own
// server-side parser over the bytes and stops right after the hello, so
// nothing is sent anywhere. It reports false when data does not hold a
// complete, well-formed ClientHello.
func ParseClientHello(data []byte) (*ClientHello, bool) {
	var info *tls.ClientHelloInfo
	srv := tls.Server(&replayConn{r: bytes.NewReader(data)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			info = hello
			return nil, errHelloParsed
		},
	})
	_ = srv.HandshakeContext(context.Background())
	if info == nil {
		return nil, false
	}

	hello := &ClientHello{
		CipherSuites: info.CipherSuites,
		Extensions:   info.Extensions,
		SNI:          info.ServerName,
		ALPN:         info.SupportedProtos,
	}
	for _, c := range info.SupportedCurves {
		hello.Groups = append(hello.Groups, uint16(c))
	}
	legacy := legacyVersion(data)
	version := legacy
	if slices.Contains(info.Extensions, extSupportedVersions) {
		version = maxVersion(info.SupportedVersions)
	}
	if version != 0 {
		hello.Version = tls.VersionName(version)
	}
	hello.JA3 = ja3(legacy, info)
	hello.JA4 = ja4(version, info)
	return hello, true
}

// legacyVersion reads legacy_version from a ClientHello that starts in the
// first record of data, or 0 when it is not there.
func legacyVersion(data []byte) uint16 {
	// record header (5) + handshake header (4) + legacy_version (2)
	if len(data) < 11 || data[0] != 0x16 || data[5] != 0x01 {
		return 0
	}
	return uint16(data[9])<<8 | uint16(data[10])
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

// ja3 is the MD5 of "version,ciphers,extensions,groups,point_formats".
func ja3(legacy uint16, info *tls.ClientHelloInfo) string {
	groups := make([]uint16, 0, len(info.SupportedCurves))
	for _, c := range info.SupportedCurves {
		groups = append(groups, uint16(c))
	}
	points := make([]string, len(info.SupportedPoints))
	for i, p := range info.SupportedPoints {
		points[i] = strconv.Itoa(int(p))
	}
	s := strings.Join([]string{
		strconv.Itoa(int(legacy)),
		joinDec(withoutGREASE(info.CipherSuites)),
		joinDec(withoutGREASE(info.Extensions)),
		joinDec(withoutGREASE(groups)),
		strings.Join(points, "-"),
	}, ",")
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ja4 builds the FoxIO JA4 fingerprint for a TCP ClientHello:
// t<ver><sni><#ciphers><#exts><alpn>_<sorted ciphers hash>_<sorted exts+sigalgs hash>.
func ja4(version uint16, info *tls.ClientHelloInfo) string {
	ciphers := withoutGREASE(info.CipherSuites)
	exts := withoutGREASE(info.Extensions)
	sni := "i"
	if slices.Contains(exts, extServerName) {
		sni = "d"
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(version), sni, min(len(ciphers), 99), min(len(exts), 99), ja4ALPN(info.SupportedProtos))

	slices.Sort(ciphers)
	b := ja4Hash(joinHex(ciphers), len(ciphers) == 0)

	sorted := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != extServerName && e != extALPN {
			sorted = append(sorted, e)
		}
	}
	slices.Sort(sorted)
	cs := joinHex(sorted)
	if len(info.SignatureSchemes) > 0 {
		sigs := make([]uint16, len(info.SignatureSchemes))
		for i, s := range info.SignatureSchemes {
			sigs[i] = uint16(s)
		}
		cs += "_" + joinHex(sigs)
	}
	c := ja4Hash(cs, len(exts) == 0)
	return a + "_" + b + "_" + c
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

// replayConn feeds captured bytes to crypto/tls and discards its replies.
type replayConn struct {
	r *bytes.Reader
}

func (c *replayConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *replayConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return nil }
func (c *replayConn) RemoteAddr() net.Addr             { return nil }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }
