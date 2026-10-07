// Package ddp parses PlayStation Device Discovery Protocol (DDP) requests and
// builds the "Server Standby" search reply a sleeping PS4/PS5 sends. DDP is an
// HTTP-like text protocol on udp/987 (PS4) and udp/9302 (PS5) with bare-LF
// line ends and no terminating empty line.
package ddp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Request methods a Remote Play / Second Screen client sends.
const (
	MethodSearch = "SRCH"
	MethodWakeup = "WAKEUP"
	MethodLaunch = "LAUNCH"
)

// Header names recorded from requests.
const (
	HeaderVersion        = "device-discovery-protocol-version"
	HeaderUserCredential = "user-credential"
	HeaderClientType     = "client-type"
)

// StatusStandby is the status code of a console in rest mode.
const StatusStandby = "620"

const (
	ps4Version       = "00020020"
	ps5Version       = "00030010"
	ps4SystemVersion = "11008001" // firmware 11.00
	ps5SystemVersion = "07610001" // firmware 7.61
	hostRequestPort  = "997"
)

var methods = []string{MethodSearch, MethodWakeup, MethodLaunch}

// ErrNotDDP is returned when the request line is not a DDP request.
var ErrNotDDP = errors.New("ddp: not a DDP request line")

// LooksLikeDDP reports whether data starts with a DDP request line
// (`SRCH|WAKEUP|LAUNCH * HTTP/1.1` ended by LF or CRLF).
func LooksLikeDDP(data []byte) bool {
	for _, m := range methods {
		line := []byte(m + " * HTTP/1.1")
		if !bytes.HasPrefix(data, line) {
			continue
		}
		rest := data[len(line):]
		return bytes.HasPrefix(rest, []byte("\n")) || bytes.HasPrefix(rest, []byte("\r\n"))
	}
	return false
}

// Request is a parsed DDP request.
type Request struct {
	Method  string
	Headers map[string]string // lowercased keys, trimmed values
}

// Version returns the client's device-discovery-protocol-version.
func (r Request) Version() string { return r.Headers[HeaderVersion] }

// Parse splits a DDP request into its method and `key:value` headers. Lines
// may end in LF or CRLF; parsing stops at the first empty line.
func Parse(data []byte) (Request, error) {
	if !LooksLikeDDP(data) {
		return Request{}, ErrNotDDP
	}
	lines := strings.Split(string(data), "\n")
	req := Request{
		Method:  strings.SplitN(lines[0], " ", 2)[0],
		Headers: map[string]string{},
	}
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		req.Headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return req, nil
}

// Console is the identity a search reply advertises.
type Console struct {
	HostID   string // 12 upper-case hex digits (the console MAC)
	HostType string // PS4 or PS5
	HostName string
	Version  string // device-discovery-protocol-version
	System   string // system-version
}

// ConsoleFor derives a stable console identity from seed (e.g. the sensor
// address) for a client speaking clientVersion. Clients on protocol version
// 0003xxxx are answered as a PS5, everyone else as a PS4.
func ConsoleFor(seed []byte, clientVersion string) Console {
	sum := sha256.Sum256(append([]byte("ddp:"), seed...))
	c := Console{
		HostID:   fmt.Sprintf("%X", sum[:6]),
		HostType: "PS4",
		Version:  ps4Version,
		System:   ps4SystemVersion,
	}
	if strings.HasPrefix(clientVersion, "0003") {
		c.HostType = "PS5"
		c.Version = ps5Version
		c.System = ps5SystemVersion
	}
	c.HostName = fmt.Sprintf("%s-%03d", c.HostType, binary.BigEndian.Uint16(sum[6:8])%1000)
	return c
}

// BuildSearchResponse returns the LF-terminated "620 Server Standby" reply
// to a SRCH request.
func BuildSearchResponse(c Console) []byte {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + StatusStandby + " Server Standby\n")
	b.WriteString("host-id:" + c.HostID + "\n")
	b.WriteString("host-type:" + c.HostType + "\n")
	b.WriteString("host-name:" + c.HostName + "\n")
	b.WriteString("host-request-port:" + hostRequestPort + "\n")
	b.WriteString(HeaderVersion + ":" + c.Version + "\n")
	b.WriteString("system-version:" + c.System + "\n")
	return []byte(b.String())
}
