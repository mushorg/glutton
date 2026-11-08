// Package sadp parses Hikvision SADP (Search Active Devices Protocol)
// discovery datagrams on udp/37020 and builds a camera's reply. A client
// sends "<?xml ...?><Probe><Uuid>…</Uuid><Types>inquiry</Types></Probe>" and
// every device answers with a <ProbeMatch> document that echoes Uuid and
// Types and describes the device (model, serial, MAC, addresses, ports,
// firmware). Other Types (activate, update, reset, ...) are recorded only.
//
// The element names follow SADP replies as commonly seen from Hikvision
// cameras; they were not checked against a capture in this repository.
package sadp

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// TypeInquiry is the discovery request type.
	TypeInquiry = "inquiry"
	// StatusProbeMatch is the decoded `status` of the discovery reply.
	StatusProbeMatch = "ProbeMatch"

	maxField = 128
)

// LooksLikeProbe reports whether b is an un-namespaced SADP <Probe>
// document. WS-Discovery probes use a namespaced (prefixed or xmlns) Probe
// element and do not match.
func LooksLikeProbe(b []byte) bool {
	t := bytes.TrimLeft(b, "\xef\xbb\xbf \t\r\n")
	if len(t) == 0 || t[0] != '<' {
		return false
	}
	return bytes.Contains(t, []byte("<Probe>")) && bytes.Contains(t, []byte("<Types>"))
}

// Request is a parsed <Probe>.
type Request struct {
	Uuid     string
	Types    string
	Password string // activate/modify requests carry one (often encrypted)
}

// Command is the decoded `command`: the lower-cased Types, or "unknown".
func (r Request) Command() string {
	if t := strings.ToLower(r.Types); t != "" {
		return t
	}
	return "unknown"
}

// element returns the text of the first <name>…</name> in b, unescaped and
// clipped to maxField bytes.
func element(b []byte, name string) string {
	open, closeTag := []byte("<"+name+">"), []byte("</"+name+">")
	i := bytes.Index(b, open)
	if i < 0 {
		return ""
	}
	rest := b[i+len(open):]
	j := bytes.Index(rest, closeTag)
	if j < 0 {
		return ""
	}
	v := strings.TrimSpace(string(rest[:j]))
	v = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace(v)
	if len(v) > maxField {
		v = v[:maxField]
	}
	return v
}

// Parse extracts the fields of a <Probe>; it does not fail on malformed XML.
func Parse(b []byte) Request {
	return Request{
		Uuid:     element(b, "Uuid"),
		Types:    element(b, "Types"),
		Password: element(b, "Password"),
	}
}

// Device is the camera the replies describe.
type Device struct {
	Model    string
	Serial   string
	MAC      [6]byte
	IP       net.IP
	Gateway  net.IP
	Software string
	DSP      string
	Uptime   time.Duration
}

// DeviceFor derives a stable device identity from seed (the sensor address).
// The camera sits on a private LAN behind the router that forwards the
// port; the MAC uses the Hikvision C0:56:E3 OUI.
func DeviceFor(seed []byte) Device {
	sum := sha256.Sum256(append([]byte("sadp:"), seed...))
	model := "DS-2CD2042WD-I"
	serialNo := (uint32(sum[4])<<24 | uint32(sum[5])<<16 | uint32(sum[6])<<8 | uint32(sum[7])) % 1000000000
	return Device{
		Model:    model,
		Serial:   fmt.Sprintf("%s20170327AAWR%09d", model, serialNo),
		MAC:      [6]byte{0xc0, 0x56, 0xe3, sum[1], sum[2], sum[3]},
		IP:       net.IPv4(192, 168, 1, 64+sum[0]%100).To4(),
		Gateway:  net.IPv4(192, 168, 1, 1).To4(),
		Software: "V5.4.5build 170124",
		DSP:      "V7.3 build 170103",
		Uptime:   time.Duration(3+int(sum[8])%40)*24*time.Hour + time.Duration(sum[9])*time.Minute*5,
	}
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// BuildProbeMatch is the device's answer to an inquiry. It echoes the
// request Uuid and Types; now sets BootTime (now - Uptime).
func BuildProbeMatch(req Request, d Device, now time.Time) []byte {
	m := d.MAC
	mac := fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x", m[0], m[1], m[2], m[3], m[4], m[5])
	boot := now.UTC().Add(-d.Uptime).Format("2006-01-02 15:04:05")
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ProbeMatch>`)
	field := func(name, v string) { fmt.Fprintf(&b, "<%s>%s</%s>", name, v, name) }
	field("Uuid", esc(req.Uuid))
	field("Types", esc(req.Types))
	field("DeviceType", "139913")
	field("DeviceDescription", d.Model)
	field("DeviceSN", d.Serial)
	field("CommandPort", "8000")
	field("HttpPort", "80")
	field("MAC", mac)
	field("IPv4Address", d.IP.String())
	field("IPv4SubnetMask", "255.255.255.0")
	field("IPv4Gateway", d.Gateway.String())
	field("IPv6Address", "::")
	field("IPv6Gateway", "::")
	field("IPv6MaskLen", "64")
	field("DHCP", "false")
	field("AnalogChannelNum", "0")
	field("DigitalChannelNum", "1")
	field("SoftwareVersion", d.Software)
	field("DSPVersion", d.DSP)
	field("BootTime", boot)
	field("Encrypt", "true")
	field("ResetAbility", "false")
	field("DiskNumber", "0")
	field("Activated", "true")
	field("PasswordResetAbility", "true")
	field("PasswordResetModeSecond", "true")
	b.WriteString(`</ProbeMatch>`)
	return []byte(b.String())
}
