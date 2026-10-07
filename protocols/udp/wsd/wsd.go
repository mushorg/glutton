// Package wsd parses WS-Discovery (SOAP-over-UDP, udp/3702) Probe and Resolve
// messages and builds the matching ProbeMatches / ResolveMatches replies. It
// does no I/O.
package wsd

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Actions a client sends.
const (
	CommandProbe   = "Probe"
	CommandResolve = "Resolve"
)

// Status values recorded on write frames.
const (
	StatusProbeMatches   = "ProbeMatches"
	StatusResolveMatches = "ResolveMatches"
)

const (
	nsDiscovery2005 = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
	nsDiscovery2009 = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
	maxTokens       = 512
	maxFieldLen     = 512
	xAddrsPort      = "5357" // WSDAPI
)

// ErrNotWSD is returned when the datagram is not a WS-Discovery envelope.
var ErrNotWSD = errors.New("wsd: not a WS-Discovery message")

// LooksLikeWSD reports whether data is an XML document that names a
// WS-Discovery namespace.
func LooksLikeWSD(data []byte) bool {
	t := bytes.TrimLeft(data, "\xef\xbb\xbf \t\r\n")
	if len(t) == 0 || t[0] != '<' {
		return false
	}
	return bytes.Contains(t, []byte(nsDiscovery2005)) || bytes.Contains(t, []byte(nsDiscovery2009))
}

// Message is a parsed WS-Discovery request.
type Message struct {
	Action    string // full wsa:Action URI
	Command   string // last path segment of Action (Probe, Resolve, Hello, Bye, ...)
	MessageID string
	Types     string
	Scopes    string
	Address   string // Resolve: wsa:EndpointReference/wsa:Address
	Namespace string // discovery namespace in use (2005/04 or 2009/01)
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxFieldLen {
		s = s[:maxFieldLen]
	}
	return s
}

// Parse extracts the addressing headers and the Probe/Resolve body fields.
func Parse(data []byte) (Message, error) {
	var m Message
	if !LooksLikeWSD(data) {
		return m, ErrNotWSD
	}
	if bytes.Contains(data, []byte(nsDiscovery2009)) {
		m.Namespace = nsDiscovery2009
	} else {
		m.Namespace = nsDiscovery2005
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var stack []string
	fields := map[string]*strings.Builder{}
	for i := 0; i < maxTokens; i++ {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if m.Action == "" {
				return m, fmt.Errorf("wsd: %w", err)
			}
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			name := stack[len(stack)-1]
			switch name {
			case "Action", "MessageID", "Types", "Scopes", "Address":
				b := fields[name]
				if b == nil {
					b = &strings.Builder{}
					fields[name] = b
				}
				if b.Len() < maxFieldLen*2 {
					b.Write(t)
				}
			}
		}
	}
	get := func(k string) string {
		if b := fields[k]; b != nil {
			return clip(b.String())
		}
		return ""
	}
	m.Action = get("Action")
	m.MessageID = get("MessageID")
	m.Types = get("Types")
	m.Scopes = get("Scopes")
	m.Address = get("Address")
	if m.Action == "" {
		return m, ErrNotWSD
	}
	if i := strings.LastIndexByte(m.Action, '/'); i >= 0 {
		m.Command = m.Action[i+1:]
	} else {
		m.Command = m.Action
	}
	return m, nil
}

// WantsDevice reports whether a Probe's Types asks for a plain device (or for
// anything). Typed probes for other services, e.g. ONVIF cameras, get no match.
func (m Message) WantsDevice() bool {
	if strings.TrimSpace(m.Types) == "" {
		return true
	}
	for _, t := range strings.Fields(m.Types) {
		if t == "Device" || strings.HasSuffix(t, ":Device") {
			return true
		}
	}
	return false
}

// DeviceUUID returns the stable fake device identity for a sensor address.
func DeviceUUID(seed []byte) string {
	sum := sha256.Sum256(append([]byte("wsd-device:"), seed...))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// DeviceAddress is the endpoint reference address of the fake device.
func DeviceAddress(seed []byte) string { return "urn:uuid:" + DeviceUUID(seed) }

const envelopeFmt = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="%[1]s" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
<soap:Header><wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To><wsa:Action>%[1]s/%[2]s</wsa:Action><wsa:MessageID>urn:uuid:%[3]s</wsa:MessageID>%[4]s<wsd:AppSequence InstanceId="1" MessageNumber="1"/></soap:Header>
<soap:Body><wsd:%[2]s><wsd:%[5]s><wsa:EndpointReference><wsa:Address>%[6]s</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device</wsd:Types><wsd:XAddrs>http://%[7]s:%[8]s/%[9]s</wsd:XAddrs><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:%[5]s></wsd:%[2]s></soap:Body></soap:Envelope>`

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// BuildMatches builds a ProbeMatches or ResolveMatches reply for req from the
// device at host (the sensor address the datagram was sent to). It returns nil
// when a real device would stay silent: other commands, typed probes for
// non-Device types, and Resolve for a different endpoint.
func BuildMatches(req Message, host string) (resp []byte, status string) {
	seed := []byte(host)
	xhost := host
	if strings.Contains(host, ":") {
		xhost = "[" + host + "]"
	}
	addr := DeviceAddress(seed)
	var wrapper, entry string
	switch req.Command {
	case CommandProbe:
		if !req.WantsDevice() {
			return nil, ""
		}
		wrapper, entry, status = "ProbeMatches", "ProbeMatch", StatusProbeMatches
	case CommandResolve:
		if req.Address != addr {
			return nil, ""
		}
		wrapper, entry, status = "ResolveMatches", "ResolveMatch", StatusResolveMatches
	default:
		return nil, ""
	}
	relates := ""
	if req.MessageID != "" {
		relates = "<wsa:RelatesTo>" + xmlEscape(req.MessageID) + "</wsa:RelatesTo>"
	}
	msgSum := sha256.Sum256([]byte(addr + "|" + req.MessageID))
	msgID := DeviceUUID(msgSum[:])
	// The envelope's Action is ".../ProbeMatches", the body wraps ".../ProbeMatch".
	out := fmt.Sprintf(envelopeFmt, req.Namespace, wrapper, msgID, relates, entry, addr, xhost, xAddrsPort, DeviceUUID(seed))
	return []byte(out), status
}
