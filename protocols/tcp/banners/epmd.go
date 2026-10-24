package banners

import (
	"bytes"
	"encoding/binary"
)

// Erlang Port Mapper Daemon (epmd, tcp/4369). A request is a 2-byte
// big-endian length and the message; epmd answers one request per connection
// and closes. The persona is the epmd of a RabbitMQ broker: one node, "rabbit",
// on the default distribution port 25672 (AMQP port + 20000). Formats follow
// the ERTS "Distribution Protocol" docs.

const (
	epmdPort      = 4369
	epmdNodeName  = "rabbit"
	epmdNodePort  = 25672
	epmdNamesReq  = 'n' // NAMES_REQ
	epmdPort2Req  = 'z' // PORT_PLEASE2_REQ
	epmdPort2Resp = 'w' // PORT2_RESP
)

// epmdNamesRequest is nmap's epmd probe and what Shodan sends to tcp/4369
// (Ochi live stream 2026-10-24, cereal.scanf.shodan.io).
var epmdNamesRequest = []byte{0x00, 0x01, epmdNamesReq}

// epmdNames is the NAMES_RESP: epmd's own port as a BE u32, then one
// "name <node> at port <port>" line per registered node. nmap match:
// m|^\0\0\x11\x11| p/Erlang Port Mapper Daemon/.
var epmdNames = append(binary.BigEndian.AppendUint32(nil, epmdPort),
	"name "+epmdNodeName+" at port 25672\n"...)

// epmdPortPleaseName returns the node name of a PORT_PLEASE2_REQ, whose
// length prefix must cover the rest of data exactly.
func epmdPortPleaseName(data []byte) (string, bool) {
	if len(data) < 4 || data[2] != epmdPort2Req || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		return "", false
	}
	name := data[3:]
	for _, c := range name {
		if c <= ' ' || c > '~' {
			return "", false
		}
	}
	return string(name), true
}

// epmdPort2 is the PORT2_RESP for name: the node's port and versions for a
// registered node, or result 1 (not found) for any other name.
func epmdPort2(name string) []byte {
	if name != epmdNodeName {
		return []byte{epmdPort2Resp, 1}
	}
	b := []byte{epmdPort2Resp, 0}
	b = binary.BigEndian.AppendUint16(b, epmdNodePort)
	b = append(b, 77, 0) // normal Erlang node, TCP/IPv4
	b = binary.BigEndian.AppendUint16(b, 6)
	b = binary.BigEndian.AppendUint16(b, 5) // distribution versions 6..5 (OTP 23+)
	b = binary.BigEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	return binary.BigEndian.AppendUint16(b, 0) // no extra data
}

// epmdReply answers NAMES_REQ and PORT_PLEASE2_REQ on any port. Both are
// matched exactly (length prefix included), so other 3+ byte payloads that
// start with 00 01 are left alone.
func epmdReply(data []byte) (Response, bool) {
	if bytes.Equal(data, epmdNamesRequest) {
		return Response{Name: "epmd-names", Data: epmdNames, Close: true}, true
	}
	if name, ok := epmdPortPleaseName(data); ok {
		return Response{Name: "epmd-port2", Data: epmdPort2(name), Close: true}, true
	}
	return Response{}, false
}
