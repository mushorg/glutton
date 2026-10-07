// Package knx parses KNXnet/IP (udp/3671) datagrams and builds the discovery
// replies of a KNX IP interface. Only the core service family is understood:
// there is no tunnelling or bus emulation.
package knx

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Service types (KNX Standard 3/8/2, core).
const (
	SearchRequest          uint16 = 0x0201
	SearchResponse         uint16 = 0x0202
	DescriptionRequest     uint16 = 0x0203
	DescriptionResponse    uint16 = 0x0204
	ConnectRequest         uint16 = 0x0205
	ConnectResponse        uint16 = 0x0206
	ConnectionStateRequest uint16 = 0x0207
	DisconnectRequest      uint16 = 0x0209
)

const (
	HeaderSize   = 6
	hpaiSize     = 8
	protocolV10  = 0x10
	HPAIUDP      = 0x01
	HPAITCP      = 0x02
	dibDevice    = 0x01
	dibFamilies  = 0x02
	mediumTP1    = 0x02
	deviceDIBLen = 54

	// StatusNoMoreConnections is E_NO_MORE_CONNECTIONS, the stub CONNECT error.
	StatusNoMoreConnections = 0x24
)

// StatusNoMoreConnectionsName is the decoded `status` of the stub CONNECT_RESPONSE.
const StatusNoMoreConnectionsName = "E_NO_MORE_CONNECTIONS"

var (
	ErrShort    = errors.New("knx: datagram shorter than header")
	ErrMagic    = errors.New("knx: bad header size or protocol version")
	ErrLength   = errors.New("knx: total length does not match datagram")
	ErrBadHPAI  = errors.New("knx: malformed HPAI")
	serviceName = map[uint16]string{
		SearchRequest:          "SEARCH_REQUEST",
		DescriptionRequest:     "DESCRIPTION_REQUEST",
		ConnectRequest:         "CONNECT_REQUEST",
		ConnectionStateRequest: "CONNECTIONSTATE_REQUEST",
		DisconnectRequest:      "DISCONNECT_REQUEST",
	}
)

// HPAI is a Host Protocol Address Information structure.
type HPAI struct {
	Protocol byte
	IP       net.IP
	Port     uint16
}

// Request is a parsed KNXnet/IP request. HPAI is nil when the service carries
// none or it was malformed.
type Request struct {
	ServiceType uint16
	HPAI        *HPAI
}

// Command returns the service name, or "UNKNOWN".
func (r *Request) Command() string {
	if r == nil {
		return "UNKNOWN"
	}
	if n, ok := serviceName[r.ServiceType]; ok {
		return n
	}
	return "UNKNOWN"
}

// ServiceTypeString formats a service type as 0xNNNN.
func ServiceTypeString(t uint16) string { return fmt.Sprintf("0x%04x", t) }

// LooksLikeKNX reports whether data has a KNXnet/IP header for one of the
// request services Parse understands and a total length equal to the datagram
// length. Used to reroute from the generic udp handler, so it is deliberately
// strict.
func LooksLikeKNX(data []byte) bool {
	if len(data) < HeaderSize || data[0] != HeaderSize || data[1] != protocolV10 ||
		int(binary.BigEndian.Uint16(data[4:6])) != len(data) {
		return false
	}
	_, ok := serviceName[binary.BigEndian.Uint16(data[2:4])]
	return ok
}

// Parse decodes a request. When the header is readable the returned Request is
// non-nil even if an error is returned (a length mismatch still yields the
// service type); a malformed HPAI leaves Request.HPAI nil and returns no error
// for the header but ErrBadHPAI.
func Parse(data []byte) (*Request, error) {
	if len(data) < HeaderSize {
		return nil, ErrShort
	}
	if data[0] != HeaderSize || data[1] != protocolV10 {
		return nil, ErrMagic
	}
	req := &Request{ServiceType: binary.BigEndian.Uint16(data[2:4])}
	if int(binary.BigEndian.Uint16(data[4:6])) != len(data) {
		return req, ErrLength
	}
	body := data[HeaderSize:]
	switch req.ServiceType {
	case SearchRequest, DescriptionRequest, ConnectRequest:
		// discovery/control endpoint HPAI first
	case ConnectionStateRequest, DisconnectRequest:
		if len(body) < 2 { // channel id + reserved
			return req, ErrBadHPAI
		}
		body = body[2:]
	default:
		return req, nil
	}
	h, err := parseHPAI(body)
	if err != nil {
		return req, err
	}
	req.HPAI = h
	return req, nil
}

func parseHPAI(b []byte) (*HPAI, error) {
	if len(b) < hpaiSize || b[0] != hpaiSize || (b[1] != HPAIUDP && b[1] != HPAITCP) {
		return nil, ErrBadHPAI
	}
	return &HPAI{
		Protocol: b[1],
		IP:       net.IPv4(b[2], b[3], b[4], b[5]),
		Port:     binary.BigEndian.Uint16(b[6:8]),
	}, nil
}

// Device is the fake gateway identity.
type Device struct {
	Address [2]byte
	Serial  [6]byte
	MAC     [6]byte
	Name    string
}

// DeviceFor derives a stable identity from seed (the sensor address). The
// serial and MAC are derived, not real; the MAC is locally administered.
func DeviceFor(seed []byte) Device {
	sum := sha256.Sum256(append([]byte("knx:"), seed...))
	d := Device{Address: [2]byte{0x11, 0x01}, Name: "IP Interface"}
	copy(d.Serial[:], sum[:6])
	copy(d.MAC[:], sum[6:12])
	d.MAC[0] = d.MAC[0]&0xfe | 0x02
	return d
}

func header(service uint16, total int) []byte {
	b := make([]byte, HeaderSize, total)
	b[0], b[1] = HeaderSize, protocolV10
	binary.BigEndian.PutUint16(b[2:], service)
	binary.BigEndian.PutUint16(b[4:], uint16(total))
	return b
}

func deviceDIB(d Device) []byte {
	b := make([]byte, deviceDIBLen)
	b[0], b[1], b[2] = deviceDIBLen, dibDevice, mediumTP1
	// b[3] device status: 0 (programming mode off)
	copy(b[4:6], d.Address[:])
	// b[6:8] project-installation identifier: 0
	copy(b[8:14], d.Serial[:])
	copy(b[14:18], []byte{224, 0, 23, 12}) // KNXnet/IP routing multicast
	copy(b[18:24], d.MAC[:])
	copy(b[24:], d.Name) // zero-padded 30 bytes
	return b
}

func familiesDIB() []byte {
	// Core, Device Management and Tunnelling, all version 1.
	return []byte{8, dibFamilies, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01}
}

// BuildDescriptionResponse returns a DESCRIPTION_RESPONSE.
func BuildDescriptionResponse(d Device) []byte {
	total := HeaderSize + deviceDIBLen + 8
	b := header(DescriptionResponse, total)
	b = append(b, deviceDIB(d)...)
	return append(b, familiesDIB()...)
}

// BuildSearchResponse returns a SEARCH_RESPONSE advertising the control
// endpoint ip:port (the address the request arrived on).
func BuildSearchResponse(d Device, ip net.IP, port uint16) []byte {
	total := HeaderSize + hpaiSize + deviceDIBLen + 8
	b := header(SearchResponse, total)
	hp := []byte{hpaiSize, HPAIUDP, 0, 0, 0, 0, 0, 0}
	if v4 := ip.To4(); v4 != nil {
		copy(hp[2:6], v4)
	}
	binary.BigEndian.PutUint16(hp[6:], port)
	b = append(b, hp...)
	b = append(b, deviceDIB(d)...)
	return append(b, familiesDIB()...)
}

// BuildConnectError returns a CONNECT_RESPONSE refusing the connection.
func BuildConnectError() []byte {
	return append(header(ConnectResponse, 8), 0x00, StatusNoMoreConnections)
}
