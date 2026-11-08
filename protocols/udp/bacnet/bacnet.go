// Package bacnet parses BACnet/IP (udp/47808) datagrams (BVLC, NPDU, APDU
// header) and builds the replies of a single BACnet device: I-Am for Who-Is,
// ReadProperty-ACK for the device object's identity properties, and Error or
// Reject PDUs for everything else. Nothing is ever written or controlled.
package bacnet

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// BVLC (Annex J) functions.
const (
	BVLCResult                   byte = 0x00
	BVLCReadBDT                  byte = 0x02
	BVLCRegisterForeignDevice    byte = 0x05
	BVLCReadFDT                  byte = 0x06
	BVLCForwardedNPDU            byte = 0x04
	BVLCDistributeBroadcastToNet byte = 0x09
	BVLCOriginalUnicast          byte = 0x0a
	BVLCOriginalBroadcast        byte = 0x0b

	bvlcType = 0x81
	// BVLCHeaderSize is type, function and the 2-byte length.
	BVLCHeaderSize = 4
)

// APDU types.
const (
	PDUConfirmed   byte = 0
	PDUUnconfirmed byte = 1
	pduComplexACK  byte = 3
	pduError       byte = 5
	pduReject      byte = 6
)

// Service choices used here.
const (
	ServiceReadProperty       byte   = 0x0c
	ServiceWhoIs              byte   = 0x08
	serviceIAm                byte   = 0x00
	ObjectDevice              uint16 = 8
	WildcardInstance          uint32 = 0x3fffff
	PropObjectIdentifier      uint32 = 75
	maxAPDUAccepted                  = 1476
	rejectUnrecognizedService byte   = 9
)

// Error classes/codes (clause 18).
const (
	ErrClassObject   byte = 1
	ErrClassProperty byte = 2
	ErrClassSecurity byte = 4
	ErrClassServices byte = 5

	ErrCodeUnknownObject      byte = 31
	ErrCodeUnknownProperty    byte = 32
	ErrCodeNotAnArray         byte = 50
	ErrCodeWriteAccessDenied  byte = 40
	ErrCodePasswordFailure    byte = 26
	ErrCodeServiceRequestDeny byte = 29
)

var (
	ErrShort  = errors.New("bacnet: datagram shorter than BVLC header")
	ErrMagic  = errors.New("bacnet: not a BACnet/IP BVLC")
	ErrLength = errors.New("bacnet: BVLC length does not match datagram")
	ErrNPDU   = errors.New("bacnet: malformed NPDU")
	ErrAPDU   = errors.New("bacnet: malformed APDU")
)

var bvlcNames = map[byte]string{
	BVLCResult:                   "BVLC_RESULT",
	0x01:                         "WRITE_BDT",
	BVLCReadBDT:                  "READ_BDT",
	0x03:                         "READ_BDT_ACK",
	BVLCForwardedNPDU:            "FORWARDED_NPDU",
	BVLCRegisterForeignDevice:    "REGISTER_FOREIGN_DEVICE",
	BVLCReadFDT:                  "READ_FDT",
	0x07:                         "READ_FDT_ACK",
	0x08:                         "DELETE_FDT_ENTRY",
	BVLCDistributeBroadcastToNet: "DISTRIBUTE_BROADCAST_TO_NETWORK",
	BVLCOriginalUnicast:          "ORIGINAL_UNICAST_NPDU",
	BVLCOriginalBroadcast:        "ORIGINAL_BROADCAST_NPDU",
	0x0c:                         "SECURE_BVLL",
}

var confirmedNames = map[byte]string{
	0x00: "ACKNOWLEDGE_ALARM", 0x01: "CONFIRMED_COV_NOTIFICATION", 0x02: "CONFIRMED_EVENT_NOTIFICATION",
	0x03: "GET_ALARM_SUMMARY", 0x04: "GET_ENROLLMENT_SUMMARY", 0x05: "SUBSCRIBE_COV",
	0x06: "ATOMIC_READ_FILE", 0x07: "ATOMIC_WRITE_FILE", 0x08: "ADD_LIST_ELEMENT",
	0x09: "REMOVE_LIST_ELEMENT", 0x0a: "CREATE_OBJECT", 0x0b: "DELETE_OBJECT",
	0x0c: "READ_PROPERTY", 0x0e: "READ_PROPERTY_MULTIPLE", 0x0f: "WRITE_PROPERTY",
	0x10: "WRITE_PROPERTY_MULTIPLE", 0x11: "DEVICE_COMMUNICATION_CONTROL", 0x12: "CONFIRMED_PRIVATE_TRANSFER",
	0x13: "CONFIRMED_TEXT_MESSAGE", 0x14: "REINITIALIZE_DEVICE", 0x15: "VT_OPEN",
	0x16: "VT_CLOSE", 0x17: "VT_DATA", 0x1a: "READ_RANGE", 0x1b: "LIFE_SAFETY_OPERATION",
	0x1c: "SUBSCRIBE_COV_PROPERTY", 0x1d: "GET_EVENT_INFORMATION",
}

var unconfirmedNames = map[byte]string{
	0x00: "I_AM", 0x01: "I_HAVE", 0x02: "UNCONFIRMED_COV_NOTIFICATION",
	0x03: "UNCONFIRMED_EVENT_NOTIFICATION", 0x04: "UNCONFIRMED_PRIVATE_TRANSFER",
	0x05: "UNCONFIRMED_TEXT_MESSAGE", 0x06: "TIME_SYNCHRONIZATION", 0x07: "WHO_HAS",
	0x08: "WHO_IS", 0x09: "UTC_TIME_SYNCHRONIZATION", 0x0a: "WRITE_GROUP",
}

var pduTypeNames = []string{"CONFIRMED_REQUEST", "UNCONFIRMED_REQUEST", "SIMPLE_ACK", "COMPLEX_ACK",
	"SEGMENT_ACK", "ERROR", "REJECT", "ABORT"}

var objectTypeNames = map[uint16]string{
	0: "analog-input", 1: "analog-output", 2: "analog-value", 3: "binary-input",
	4: "binary-output", 5: "binary-value", 8: "device", 10: "file",
	13: "multi-state-input", 14: "multi-state-output", 17: "schedule", 19: "multi-state-value",
}

var propertyNames = map[uint32]string{
	8: "all", 12: "application-software-version", 28: "description", 44: "firmware-revision",
	58: "location", 62: "max-apdu-length-accepted", 70: "model-name", 75: "object-identifier",
	76: "object-list", 77: "object-name", 79: "object-type", 85: "present-value",
	98: "protocol-version", 107: "segmentation-supported", 112: "system-status",
	120: "vendor-identifier", 121: "vendor-name", 139: "protocol-revision",
}

// ObjectID is a BACnet object identifier.
type ObjectID struct {
	Type     uint16
	Instance uint32
}

func (o ObjectID) String() string {
	name, ok := objectTypeNames[o.Type]
	if !ok {
		name = strconv.Itoa(int(o.Type))
	}
	return name + ":" + strconv.FormatUint(uint64(o.Instance), 10)
}

func decodeObjectID(b []byte) ObjectID {
	v := binary.BigEndian.Uint32(b)
	return ObjectID{Type: uint16(v >> 22), Instance: v & WildcardInstance}
}

func encodeObjectID(o ObjectID) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(o.Type)<<22|o.Instance&WildcardInstance)
}

// PropertyName returns the standard name of a property id, or its number.
func PropertyName(p uint32) string {
	if n, ok := propertyNames[p]; ok {
		return n
	}
	return strconv.FormatUint(uint64(p), 10)
}

// Address is an NPDU network/MAC address specifier.
type Address struct {
	Net uint16
	MAC []byte
}

// Message is a parsed BACnet/IP datagram. Fields past the point where parsing
// stopped are zero.
type Message struct {
	Function     byte
	NetworkMsg   bool
	NetworkType  byte
	ExpectReply  bool
	Source       *Address // NPDU SNET/SADR when routed
	HasAPDU      bool
	PDUType      byte
	Segmented    bool
	InvokeID     byte
	Service      byte
	Object       *ObjectID
	Property     *uint32
	ArrayIndex   *uint32
	LowLimit     *uint32
	HighLimit    *uint32
	Password     string
	HasPassword  bool
	serviceBytes []byte
}

// FunctionName returns the BVLC function name.
func (m *Message) FunctionName() string {
	if n, ok := bvlcNames[m.Function]; ok {
		return n
	}
	return fmt.Sprintf("0x%02x", m.Function)
}

// Command returns the leaf operation: the APDU service name, a network-layer
// message type, or the BVLC function for BVLL-only datagrams.
func (m *Message) Command() string {
	if m == nil {
		return "UNKNOWN"
	}
	if m.NetworkMsg {
		return fmt.Sprintf("NETWORK_MESSAGE_0x%02x", m.NetworkType)
	}
	if !m.HasAPDU {
		return m.FunctionName()
	}
	var names map[byte]string
	switch m.PDUType {
	case PDUConfirmed:
		names = confirmedNames
	case PDUUnconfirmed:
		names = unconfirmedNames
	default:
		return pduTypeNames[m.PDUType&7]
	}
	if n, ok := names[m.Service]; ok {
		return n
	}
	return fmt.Sprintf("%s_0x%02x", pduTypeNames[m.PDUType], m.Service)
}

// LooksLikeBACnet reports whether data is a BACnet/IP datagram: type 0x81, a
// known BVLC function, a length equal to the datagram, and an NPDU version 1
// for NPDU-carrying functions. Used to reroute from the generic udp handler,
// so it is deliberately strict.
func LooksLikeBACnet(data []byte) bool {
	if len(data) < BVLCHeaderSize || data[0] != bvlcType ||
		int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
		return false
	}
	if _, ok := bvlcNames[data[1]]; !ok {
		return false
	}
	switch data[1] {
	case BVLCOriginalUnicast, BVLCOriginalBroadcast, BVLCDistributeBroadcastToNet:
		return len(data) >= 6 && data[4] == 0x01
	case BVLCForwardedNPDU:
		return len(data) >= 12 && data[10] == 0x01
	}
	return true
}

// Parse decodes a datagram. The returned Message is non-nil whenever the BVLC
// header was readable, even when a later layer fails to parse.
func Parse(data []byte) (*Message, error) {
	if len(data) < BVLCHeaderSize {
		return nil, ErrShort
	}
	if data[0] != bvlcType {
		return nil, ErrMagic
	}
	m := &Message{Function: data[1]}
	if int(binary.BigEndian.Uint16(data[2:4])) != len(data) {
		return m, ErrLength
	}
	body := data[BVLCHeaderSize:]
	switch m.Function {
	case BVLCOriginalUnicast, BVLCOriginalBroadcast, BVLCDistributeBroadcastToNet:
	case BVLCForwardedNPDU:
		if len(body) < 6 {
			return m, ErrNPDU
		}
		body = body[6:] // original source B/IP address
	default:
		return m, nil // BVLL-only message
	}
	apdu, err := m.parseNPDU(body)
	if err != nil || apdu == nil {
		return m, err
	}
	m.HasAPDU = true
	return m, m.parseAPDU(apdu)
}

func (m *Message) parseNPDU(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x01 {
		return nil, ErrNPDU
	}
	ctl := b[1]
	m.ExpectReply = ctl&0x04 != 0
	b = b[2:]
	hasDest := ctl&0x20 != 0
	if hasDest {
		if len(b) < 3 || len(b) < 3+int(b[2]) {
			return nil, ErrNPDU
		}
		b = b[3+int(b[2]):]
	}
	if ctl&0x08 != 0 {
		if len(b) < 3 || b[2] == 0 || len(b) < 3+int(b[2]) {
			return nil, ErrNPDU
		}
		m.Source = &Address{Net: binary.BigEndian.Uint16(b), MAC: append([]byte(nil), b[3:3+int(b[2])]...)}
		b = b[3+int(b[2]):]
	}
	if hasDest {
		if len(b) < 1 {
			return nil, ErrNPDU
		}
		b = b[1:] // hop count
	}
	if ctl&0x80 != 0 {
		if len(b) < 1 {
			return nil, ErrNPDU
		}
		m.NetworkMsg, m.NetworkType = true, b[0]
		return nil, nil
	}
	if len(b) == 0 {
		return nil, ErrAPDU
	}
	return b, nil
}

func (m *Message) parseAPDU(b []byte) error {
	m.PDUType = b[0] >> 4
	switch m.PDUType {
	case PDUConfirmed:
		if len(b) < 4 {
			return ErrAPDU
		}
		m.Segmented = b[0]&0x08 != 0
		m.InvokeID = b[2]
		hdr := 3
		if m.Segmented {
			hdr += 2
		}
		if len(b) < hdr+1 {
			return ErrAPDU
		}
		m.Service = b[hdr]
		m.serviceBytes = b[hdr+1:]
	case PDUUnconfirmed:
		if len(b) < 2 {
			return ErrAPDU
		}
		m.Service = b[1]
		m.serviceBytes = b[2:]
	default:
		return nil
	}
	if m.Segmented {
		return nil
	}
	return m.parseService()
}

// tag is one decoded BACnet tag.
type tag struct {
	number  byte
	context bool
	opening bool
	closing bool
	value   []byte
}

func readTag(b []byte) (tag, []byte, error) {
	if len(b) < 1 {
		return tag{}, nil, ErrAPDU
	}
	t := tag{number: b[0] >> 4, context: b[0]&0x08 != 0}
	lvt := int(b[0] & 0x07)
	b = b[1:]
	if t.number == 0x0f {
		if len(b) < 1 {
			return tag{}, nil, ErrAPDU
		}
		t.number, b = b[0], b[1:]
	}
	if t.context && lvt == 6 {
		t.opening = true
		return t, b, nil
	}
	if t.context && lvt == 7 {
		t.closing = true
		return t, b, nil
	}
	if !t.context && t.number == 1 { // application boolean carries its value in LVT
		return t, b, nil
	}
	if lvt == 5 {
		if len(b) < 1 {
			return tag{}, nil, ErrAPDU
		}
		lvt, b = int(b[0]), b[1:]
		switch lvt {
		case 254:
			if len(b) < 2 {
				return tag{}, nil, ErrAPDU
			}
			lvt, b = int(binary.BigEndian.Uint16(b)), b[2:]
		case 255:
			return tag{}, nil, ErrAPDU // 32-bit lengths never fit a datagram
		}
	}
	if len(b) < lvt {
		return tag{}, nil, ErrAPDU
	}
	t.value = b[:lvt]
	return t, b[lvt:], nil
}

func decodeUnsigned(v []byte) (uint32, bool) {
	if len(v) == 0 || len(v) > 4 {
		return 0, false
	}
	var n uint32
	for _, c := range v {
		n = n<<8 | uint32(c)
	}
	return n, true
}

// decodeString returns a CharacterString value (first byte is the charset).
func decodeString(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	return string(v[1:])
}

func (m *Message) parseService() error {
	b := m.serviceBytes
	switch {
	case m.PDUType == PDUUnconfirmed && m.Service == ServiceWhoIs:
		for len(b) > 0 {
			t, rest, err := readTag(b)
			if err != nil || !t.context {
				return ErrAPDU
			}
			n, ok := decodeUnsigned(t.value)
			if !ok {
				return ErrAPDU
			}
			switch t.number {
			case 0:
				m.LowLimit = &n
			case 1:
				m.HighLimit = &n
			}
			b = rest
		}
		if (m.LowLimit == nil) != (m.HighLimit == nil) {
			return ErrAPDU
		}
	case m.PDUType == PDUConfirmed && (m.Service == ServiceReadProperty || m.Service == 0x0f): // ReadProperty / WriteProperty
		t, rest, err := readTag(b)
		if err != nil || !t.context || t.number != 0 || len(t.value) != 4 {
			return ErrAPDU
		}
		o := decodeObjectID(t.value)
		m.Object = &o
		t, rest, err = readTag(rest)
		if err != nil || !t.context || t.number != 1 {
			return ErrAPDU
		}
		p, ok := decodeUnsigned(t.value)
		if !ok {
			return ErrAPDU
		}
		m.Property = &p
		if len(rest) > 0 {
			if t, _, err := readTag(rest); err == nil && t.context && t.number == 2 {
				if idx, ok := decodeUnsigned(t.value); ok {
					m.ArrayIndex = &idx
				}
			}
		}
	case m.PDUType == PDUConfirmed && (m.Service == 0x11 || m.Service == 0x14): // DCC / ReinitializeDevice
		pwTag := byte(1)
		if m.Service == 0x11 {
			pwTag = 2
		}
		for len(b) > 0 {
			t, rest, err := readTag(b)
			if err != nil {
				return ErrAPDU
			}
			if t.context && t.number == pwTag && !t.opening && !t.closing {
				m.Password, m.HasPassword = decodeString(t.value), true
			}
			b = rest
		}
	}
	return nil
}

// Device is the fake device identity.
type Device struct {
	Instance    uint32
	Name        string
	VendorID    uint32
	VendorName  string
	Model       string
	Firmware    string
	AppSoftware string
	Location    string
	Description string
}

type persona struct {
	vendorID              uint32
	vendor, model, fw, sw string
}

// Plausible building-automation controllers; picked per sensor.
var personas = []persona{
	{5, "Johnson Controls, Inc.", "NAE5510-2", "9.0.0.4", "9.0.0.4"},
	{8, "Delta Controls", "eBCON", "V3.40", "V3.40 B571234"},
	{24, "Automated Logic Corporation", "LGR250", "drv_lgr_6-04-062", "6.04"},
	{17, "Honeywell Inc.", "Spyder BACnet", "3.2.1", "3.2.1"},
}

var locations = []string{"Mechanical Room", "Boiler Room", "Roof", "Basement", "Plant Room 2"}

var units = []string{"AHU", "RTU", "VAV", "CHLR", "BLR", "FCU"}

// DeviceFor derives a stable identity from seed (the sensor address).
func DeviceFor(seed []byte) Device {
	sum := sha256.Sum256(append([]byte("bacnet:"), seed...))
	p := personas[int(sum[0])%len(personas)]
	inst := 1000 + binary.BigEndian.Uint32(sum[1:5])%399000
	unit := fmt.Sprintf("%s-%d", units[int(sum[5])%len(units)], 1+int(sum[6])%12)
	return Device{
		Instance:    inst,
		Name:        unit,
		VendorID:    p.vendorID,
		VendorName:  p.vendor,
		Model:       p.model,
		Firmware:    p.fw,
		AppSoftware: p.sw,
		Location:    locations[int(sum[7])%len(locations)],
		Description: unit + " Controller",
	}
}

// ID returns the device object identifier.
func (d Device) ID() ObjectID { return ObjectID{Type: ObjectDevice, Instance: d.Instance} }

func appUnsigned(n uint32) []byte {
	v := binary.BigEndian.AppendUint32(nil, n)
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	return append([]byte{0x20 | byte(len(v))}, v...)
}

func appEnumerated(n byte) []byte { return []byte{0x91, n} }

func appString(s string) []byte {
	if len(s) > 200 {
		s = s[:200]
	}
	l := len(s) + 1 // charset byte (0 = UTF-8)
	var b []byte
	if l <= 4 {
		b = []byte{0x70 | byte(l)}
	} else {
		b = []byte{0x75, byte(l)}
	}
	b = append(b, 0x00)
	return append(b, s...)
}

func contextUnsigned(num byte, n uint32) []byte {
	b := appUnsigned(n)
	b[0] = num<<4 | 0x08 | b[0]&0x07
	return b
}

// propertyValue returns the application-tagged value of a device property.
func (d Device) propertyValue(p uint32) ([]byte, bool) {
	switch p {
	case 75:
		return append([]byte{0xc4}, encodeObjectID(d.ID())...), true
	case 77:
		return appString(d.Name), true
	case 79:
		return appEnumerated(byte(ObjectDevice)), true
	case 28:
		return appString(d.Description), true
	case 58:
		return appString(d.Location), true
	case 70:
		return appString(d.Model), true
	case 121:
		return appString(d.VendorName), true
	case 120:
		return appUnsigned(d.VendorID), true
	case 44:
		return appString(d.Firmware), true
	case 12:
		return appString(d.AppSoftware), true
	case 112:
		return appEnumerated(0), true // operational
	case 98:
		return appUnsigned(1), true
	case 139:
		return appUnsigned(14), true
	case 62:
		return appUnsigned(maxAPDUAccepted), true
	case 107:
		return appEnumerated(3), true // no-segmentation
	}
	return nil, false
}

// npdu returns a reply NPDU routed back to src when the request was routed.
func npdu(src *Address) []byte {
	if src == nil {
		return []byte{0x01, 0x00}
	}
	b := []byte{0x01, 0x20}
	b = binary.BigEndian.AppendUint16(b, src.Net)
	b = append(b, byte(len(src.MAC)))
	b = append(b, src.MAC...)
	return append(b, 0xff) // hop count
}

func bvlc(function byte, body []byte) []byte {
	b := []byte{bvlcType, function, 0, 0}
	b = append(b, body...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func unicast(src *Address, apdu []byte) []byte {
	return bvlc(BVLCOriginalUnicast, append(npdu(src), apdu...))
}

// BuildIAm returns an I-Am for d.
func BuildIAm(d Device, src *Address) []byte {
	apdu := []byte{PDUUnconfirmed << 4, serviceIAm, 0xc4}
	apdu = append(apdu, encodeObjectID(d.ID())...)
	apdu = append(apdu, appUnsigned(maxAPDUAccepted)...)
	apdu = append(apdu, appEnumerated(3)...)
	apdu = append(apdu, appUnsigned(d.VendorID)...)
	return unicast(src, apdu)
}

// WhoIsMatches reports whether d answers the Who-Is in m.
func WhoIsMatches(m *Message, d Device) bool {
	if m.LowLimit == nil || m.HighLimit == nil {
		return true
	}
	return d.Instance >= *m.LowLimit && d.Instance <= *m.HighLimit
}

// BuildError returns an Error-PDU for the confirmed request m.
func BuildError(m *Message, class, code byte) []byte {
	return unicast(m.Source, []byte{pduError << 4, m.InvokeID, m.Service, 0x91, class, 0x91, code})
}

// BuildReject returns a Reject-PDU (unrecognized-service) for m.
func BuildReject(m *Message) []byte {
	return unicast(m.Source, []byte{pduReject << 4, m.InvokeID, rejectUnrecognizedService})
}

// Reply is a built response and its decoded `status`.
type Reply struct {
	Payload []byte
	Status  string
}

// ErrorStatus formats an Error-PDU status.
func ErrorStatus(class, code byte) string {
	return fmt.Sprintf("ERROR:%s/%s", errClassNames[class], errCodeNames[code])
}

var errClassNames = map[byte]string{ErrClassObject: "object", ErrClassProperty: "property",
	ErrClassSecurity: "security", ErrClassServices: "services"}

var errCodeNames = map[byte]string{
	ErrCodeUnknownObject: "unknown-object", ErrCodeUnknownProperty: "unknown-property",
	ErrCodeNotAnArray: "property-is-not-an-array", ErrCodeWriteAccessDenied: "write-access-denied",
	ErrCodePasswordFailure: "password-failure", ErrCodeServiceRequestDeny: "service-request-denied",
}

func errorReply(m *Message, class, code byte) *Reply {
	return &Reply{Payload: BuildError(m, class, code), Status: ErrorStatus(class, code)}
}

// Respond builds the device's reply to m, or nil when a real device stays
// silent (unconfirmed services other than a matching Who-Is, ACKs, segmented
// requests, network-layer messages).
func Respond(m *Message, d Device) *Reply {
	if m == nil {
		return nil
	}
	if !m.HasAPDU {
		if m.NetworkMsg {
			return nil
		}
		// BVLL-only requests: answer with the NAK a non-BBMD device sends.
		var code uint16
		switch m.Function {
		case BVLCReadBDT:
			code = 0x0020
		case BVLCRegisterForeignDevice:
			code = 0x0030
		case BVLCReadFDT:
			code = 0x0040
		default:
			return nil
		}
		return &Reply{Payload: bvlc(BVLCResult, binary.BigEndian.AppendUint16(nil, code)), Status: fmt.Sprintf("BVLC_RESULT_NAK_0x%04x", code)}
	}
	switch m.PDUType {
	case PDUUnconfirmed:
		if m.Service == ServiceWhoIs && WhoIsMatches(m, d) {
			return &Reply{Payload: BuildIAm(d, m.Source), Status: "I_AM"}
		}
		return nil
	case PDUConfirmed:
	default:
		return nil
	}
	if m.Segmented {
		return nil
	}
	switch m.Service {
	case ServiceReadProperty:
		if m.Object == nil || m.Property == nil {
			return &Reply{Payload: BuildReject(m), Status: "REJECT"}
		}
		if m.Object.Type != ObjectDevice || (m.Object.Instance != WildcardInstance && m.Object.Instance != d.Instance) {
			return errorReply(m, ErrClassObject, ErrCodeUnknownObject)
		}
		val, ok := d.propertyValue(*m.Property)
		if !ok {
			return errorReply(m, ErrClassProperty, ErrCodeUnknownProperty)
		}
		if m.ArrayIndex != nil {
			return errorReply(m, ErrClassProperty, ErrCodeNotAnArray)
		}
		apdu := []byte{pduComplexACK << 4, m.InvokeID, ServiceReadProperty, 0x0c}
		apdu = append(apdu, encodeObjectID(d.ID())...)
		apdu = append(apdu, contextUnsigned(1, *m.Property)...)
		apdu = append(apdu, 0x3e)
		apdu = append(apdu, val...)
		apdu = append(apdu, 0x3f)
		return &Reply{Payload: unicast(m.Source, apdu), Status: "READ_PROPERTY_ACK"}
	case 0x0f, 0x10: // WriteProperty, WritePropertyMultiple
		return errorReply(m, ErrClassProperty, ErrCodeWriteAccessDenied)
	case 0x11, 0x14: // DeviceCommunicationControl, ReinitializeDevice
		return errorReply(m, ErrClassSecurity, ErrCodePasswordFailure)
	}
	return &Reply{Payload: BuildReject(m), Status: "REJECT"}
}
