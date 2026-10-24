// Package ipp parses and builds the Internet Printing Protocol (RFC 8010
// encoding, RFC 8011 semantics): binary messages carried in HTTP POST bodies
// with Content-Type application/ipp, usually on tcp/631 (CUPS). A request is
//
//	version-number (2) | operation-id (2) | request-id (4) |
//	attribute groups ... | end-of-attributes-tag (0x03) | document data
//
// Each attribute is value-tag (1) | name-length (2) | name | value-length (2) |
// value; an empty name adds another value to the previous attribute.
// Operations seen from scanners and the CUPS persona were cross-checked
// against ipphoney (gitlab.com/bontchev/ipphoney); no code is shared with it.
package ipp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Delimiter (group) tags.
const (
	TagOperation   byte = 0x01
	TagJob         byte = 0x02
	TagEnd         byte = 0x03
	TagPrinter     byte = 0x04
	TagUnsupported byte = 0x05
)

// Value tags.
const (
	TagUnsupportedValue byte = 0x10
	TagUnknown          byte = 0x12
	TagNoValue          byte = 0x13
	TagInteger          byte = 0x21
	TagBoolean          byte = 0x22
	TagEnum             byte = 0x23
	TagOctetString      byte = 0x30
	TagDateTime         byte = 0x31
	TagResolution       byte = 0x32
	TagRange            byte = 0x33
	TagBegCollection    byte = 0x34
	TagTextWithLang     byte = 0x35
	TagNameWithLang     byte = 0x36
	TagEndCollection    byte = 0x37
	TagText             byte = 0x41
	TagName             byte = 0x42
	TagKeyword          byte = 0x44
	TagURI              byte = 0x45
	TagURIScheme        byte = 0x46
	TagCharset          byte = 0x47
	TagLanguage         byte = 0x48
	TagMimeType         byte = 0x49
	TagMemberName       byte = 0x4A
)

// Operation IDs (RFC 8011 §5.4.15, PWG 5100.x, CUPS 0x4000 range).
const (
	OpPrintJob             uint16 = 0x0002
	OpPrintURI             uint16 = 0x0003
	OpValidateJob          uint16 = 0x0004
	OpCreateJob            uint16 = 0x0005
	OpSendDocument         uint16 = 0x0006
	OpSendURI              uint16 = 0x0007
	OpCancelJob            uint16 = 0x0008
	OpGetJobAttributes     uint16 = 0x0009
	OpGetJobs              uint16 = 0x000A
	OpGetPrinterAttributes uint16 = 0x000B
	OpHoldJob              uint16 = 0x000C
	OpReleaseJob           uint16 = 0x000D
	OpRestartJob           uint16 = 0x000E
	OpPausePrinter         uint16 = 0x0010
	OpResumePrinter        uint16 = 0x0011
	OpPurgeJobs            uint16 = 0x0012
	OpSetPrinterAttributes uint16 = 0x0013
	OpSetJobAttributes     uint16 = 0x0014
	OpEnablePrinter        uint16 = 0x0022
	OpDisablePrinter       uint16 = 0x0023
	OpCancelJobs           uint16 = 0x0038
	OpCancelMyJobs         uint16 = 0x0039
	OpCloseJob             uint16 = 0x003B
	OpIdentifyPrinter      uint16 = 0x003C
	OpValidateDocument     uint16 = 0x003D
	OpCUPSGetDefault       uint16 = 0x4001
	OpCUPSGetPrinters      uint16 = 0x4002
	OpCUPSAddModifyPrinter uint16 = 0x4003
	OpCUPSDeletePrinter    uint16 = 0x4004
	OpCUPSGetClasses       uint16 = 0x4005
	OpCUPSAddModifyClass   uint16 = 0x4006
	OpCUPSDeleteClass      uint16 = 0x4007
	OpCUPSAcceptJobs       uint16 = 0x4008
	OpCUPSRejectJobs       uint16 = 0x4009
	OpCUPSSetDefault       uint16 = 0x400A
	OpCUPSGetDevices       uint16 = 0x400B
	OpCUPSGetPPDs          uint16 = 0x400C
	OpCUPSMoveJob          uint16 = 0x400D
	OpCUPSAuthenticateJob  uint16 = 0x400E
	OpCUPSGetPPD           uint16 = 0x400F
)

// Status codes (RFC 8011 §B).
const (
	StatusOK                    uint16 = 0x0000
	StatusBadRequest            uint16 = 0x0400
	StatusNotPossible           uint16 = 0x0404
	StatusNotFound              uint16 = 0x0406
	StatusOperationNotSupported uint16 = 0x0501
	StatusVersionNotSupported   uint16 = 0x0503
)

const (
	// maxAttributes bounds the attributes kept from one request.
	maxAttributes = 256
	// maxValues bounds the values kept per attribute.
	maxValues = 64
	// maxDepth bounds collection nesting.
	maxDepth = 16
)

var ErrMalformed = errors.New("malformed IPP message")

var operationNames = map[uint16]string{
	OpPrintJob:             "Print-Job",
	OpPrintURI:             "Print-URI",
	OpValidateJob:          "Validate-Job",
	OpCreateJob:            "Create-Job",
	OpSendDocument:         "Send-Document",
	OpSendURI:              "Send-URI",
	OpCancelJob:            "Cancel-Job",
	OpGetJobAttributes:     "Get-Job-Attributes",
	OpGetJobs:              "Get-Jobs",
	OpGetPrinterAttributes: "Get-Printer-Attributes",
	OpHoldJob:              "Hold-Job",
	OpReleaseJob:           "Release-Job",
	OpRestartJob:           "Restart-Job",
	OpPausePrinter:         "Pause-Printer",
	OpResumePrinter:        "Resume-Printer",
	OpPurgeJobs:            "Purge-Jobs",
	OpSetPrinterAttributes: "Set-Printer-Attributes",
	OpSetJobAttributes:     "Set-Job-Attributes",
	0x0015:                 "Get-Printer-Supported-Values",
	0x0016:                 "Create-Printer-Subscriptions",
	0x0017:                 "Create-Job-Subscriptions",
	0x0018:                 "Get-Subscription-Attributes",
	0x0019:                 "Get-Subscriptions",
	0x001A:                 "Renew-Subscription",
	0x001B:                 "Cancel-Subscription",
	0x001C:                 "Get-Notifications",
	OpEnablePrinter:        "Enable-Printer",
	OpDisablePrinter:       "Disable-Printer",
	0x0024:                 "Pause-Printer-After-Current-Job",
	0x0025:                 "Hold-New-Jobs",
	0x0026:                 "Release-Held-New-Jobs",
	0x0027:                 "Deactivate-Printer",
	0x0028:                 "Activate-Printer",
	0x0029:                 "Restart-Printer",
	0x002A:                 "Shutdown-Printer",
	0x002B:                 "Startup-Printer",
	0x002D:                 "Cancel-Current-Job",
	0x002F:                 "Resume-Job",
	0x0033:                 "Cancel-Document",
	0x0034:                 "Get-Document-Attributes",
	0x0035:                 "Get-Documents",
	OpCancelJobs:           "Cancel-Jobs",
	OpCancelMyJobs:         "Cancel-My-Jobs",
	0x003A:                 "Resubmit-Job",
	OpCloseJob:             "Close-Job",
	OpIdentifyPrinter:      "Identify-Printer",
	OpValidateDocument:     "Validate-Document",
	OpCUPSGetDefault:       "CUPS-Get-Default",
	OpCUPSGetPrinters:      "CUPS-Get-Printers",
	OpCUPSAddModifyPrinter: "CUPS-Add-Modify-Printer",
	OpCUPSDeletePrinter:    "CUPS-Delete-Printer",
	OpCUPSGetClasses:       "CUPS-Get-Classes",
	OpCUPSAddModifyClass:   "CUPS-Add-Modify-Class",
	OpCUPSDeleteClass:      "CUPS-Delete-Class",
	OpCUPSAcceptJobs:       "CUPS-Accept-Jobs",
	OpCUPSRejectJobs:       "CUPS-Reject-Jobs",
	OpCUPSSetDefault:       "CUPS-Set-Default",
	OpCUPSGetDevices:       "CUPS-Get-Devices",
	OpCUPSGetPPDs:          "CUPS-Get-PPDs",
	OpCUPSMoveJob:          "CUPS-Move-Job",
	OpCUPSAuthenticateJob:  "CUPS-Authenticate-Job",
	OpCUPSGetPPD:           "CUPS-Get-PPD",
}

var statusNames = map[uint16]string{
	StatusOK:                    "successful-ok",
	StatusBadRequest:            "client-error-bad-request",
	StatusNotPossible:           "client-error-not-possible",
	StatusNotFound:              "client-error-not-found",
	StatusOperationNotSupported: "server-error-operation-not-supported",
	StatusVersionNotSupported:   "server-error-version-not-supported",
}

var groupNames = map[byte]string{
	TagOperation:   "operation",
	TagJob:         "job",
	TagPrinter:     "printer",
	TagUnsupported: "unsupported",
	0x06:           "subscription",
	0x07:           "event-notification",
	0x08:           "resource",
	0x09:           "document",
	0x0A:           "system",
}

var tagNames = map[byte]string{
	TagUnsupportedValue: "unsupported",
	TagUnknown:          "unknown",
	TagNoValue:          "no-value",
	0x15:                "not-settable",
	0x16:                "delete-attribute",
	0x17:                "admin-define",
	TagInteger:          "integer",
	TagBoolean:          "boolean",
	TagEnum:             "enum",
	TagOctetString:      "octetString",
	TagDateTime:         "dateTime",
	TagResolution:       "resolution",
	TagRange:            "rangeOfInteger",
	TagBegCollection:    "collection",
	TagTextWithLang:     "textWithLanguage",
	TagNameWithLang:     "nameWithLanguage",
	TagText:             "textWithoutLanguage",
	TagName:             "nameWithoutLanguage",
	TagKeyword:          "keyword",
	TagURI:              "uri",
	TagURIScheme:        "uriScheme",
	TagCharset:          "charset",
	TagLanguage:         "naturalLanguage",
	TagMimeType:         "mimeMediaType",
}

// OperationName returns the operation's name, or its hex ID when unknown.
func OperationName(op uint16) string {
	if n, ok := operationNames[op]; ok {
		return n
	}
	return fmt.Sprintf("0x%04X", op)
}

// StatusName returns the status code's keyword, or its hex value when unknown.
func StatusName(code uint16) string {
	if n, ok := statusNames[code]; ok {
		return n
	}
	return fmt.Sprintf("0x%04X", code)
}

func tagName(tag byte) string {
	if n, ok := tagNames[tag]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", tag)
}

func groupName(tag byte) string {
	if n, ok := groupNames[tag]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", tag)
}

// Attribute is one decoded request attribute. Collection members are
// flattened to dotted names ("media-col.media-size.x-dimension").
type Attribute struct {
	Group  string   `json:"group"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Values []string `json:"values,omitempty"`
}

// Message is a decoded IPP request.
type Message struct {
	Major, Minor byte
	Operation    uint16
	RequestID    uint32
	Attributes   []Attribute
	// Data is the document (or PPD) following the end-of-attributes tag.
	Data []byte
	// Dropped is set when attributes or values past the caps were skipped.
	Dropped bool
}

// Version returns "major.minor".
func (m Message) Version() string {
	return fmt.Sprintf("%d.%d", m.Major, m.Minor)
}

// Get returns the first value of the named attribute in group ("" = any).
func (m Message) Get(group, name string) string {
	for _, a := range m.Attributes {
		if a.Name == name && (group == "" || a.Group == group) && len(a.Values) > 0 {
			return a.Values[0]
		}
	}
	return ""
}

// Values returns every value of the named attribute in group ("" = any).
func (m Message) Values(group, name string) []string {
	for _, a := range m.Attributes {
		if a.Name == name && (group == "" || a.Group == group) {
			return a.Values
		}
	}
	return nil
}

// Parse decodes an IPP request body. A partial message is returned with
// ErrMalformed when the attribute stream is cut or invalid.
func Parse(b []byte) (Message, error) {
	var m Message
	if len(b) < 8 {
		return m, fmt.Errorf("%w: %d byte header", ErrMalformed, len(b))
	}
	m.Major, m.Minor = b[0], b[1]
	m.Operation = binary.BigEndian.Uint16(b[2:4])
	m.RequestID = binary.BigEndian.Uint32(b[4:8])

	p := &parser{b: b, i: 8, m: &m}
	if err := p.attributes(); err != nil {
		return m, err
	}
	m.Data = b[p.i:]
	return m, nil
}

type parser struct {
	b     []byte
	i     int
	m     *Message
	group string
	// stack holds the open collection names; member is the pending
	// memberAttrName inside the innermost one.
	stack  []string
	member string
	// prev is the full name of the latest attribute or collection, reopened
	// by an unnamed begCollection (another value of a 1setOf collection).
	prev string
	last int // index of the attribute additional values go to; -1 when dropped
}

func (p *parser) u16() (int, error) {
	if p.i+2 > len(p.b) {
		return 0, fmt.Errorf("%w: truncated at offset %d", ErrMalformed, p.i)
	}
	v := int(binary.BigEndian.Uint16(p.b[p.i:]))
	p.i += 2
	return v, nil
}

func (p *parser) bytes(n int) ([]byte, error) {
	if p.i+n > len(p.b) {
		return nil, fmt.Errorf("%w: truncated at offset %d", ErrMalformed, p.i)
	}
	v := p.b[p.i : p.i+n]
	p.i += n
	return v, nil
}

func (p *parser) attributes() error {
	p.last = -1
	for {
		if p.i >= len(p.b) {
			return fmt.Errorf("%w: missing end-of-attributes-tag", ErrMalformed)
		}
		tag := p.b[p.i]
		p.i++
		if tag == TagEnd {
			if len(p.stack) > 0 {
				return fmt.Errorf("%w: unterminated collection", ErrMalformed)
			}
			return nil
		}
		if tag < 0x10 {
			if len(p.stack) > 0 {
				return fmt.Errorf("%w: group tag inside collection", ErrMalformed)
			}
			p.group = groupName(tag)
			p.last = -1
			continue
		}
		if p.group == "" {
			return fmt.Errorf("%w: attribute before group tag", ErrMalformed)
		}
		nlen, err := p.u16()
		if err != nil {
			return err
		}
		name, err := p.bytes(nlen)
		if err != nil {
			return err
		}
		vlen, err := p.u16()
		if err != nil {
			return err
		}
		value, err := p.bytes(vlen)
		if err != nil {
			return err
		}
		if err := p.attribute(tag, string(name), value); err != nil {
			return err
		}
	}
}

func (p *parser) attribute(tag byte, name string, value []byte) error {
	switch tag {
	case TagEndCollection:
		if len(p.stack) == 0 {
			return fmt.Errorf("%w: endCollection outside collection", ErrMalformed)
		}
		p.prev = strings.Join(p.stack, ".")
		p.stack = p.stack[:len(p.stack)-1]
		p.member = ""
		return nil
	case TagMemberName:
		if len(p.stack) == 0 {
			return fmt.Errorf("%w: memberAttrName outside collection", ErrMalformed)
		}
		p.member = string(value)
		return nil
	}

	// resolve the full name: a named top-level attribute, a collection
	// member, or (empty name) another value of the previous attribute
	full := ""
	switch {
	case name != "":
		if len(p.stack) > 0 {
			return fmt.Errorf("%w: named attribute inside collection", ErrMalformed)
		}
		full = name
	case p.member != "":
		full = strings.Join(append(append([]string(nil), p.stack...), p.member), ".")
		p.member = ""
	}

	if tag == TagBegCollection {
		if len(p.stack) >= maxDepth {
			return fmt.Errorf("%w: collection nesting too deep", ErrMalformed)
		}
		open := full
		if open == "" {
			// another value of the collection that just closed
			open = p.prev
		} else if len(p.stack) == 0 {
			p.add(full, tag, nil)
		}
		// members are joined to the stack, so keep only the last segment
		p.stack = append(p.stack, open[strings.LastIndex(open, ".")+1:])
		p.prev = open
		return nil
	}

	v, err := formatValue(tag, value)
	if err != nil {
		return err
	}
	if full == "" {
		if p.last < 0 {
			// nothing to attach to (first in group, or past the cap)
			return nil
		}
		a := &p.m.Attributes[p.last]
		if len(a.Values) >= maxValues {
			p.m.Dropped = true
			return nil
		}
		a.Values = append(a.Values, v)
		return nil
	}
	p.add(full, tag, &v)
	p.prev = full
	return nil
}

func (p *parser) add(name string, tag byte, v *string) {
	if len(p.m.Attributes) >= maxAttributes {
		p.m.Dropped = true
		p.last = -1
		return
	}
	a := Attribute{Group: p.group, Name: name, Type: tagName(tag)}
	if v != nil {
		a.Values = []string{*v}
	}
	p.m.Attributes = append(p.m.Attributes, a)
	p.last = len(p.m.Attributes) - 1
}

func formatValue(tag byte, v []byte) (string, error) {
	fixed := func(n int) error {
		if len(v) != n {
			return fmt.Errorf("%w: %s value of %d bytes", ErrMalformed, tagName(tag), len(v))
		}
		return nil
	}
	switch {
	case tag >= 0x10 && tag < 0x20:
		// out-of-band values carry no data
		return tagName(tag), nil
	case tag == TagInteger || tag == TagEnum:
		if err := fixed(4); err != nil {
			return "", err
		}
		return strconv.Itoa(int(int32(binary.BigEndian.Uint32(v)))), nil
	case tag == TagBoolean:
		if err := fixed(1); err != nil {
			return "", err
		}
		return strconv.FormatBool(v[0] != 0), nil
	case tag == TagRange:
		if err := fixed(8); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d-%d", int32(binary.BigEndian.Uint32(v)), int32(binary.BigEndian.Uint32(v[4:]))), nil
	case tag == TagResolution:
		if err := fixed(9); err != nil {
			return "", err
		}
		units := "dpi"
		if v[8] == 4 {
			units = "dpcm"
		}
		return fmt.Sprintf("%dx%d%s", int32(binary.BigEndian.Uint32(v)), int32(binary.BigEndian.Uint32(v[4:])), units), nil
	case tag == TagDateTime:
		if err := fixed(11); err != nil {
			return "", err
		}
		return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%d%c%02d:%02d",
			binary.BigEndian.Uint16(v), v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10]), nil
	case tag == TagTextWithLang || tag == TagNameWithLang:
		// language length, language, text length, text
		if len(v) < 4 {
			return "", fmt.Errorf("%w: short %s value", ErrMalformed, tagName(tag))
		}
		ll := int(binary.BigEndian.Uint16(v))
		if 2+ll+2 > len(v) {
			return "", fmt.Errorf("%w: short %s value", ErrMalformed, tagName(tag))
		}
		tl := int(binary.BigEndian.Uint16(v[2+ll:]))
		if 4+ll+tl != len(v) {
			return "", fmt.Errorf("%w: bad %s lengths", ErrMalformed, tagName(tag))
		}
		return printable(v[4+ll:]), nil
	default:
		// text, name, keyword, uri, charset, mimeMediaType, octetString, ...
		return printable(v), nil
	}
}

// printable keeps UTF-8 as is and hex-encodes binary values.
func printable(v []byte) string {
	if utf8.Valid(v) {
		return string(v)
	}
	return "hex:" + hex.EncodeToString(v)
}

// Value is one encoded attribute value.
type Value struct {
	Tag  byte
	Data []byte
}

// Attr is an attribute to encode; every value after the first is written
// as an additional value (empty name).
type Attr struct {
	Name   string
	Values []Value
}

// Group is an attribute group to encode.
type Group struct {
	Tag   byte
	Attrs []Attr
}

// Response is an IPP response message.
type Response struct {
	Major, Minor byte
	Status       uint16
	RequestID    uint32
	Groups       []Group
}

// Encode serializes the response.
func (r Response) Encode() []byte {
	var b bytes.Buffer
	b.Write([]byte{r.Major, r.Minor})
	_ = binary.Write(&b, binary.BigEndian, r.Status)
	_ = binary.Write(&b, binary.BigEndian, r.RequestID)
	for _, g := range r.Groups {
		b.WriteByte(g.Tag)
		for _, a := range g.Attrs {
			for i, v := range a.Values {
				b.WriteByte(v.Tag)
				name := ""
				if i == 0 {
					name = a.Name
				}
				_ = binary.Write(&b, binary.BigEndian, uint16(len(name)))
				b.WriteString(name)
				_ = binary.Write(&b, binary.BigEndian, uint16(len(v.Data)))
				b.Write(v.Data)
			}
		}
	}
	b.WriteByte(TagEnd)
	return b.Bytes()
}

func strAttr(tag byte, name string, vals []string) Attr {
	a := Attr{Name: name}
	for _, v := range vals {
		a.Values = append(a.Values, Value{Tag: tag, Data: []byte(v)})
	}
	return a
}

func Keyword(name string, vals ...string) Attr  { return strAttr(TagKeyword, name, vals) }
func Text(name string, vals ...string) Attr     { return strAttr(TagText, name, vals) }
func Name(name string, vals ...string) Attr     { return strAttr(TagName, name, vals) }
func URI(name string, vals ...string) Attr      { return strAttr(TagURI, name, vals) }
func Charset(name string, vals ...string) Attr  { return strAttr(TagCharset, name, vals) }
func Language(name string, vals ...string) Attr { return strAttr(TagLanguage, name, vals) }
func MimeType(name string, vals ...string) Attr { return strAttr(TagMimeType, name, vals) }

func intAttr(tag byte, name string, vals []int32) Attr {
	a := Attr{Name: name}
	for _, v := range vals {
		a.Values = append(a.Values, Value{Tag: tag, Data: binary.BigEndian.AppendUint32(nil, uint32(v))})
	}
	return a
}

func Integer(name string, vals ...int32) Attr { return intAttr(TagInteger, name, vals) }
func Enum(name string, vals ...int32) Attr    { return intAttr(TagEnum, name, vals) }

func Boolean(name string, v bool) Attr {
	b := byte(0)
	if v {
		b = 1
	}
	return Attr{Name: name, Values: []Value{{Tag: TagBoolean, Data: []byte{b}}}}
}

func Range(name string, lo, hi int32) Attr {
	d := binary.BigEndian.AppendUint32(nil, uint32(lo))
	d = binary.BigEndian.AppendUint32(d, uint32(hi))
	return Attr{Name: name, Values: []Value{{Tag: TagRange, Data: d}}}
}

// Resolution encodes x by y dots per inch.
func Resolution(name string, x, y int32) Attr {
	d := binary.BigEndian.AppendUint32(nil, uint32(x))
	d = binary.BigEndian.AppendUint32(d, uint32(y))
	d = append(d, 3)
	return Attr{Name: name, Values: []Value{{Tag: TagResolution, Data: d}}}
}

// DateTime encodes t in UTC (RFC 2579 DateAndTime).
func DateTime(name string, t time.Time) Attr {
	t = t.UTC()
	d := binary.BigEndian.AppendUint16(nil, uint16(t.Year()))
	d = append(d, byte(t.Month()), byte(t.Day()), byte(t.Hour()), byte(t.Minute()), byte(t.Second()),
		byte(t.Nanosecond()/1e8), '+', 0, 0)
	return Attr{Name: name, Values: []Value{{Tag: TagDateTime, Data: d}}}
}

func NoValue(name string) Attr {
	return Attr{Name: name, Values: []Value{{Tag: TagNoValue}}}
}
