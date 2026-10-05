// Package ike parses IKE (ISAKMP) messages and builds stateless IKEv2
// IKE_SA_INIT responses (RFC 7296) for the UDP IKE handler. Internet-wide
// scanners (e.g. Censys) send an IKE_SA_INIT that offers every transform
// they know; a real gateway answers with the proposal it accepts, an
// INVALID_KE_PAYLOAD asking for its preferred Diffie-Hellman group, or
// NO_PROPOSAL_CHOSEN. The package does no I/O and never completes a key
// exchange: response KE values are random bytes.
package ike

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// HeaderLen is the fixed ISAKMP header length.
	HeaderLen = 28
	// nonESPMarkerLen is the zero prefix of IKE on the NAT-T port (RFC 3948).
	nonESPMarkerLen = 4

	// Version bytes (major << 4 | minor).
	VersionV1 byte = 0x10
	VersionV2 byte = 0x20

	flagInitiator byte = 0x08
	flagResponse  byte = 0x20

	protocolIKE byte = 1
)

// IKEv2 exchange types.
const (
	ExchangeSAInit        byte = 34
	ExchangeAuth          byte = 35
	ExchangeCreateChildSA byte = 36
	ExchangeInformational byte = 37
)

// IKEv2 payload types (RFC 7296 §3.2) and the IKEv1 Vendor ID type.
const (
	payloadNone     byte = 0
	payloadSA       byte = 33
	payloadKE       byte = 34
	payloadNonce    byte = 40
	payloadNotify   byte = 41
	payloadVendorID byte = 43
	payloadV1VID    byte = 13
)

// Transform types.
const (
	TransformENCR  byte = 1
	TransformPRF   byte = 2
	TransformINTEG byte = 3
	TransformDH    byte = 4
)

// Notify message types sent by the responder.
const (
	NotifyNoProposalChosen uint16 = 14
	NotifyInvalidKEPayload uint16 = 17
)

const attrKeyLength uint16 = 14

var (
	ErrTruncated = errors.New("truncated IKE message")
	ErrMalformed = errors.New("malformed IKE message")
)

var exchangeNames = map[byte]string{
	// IKEv1 (RFC 2408/2409)
	1: "BASE", 2: "IDENTITY_PROTECTION", 3: "AUTHENTICATION_ONLY", 4: "AGGRESSIVE",
	5: "INFORMATIONAL_V1", 32: "QUICK_MODE", 33: "NEW_GROUP_MODE",
	// IKEv2
	ExchangeSAInit: "IKE_SA_INIT", ExchangeAuth: "IKE_AUTH",
	ExchangeCreateChildSA: "CREATE_CHILD_SA", ExchangeInformational: "INFORMATIONAL",
}

var transformNames = map[byte]map[uint16]string{
	TransformENCR: {
		1: "DES_IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA", 6: "CAST", 7: "BLOWFISH",
		8: "3IDEA", 9: "DES_IV32", 11: "NULL", 12: "AES_CBC", 13: "AES_CTR",
		14: "AES_CCM_8", 15: "AES_CCM_12", 16: "AES_CCM_16", 18: "AES_GCM_8",
		19: "AES_GCM_12", 20: "AES_GCM_16", 23: "CAMELLIA_CBC", 28: "CHACHA20_POLY1305",
	},
	TransformPRF: {
		1: "HMAC_MD5", 2: "HMAC_SHA1", 3: "HMAC_TIGER", 4: "AES128_XCBC",
		5: "HMAC_SHA2_256", 6: "HMAC_SHA2_384", 7: "HMAC_SHA2_512", 8: "AES128_CMAC",
	},
	TransformINTEG: {
		0: "NONE", 1: "HMAC_MD5_96", 2: "HMAC_SHA1_96", 3: "DES_MAC", 4: "KPDK_MD5",
		5: "AES_XCBC_96", 6: "HMAC_MD5_128", 7: "HMAC_SHA1_160", 8: "AES_CMAC_96",
		12: "HMAC_SHA2_256_128", 13: "HMAC_SHA2_384_192", 14: "HMAC_SHA2_512_256",
	},
	TransformDH: {
		0: "NONE", 1: "MODP_768", 2: "MODP_1024", 5: "MODP_1536", 14: "MODP_2048",
		15: "MODP_3072", 16: "MODP_4096", 17: "MODP_6144", 18: "MODP_8192",
		19: "ECP_256", 20: "ECP_384", 21: "ECP_521", 31: "CURVE25519", 32: "CURVE448",
	},
}

var notifyNames = map[uint16]string{
	1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
	7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI",
	NotifyNoProposalChosen: "NO_PROPOSAL_CHOSEN", NotifyInvalidKEPayload: "INVALID_KE_PAYLOAD",
	24: "AUTHENTICATION_FAILED", 16388: "NAT_DETECTION_SOURCE_IP",
	16389: "NAT_DETECTION_DESTINATION_IP", 16390: "COOKIE",
	16404: "MULTIPLE_AUTH_SUPPORTED", 16406: "REDIRECT_SUPPORTED",
	16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
}

// ExchangeName returns the name of an exchange type.
func ExchangeName(t byte) string {
	if name, ok := exchangeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", t)
}

// NotifyName returns the name of a notify message type.
func NotifyName(t uint16) string {
	if name, ok := notifyNames[t]; ok {
		return name
	}
	return fmt.Sprintf("NOTIFY_%d", t)
}

// Transform is one SA transform.
type Transform struct {
	Type      byte
	ID        uint16
	KeyLength uint16 // bits, 0 when absent
}

// Name returns e.g. "AES_CBC_256", "HMAC_SHA1" or "MODP_2048".
func (t Transform) Name() string {
	name, ok := transformNames[t.Type][t.ID]
	if !ok {
		name = fmt.Sprintf("UNKNOWN_%d", t.ID)
	}
	if t.KeyLength != 0 {
		name = fmt.Sprintf("%s_%d", name, t.KeyLength)
	}
	return name
}

// Proposal is one SA proposal.
type Proposal struct {
	Num        byte
	Protocol   byte
	Transforms []Transform
}

// Message is a parsed IKE message. Fields after the header are only decoded
// for IKEv2, except Vendor IDs which both versions carry.
type Message struct {
	SPIi      [8]byte
	SPIr      [8]byte
	Version   byte
	Exchange  byte
	Flags     byte
	MessageID uint32
	Length    uint32

	Proposals []Proposal
	HasKE     bool
	KEGroup   uint16
	Nonce     []byte
	Notifies  []uint16
	VendorIDs [][]byte
}

// VersionString returns e.g. "2.0".
func (m Message) VersionString() string {
	return fmt.Sprintf("%d.%d", m.Version>>4, m.Version&0x0f)
}

// Offered returns the names of all transforms of one type across proposals,
// in order and without duplicates.
func (m Message) Offered(transformType byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range m.Proposals {
		for _, t := range p.Transforms {
			if t.Type != transformType {
				continue
			}
			if name := t.Name(); !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// VendorIDHex returns the Vendor ID payloads as hex strings.
func (m Message) VendorIDHex() []string {
	var out []string
	for _, v := range m.VendorIDs {
		out = append(out, hex.EncodeToString(v))
	}
	return out
}

// NotifyNames returns the names of the notify payloads.
func (m Message) NotifyNames() []string {
	var out []string
	for _, n := range m.Notifies {
		out = append(out, NotifyName(n))
	}
	return out
}

// isSAInitRequest reports whether m opens an IKEv2 SA (and so deserves a reply).
func (m Message) isSAInitRequest() bool {
	return m.Version>>4 == 2 && m.Exchange == ExchangeSAInit &&
		m.Flags&flagInitiator != 0 && m.Flags&flagResponse == 0 &&
		m.SPIr == [8]byte{} && m.MessageID == 0
}

// StripNonESPMarker removes the 4 zero bytes that precede IKE on the NAT-T
// port when the rest is a complete IKE message, and reports whether it did.
func StripNonESPMarker(data []byte) ([]byte, bool) {
	if len(data) < nonESPMarkerLen+HeaderLen || binary.BigEndian.Uint32(data) != 0 {
		return data, false
	}
	rest := data[nonESPMarkerLen:]
	if int(binary.BigEndian.Uint32(rest[24:28])) != len(rest) {
		return data, false
	}
	return rest, true
}

// LooksLikeIKE is a strict, cheap check for the generic UDP handler: a known
// version and exchange type and a header length equal to the datagram length
// (after an optional non-ESP marker).
func LooksLikeIKE(data []byte) bool {
	data, _ = StripNonESPMarker(data)
	if len(data) < HeaderLen || data[16] == payloadNone {
		return false
	}
	if int(binary.BigEndian.Uint32(data[24:28])) != len(data) {
		return false
	}
	switch data[17] {
	case VersionV2:
		return data[18] >= ExchangeSAInit && data[18] <= ExchangeInformational
	case VersionV1:
		switch data[18] {
		case 2, 4, 5, 32:
			return true
		}
	}
	return false
}

// Parse decodes an IKE message (without non-ESP marker). Header fields are
// returned even when the payload chain is truncated or malformed.
func Parse(data []byte) (Message, error) {
	var m Message
	if len(data) < HeaderLen {
		return m, ErrTruncated
	}
	copy(m.SPIi[:], data[0:8])
	copy(m.SPIr[:], data[8:16])
	next := data[16]
	m.Version = data[17]
	m.Exchange = data[18]
	m.Flags = data[19]
	m.MessageID = binary.BigEndian.Uint32(data[20:24])
	m.Length = binary.BigEndian.Uint32(data[24:28])
	if m.Length < HeaderLen {
		return m, ErrMalformed
	}
	if int(m.Length) > len(data) {
		return m, ErrTruncated
	}
	v2 := m.Version>>4 == 2

	b := data[HeaderLen:m.Length]
	for next != payloadNone {
		if len(b) < 4 {
			return m, ErrTruncated
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n < 4 || n > len(b) {
			return m, ErrMalformed
		}
		typ, body := next, b[4:n]
		next, b = b[0], b[n:]

		var err error
		switch {
		case v2 && typ == payloadSA:
			m.Proposals, err = parseSA(body)
		case v2 && typ == payloadKE:
			if len(body) < 4 {
				return m, ErrMalformed
			}
			m.HasKE = true
			m.KEGroup = binary.BigEndian.Uint16(body[0:2])
		case v2 && typ == payloadNonce:
			m.Nonce = body
		case v2 && typ == payloadNotify:
			if len(body) < 4 || len(body) < 4+int(body[1]) {
				return m, ErrMalformed
			}
			m.Notifies = append(m.Notifies, binary.BigEndian.Uint16(body[2:4]))
		case (v2 && typ == payloadVendorID) || (!v2 && typ == payloadV1VID):
			m.VendorIDs = append(m.VendorIDs, body)
		}
		if err != nil {
			return m, err
		}
	}
	return m, nil
}

func parseSA(b []byte) ([]Proposal, error) {
	var proposals []Proposal
	for len(b) > 0 {
		if len(b) < 8 {
			return proposals, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		spiSize := int(b[6])
		if n < 8+spiSize || n > len(b) {
			return proposals, ErrMalformed
		}
		p := Proposal{Num: b[4], Protocol: b[5]}
		ts, err := parseTransforms(b[8+spiSize:n], int(b[7]))
		p.Transforms = ts
		proposals = append(proposals, p)
		if err != nil {
			return proposals, err
		}
		last := b[0] == 0
		b = b[n:]
		if last {
			break
		}
	}
	return proposals, nil
}

func parseTransforms(b []byte, count int) ([]Transform, error) {
	var ts []Transform
	for i := 0; i < count; i++ {
		if len(b) < 8 {
			return ts, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n < 8 || n > len(b) {
			return ts, ErrMalformed
		}
		t := Transform{Type: b[4], ID: binary.BigEndian.Uint16(b[6:8])}
		attrs := b[8:n]
		for len(attrs) >= 4 {
			typ := binary.BigEndian.Uint16(attrs[0:2])
			if typ&0x8000 != 0 { // TV format
				if typ&0x7fff == attrKeyLength {
					t.KeyLength = binary.BigEndian.Uint16(attrs[2:4])
				}
				attrs = attrs[4:]
				continue
			}
			l := int(binary.BigEndian.Uint16(attrs[2:4]))
			if 4+l > len(attrs) {
				return ts, ErrMalformed
			}
			attrs = attrs[4+l:]
		}
		ts = append(ts, t)
		b = b[n:]
	}
	return ts, nil
}

// Persona policy: a gateway that still accepts legacy 3DES/SHA1 proposals
// but insists on at least a 2048-bit (or EC) Diffie-Hellman group.
var (
	prefENCR = []Transform{
		{TransformENCR, 20, 256}, {TransformENCR, 20, 128}, // AES_GCM_16
		{TransformENCR, 12, 256}, {TransformENCR, 12, 128}, // AES_CBC
		{TransformENCR, 3, 0}, // 3DES
	}
	prefPRF   = []uint16{5, 6, 7, 2}    // SHA2_256, SHA2_384, SHA2_512, SHA1
	prefINTEG = []uint16{12, 13, 14, 2} // SHA2_256_128, SHA2_384_192, SHA2_512_256, SHA1_96
	prefDH    = []uint16{14, 19, 20}    // MODP_2048, ECP_256, ECP_384

	// keSize is the public value length per accepted group.
	keSize = map[uint16]int{14: 256, 19: 64, 20: 96}
)

func isAEAD(t Transform) bool {
	return t.Type == TransformENCR && t.ID >= 14 && t.ID <= 20
}

func offers(p Proposal, want Transform) bool {
	for _, t := range p.Transforms {
		if t == want {
			return true
		}
	}
	return false
}

func pickID(p Proposal, typ byte, prefs []uint16) (Transform, bool) {
	for _, id := range prefs {
		if t := (Transform{Type: typ, ID: id}); offers(p, t) {
			return t, true
		}
	}
	return Transform{}, false
}

// Choice is the proposal the responder accepts.
type Choice struct {
	ProposalNum byte
	ENCR        Transform
	PRF         Transform
	INTEG       *Transform // nil for AEAD ciphers
	DH          Transform
}

// Choose picks the first IKE proposal that satisfies the persona policy.
func Choose(m Message) (Choice, bool) {
	for _, p := range m.Proposals {
		if p.Protocol != protocolIKE {
			continue
		}
		var c Choice
		var ok bool
		for _, e := range prefENCR {
			if offers(p, e) {
				c.ENCR, ok = e, true
				break
			}
		}
		if !ok {
			continue
		}
		if c.PRF, ok = pickID(p, TransformPRF, prefPRF); !ok {
			continue
		}
		if !isAEAD(c.ENCR) {
			integ, ok := pickID(p, TransformINTEG, prefINTEG)
			if !ok {
				continue
			}
			c.INTEG = &integ
		}
		if c.DH, ok = pickID(p, TransformDH, prefDH); !ok {
			continue
		}
		c.ProposalNum = p.Num
		return c, true
	}
	return Choice{}, false
}

// Transforms returns the chosen transforms in wire order.
func (c Choice) Transforms() []Transform {
	ts := []Transform{c.ENCR, c.PRF}
	if c.INTEG != nil {
		ts = append(ts, *c.INTEG)
	}
	return append(ts, c.DH)
}

// Reply is a built response.
type Reply struct {
	Data   []byte
	Status string  // notify name, or "IKE_SA_INIT" for a full response
	SPIr   [8]byte // zero for notify-only responses
	Choice *Choice
}

// BuildReply returns the response to an IKEv2 IKE_SA_INIT request, or false
// when m is not one. rnd supplies the responder SPI, KE value and nonce.
func BuildReply(m Message, rnd io.Reader) (Reply, bool, error) {
	if !m.isSAInitRequest() {
		return Reply{}, false, nil
	}
	c, ok := Choose(m)
	if !ok {
		return Reply{Data: notifyResponse(m, NotifyNoProposalChosen, nil), Status: NotifyName(NotifyNoProposalChosen)}, true, nil
	}
	if !m.HasKE || m.KEGroup != c.DH.ID {
		group := binary.BigEndian.AppendUint16(nil, c.DH.ID)
		return Reply{Data: notifyResponse(m, NotifyInvalidKEPayload, group), Status: NotifyName(NotifyInvalidKEPayload), Choice: &c}, true, nil
	}

	var spiR [8]byte
	ke := make([]byte, keSize[c.DH.ID])
	nonce := make([]byte, 32)
	for _, b := range [][]byte{spiR[:], ke, nonce} {
		if _, err := io.ReadFull(rnd, b); err != nil {
			return Reply{}, false, err
		}
	}
	if spiR == [8]byte{} {
		spiR[7] = 1 // SPIs are never zero
	}

	var body []byte
	body = appendPayload(body, payloadKE, saPayload(c))
	keBody := binary.BigEndian.AppendUint16(nil, c.DH.ID)
	keBody = append(keBody, 0, 0)
	body = appendPayload(body, payloadNonce, append(keBody, ke...))
	body = appendPayload(body, payloadNone, nonce)
	return Reply{Data: header(m, spiR, payloadSA, body), Status: ExchangeName(ExchangeSAInit), SPIr: spiR, Choice: &c}, true, nil
}

func saPayload(c Choice) []byte {
	ts := c.Transforms()
	var tb []byte
	for i, t := range ts {
		more := byte(3)
		if i == len(ts)-1 {
			more = 0
		}
		var attrs []byte
		if t.KeyLength != 0 {
			attrs = binary.BigEndian.AppendUint16(attrs, 0x8000|attrKeyLength)
			attrs = binary.BigEndian.AppendUint16(attrs, t.KeyLength)
		}
		tb = append(tb, more, 0)
		tb = binary.BigEndian.AppendUint16(tb, uint16(8+len(attrs)))
		tb = append(tb, t.Type, 0)
		tb = binary.BigEndian.AppendUint16(tb, t.ID)
		tb = append(tb, attrs...)
	}
	p := []byte{0, 0}
	p = binary.BigEndian.AppendUint16(p, uint16(8+len(tb)))
	p = append(p, c.ProposalNum, protocolIKE, 0, byte(len(ts)))
	return append(p, tb...)
}

// appendPayload appends a generic payload header (with the type of the
// payload that follows) and body.
func appendPayload(dst []byte, next byte, body []byte) []byte {
	dst = append(dst, next, 0)
	dst = binary.BigEndian.AppendUint16(dst, uint16(4+len(body)))
	return append(dst, body...)
}

func notifyResponse(m Message, notify uint16, data []byte) []byte {
	body := []byte{0, 0} // protocol ID, SPI size
	body = binary.BigEndian.AppendUint16(body, notify)
	body = append(body, data...)
	return header(m, [8]byte{}, payloadNotify, appendPayload(nil, payloadNone, body))
}

func header(m Message, spiR [8]byte, first byte, body []byte) []byte {
	out := make([]byte, 0, HeaderLen+len(body))
	out = append(out, m.SPIi[:]...)
	out = append(out, spiR[:]...)
	out = append(out, first, VersionV2, ExchangeSAInit, flagResponse)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(HeaderLen+len(body)))
	return append(out, body...)
}
