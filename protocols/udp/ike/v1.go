package ike

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

// IKEv1 attribute types (RFC 2409 Appendix A).
const (
	v1AttrEncryption   uint16 = 1
	v1AttrHash         uint16 = 2
	v1AttrAuth         uint16 = 3
	v1AttrGroup        uint16 = 4
	v1AttrLifeType     uint16 = 11
	v1AttrLifeDuration uint16 = 12
	v1AttrKeyLength    uint16 = 14

	v1LifeSeconds uint16 = 1
	v1AuthPSK     uint16 = 1
)

// V1Transform is one IKEv1 transform: a single set of attributes, not an
// IKEv2 OR of independent transforms.
type V1Transform struct {
	Num         byte
	ID          uint16 // KEY_IKE (1) for phase 1
	Encryption  uint16
	Hash        uint16
	AuthMethod  uint16
	Group       uint16
	KeyLength   uint16 // bits, 0 when absent (DES, 3DES)
	LifeSeconds uint32
	HasLife     bool
}

// V1Proposal is one IKEv1 proposal.
type V1Proposal struct {
	Num        byte
	Protocol   byte
	Transforms []V1Transform
}

// V1Choice is the transform the responder accepts.
type V1Choice struct {
	ProposalNum byte
	Transform   V1Transform
}

func (t V1Transform) EncryptionName() string { return v1Named(v1EncNames, t.Encryption, t.KeyLength) }
func (t V1Transform) HashName() string       { return v1Named(v1HashNames, t.Hash, 0) }
func (t V1Transform) AuthName() string       { return v1Named(v1AuthNames, t.AuthMethod, 0) }
func (t V1Transform) GroupName() string      { return v1Named(transformNames[TransformDH], t.Group, 0) }

func (t V1Transform) LifeString() string {
	if !t.HasLife {
		return ""
	}
	return fmt.Sprintf("%d", t.LifeSeconds)
}

var (
	v1EncNames  = map[uint16]string{1: "DES", 5: "3DES", 7: "AES_CBC"}
	v1HashNames = map[uint16]string{
		1: "MD5", 2: "SHA1", 4: "SHA2_256", 5: "SHA2_384", 6: "SHA2_512",
	}
	v1AuthNames = map[uint16]string{1: "PSK", 3: "RSA_SIG", 65001: "XAUTH_INIT_PSK"}

	v1IDTypes = map[byte]string{
		1: "IPV4_ADDR", 2: "FQDN", 3: "USER_FQDN", 4: "IPV4_ADDR_SUBNET",
		5: "IPV6_ADDR", 9: "DER_ASN1_DN", 11: "KEY_ID",
	}
)

func v1Named(table map[uint16]string, id, keyLen uint16) string {
	name, ok := table[id]
	if !ok {
		name = fmt.Sprintf("UNKNOWN_%d", id)
	}
	if keyLen != 0 {
		name = fmt.Sprintf("%s_%d", name, keyLen)
	}
	return name
}

// V1Offered returns the names of one IKEv1 attribute across transforms, in
// order and without duplicates. attr is "encryption", "hash", "auth", "group"
// or "life".
func (m Message) V1Offered(attr string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range m.V1Proposals {
		for _, t := range p.Transforms {
			var name string
			switch attr {
			case "encryption":
				name = t.EncryptionName()
			case "hash":
				name = t.HashName()
			case "auth":
				name = t.AuthName()
			case "group":
				name = t.GroupName()
			case "life":
				name = t.LifeString()
			}
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func firstV1Group(m Message) uint16 {
	for _, p := range m.V1Proposals {
		for _, t := range p.Transforms {
			if t.Group != 0 {
				return t.Group
			}
		}
	}
	return 0
}

func parseV1SA(body []byte) ([]V1Proposal, error) {
	if len(body) < 8 {
		return nil, ErrMalformed
	}
	b := body[8:] // DOI, situation
	var props []V1Proposal
	for len(b) > 0 {
		if len(b) < 8 {
			return props, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		spiSize := int(b[6])
		if n < 8+spiSize || n > len(b) {
			return props, ErrMalformed
		}
		p := V1Proposal{Num: b[4], Protocol: b[5]}
		ts, err := parseV1Transforms(b[8+spiSize:n], int(b[7]))
		p.Transforms = ts
		props = append(props, p)
		if err != nil {
			return props, err
		}
		last := b[0] == 0
		b = b[n:]
		if last {
			break
		}
	}
	return props, nil
}

func parseV1Transforms(b []byte, count int) ([]V1Transform, error) {
	var ts []V1Transform
	for i := 0; i < count; i++ {
		if len(b) < 8 {
			return ts, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n < 8 || n > len(b) {
			return ts, ErrMalformed
		}
		t := V1Transform{Num: b[4], ID: uint16(b[5])}
		var err error
		t, err = parseV1Attrs(t, b[8:n])
		if err != nil {
			return ts, err
		}
		ts = append(ts, t)
		b = b[n:]
	}
	if len(b) != 0 {
		return ts, ErrMalformed
	}
	return ts, nil
}

func parseV1Attrs(t V1Transform, attrs []byte) (V1Transform, error) {
	var lifeType uint16
	var lifeRaw uint32
	var hasLifeRaw bool
	for len(attrs) > 0 {
		if len(attrs) < 4 {
			return t, ErrMalformed
		}
		typ := binary.BigEndian.Uint16(attrs[0:2])
		if typ&0x8000 != 0 {
			val := binary.BigEndian.Uint16(attrs[2:4])
			switch typ & 0x7fff {
			case v1AttrEncryption:
				t.Encryption = val
			case v1AttrHash:
				t.Hash = val
			case v1AttrAuth:
				t.AuthMethod = val
			case v1AttrGroup:
				t.Group = val
			case v1AttrKeyLength:
				t.KeyLength = val
			case v1AttrLifeType:
				lifeType = val
			}
			attrs = attrs[4:]
			continue
		}
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+l > len(attrs) {
			return t, ErrMalformed
		}
		raw := attrs[4 : 4+l]
		if typ == v1AttrLifeDuration {
			hasLifeRaw = true
			for _, c := range raw {
				lifeRaw = lifeRaw<<8 | uint32(c)
			}
		}
		attrs = attrs[4+l:]
	}
	if hasLifeRaw && (lifeType == 0 || lifeType == v1LifeSeconds) {
		t.HasLife = true
		t.LifeSeconds = lifeRaw
	}
	return t, nil
}

func parseV1ID(body []byte) (string, string, error) {
	if len(body) < 4 {
		return "", "", ErrMalformed
	}
	typ := body[0]
	name, ok := v1IDTypes[typ]
	if !ok {
		name = fmt.Sprintf("UNKNOWN_%d", typ)
	}
	data := body[4:]
	switch typ {
	case 1: // IPV4_ADDR
		if len(data) < 4 {
			return "", "", ErrMalformed
		}
		return name, net.IP(data[:4]).String(), nil
	case 2, 3: // FQDN, USER_FQDN
		return name, string(data), nil
	default:
		return name, hex.EncodeToString(data), nil
	}
}

// Persona policy for IKEv1: prefer AES-256/SHA2-256/MODP_2048/PSK and still
// accept down to AES-128/SHA1/MODP_1024/PSK. DES and XAUTH are recorded but
// not chosen.
var v1Prefs = []struct {
	enc, keyLen, hash, group uint16
}{
	{7, 256, 4, 14},
	{7, 128, 4, 14},
	{7, 256, 2, 14},
	{7, 128, 2, 14},
	{5, 0, 2, 14},
	{5, 0, 1, 14},
	{7, 256, 4, 2},
	{7, 128, 2, 2},
}

// ChooseV1 returns the first offered transform that matches the preference
// list. The transform number is the one from the request.
func ChooseV1(m Message) (V1Choice, bool) {
	for _, want := range v1Prefs {
		for _, p := range m.V1Proposals {
			if p.Protocol != protocolIKE {
				continue
			}
			for _, t := range p.Transforms {
				if t.Encryption == want.enc && t.KeyLength == want.keyLen &&
					t.Hash == want.hash && t.Group == want.group &&
					t.AuthMethod == v1AuthPSK {
					return V1Choice{ProposalNum: p.Num, Transform: t}, true
				}
			}
		}
	}
	return V1Choice{}, false
}

// isMainModeRequest reports whether m is an unencrypted IKEv1 Main Mode
// message 1 (exchange 2, zero responder SPI, message ID 0).
func (m Message) isMainModeRequest() bool {
	return m.Version>>4 == 1 && m.Exchange == exchangeMainMode &&
		m.Flags&flagV1Encryption == 0 &&
		m.SPIr == [8]byte{} && m.MessageID == 0
}

// Gateway vendor IDs a common IPsec gateway announces in Main Mode message 2.
var (
	vidNATRFC3947 = md5VID("RFC 3947")
	vidNATDraft02 = md5VID("draft-ietf-ipsec-nat-t-ike-02\n")
	// vidDPD is the Dead Peer Detection vendor ID (RFC 3706).
	vidDPD = []byte{0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00}
	// vidXAUTH is the Cisco / draft-ietf-ipsec-isakmp-xauth vendor ID.
	vidXAUTH = []byte{0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12}
)

func md5VID(s string) []byte {
	sum := md5.Sum([]byte(s))
	return append([]byte(nil), sum[:]...)
}

// gatewayVIDs is the Vendor ID set written into Main Mode message 2.
func gatewayVIDs() [][]byte {
	return [][]byte{vidNATRFC3947, vidNATDraft02, vidDPD, vidXAUTH}
}

// BuildReplyV1 returns Main Mode message 2 for an IKEv1 identity-protection
// request, or an Informational NO_PROPOSAL_CHOSEN when nothing matches. ok
// is false for every other exchange, including Aggressive Mode. rnd supplies
// the responder SPI.
func BuildReplyV1(m Message, rnd io.Reader) (Reply, bool, error) {
	if !m.isMainModeRequest() {
		return Reply{}, false, nil
	}
	c, ok := ChooseV1(m)
	if !ok {
		return Reply{Data: notifyV1(m), Status: NotifyName(NotifyNoProposalChosen)}, true, nil
	}
	// state a lifetime when the offer omitted one, so message 2 stays a
	// complete transform. A one-transform message 1 without it is smaller
	// than half this reply and the handler drops the reply.
	if !c.Transform.HasLife {
		c.Transform.HasLife = true
		c.Transform.LifeSeconds = 28800
	}
	var spiR [8]byte
	if _, err := io.ReadFull(rnd, spiR[:]); err != nil {
		return Reply{}, false, err
	}
	if spiR == [8]byte{} {
		spiR[7] = 1
	}
	vids := gatewayVIDs()
	body := appendPayload(nil, payloadV1VID, saV1(c))
	for i, vid := range vids {
		next := byte(payloadV1VID)
		if i == len(vids)-1 {
			next = payloadNone
		}
		body = appendPayload(body, next, vid)
	}
	data := header(m, spiR, payloadV1SA, VersionV1, exchangeMainMode, 0, body)
	return Reply{
		Data:   data,
		Status: ExchangeName(exchangeMainMode),
		SPIr:   spiR,
		V1:     &c,
	}, true, nil
}

func notifyV1(m Message) []byte {
	n := binary.BigEndian.AppendUint32(nil, 1) // DOI IPSEC
	n = append(n, protocolIKE, 0)              // ISAKMP, no SPI
	n = binary.BigEndian.AppendUint16(n, NotifyNoProposalChosen)
	body := appendPayload(nil, payloadNone, n)
	return header(m, [8]byte{}, payloadV1Notify, VersionV1, exchangeInfoV1, 0, body)
}

func saV1(c V1Choice) []byte {
	attrs := v1Attrs(c.Transform)
	tb := []byte{0, 0}
	tb = binary.BigEndian.AppendUint16(tb, uint16(8+len(attrs)))
	tb = append(tb, c.Transform.Num, byte(c.Transform.ID), 0, 0)
	tb = append(tb, attrs...)

	prop := []byte{0, 0}
	prop = binary.BigEndian.AppendUint16(prop, uint16(8+len(tb)))
	prop = append(prop, c.ProposalNum, protocolIKE, 0, 1)
	prop = append(prop, tb...)

	body := binary.BigEndian.AppendUint32(nil, 1) // DOI
	body = binary.BigEndian.AppendUint32(body, 1) // SIT_IDENTITY_ONLY
	return append(body, prop...)
}

func v1Attrs(t V1Transform) []byte {
	a := v1TV(v1AttrEncryption, t.Encryption)
	if t.KeyLength != 0 {
		a = append(a, v1TV(v1AttrKeyLength, t.KeyLength)...)
	}
	a = append(a, v1TV(v1AttrHash, t.Hash)...)
	a = append(a, v1TV(v1AttrAuth, t.AuthMethod)...)
	a = append(a, v1TV(v1AttrGroup, t.Group)...)
	if t.HasLife {
		a = append(a, v1TV(v1AttrLifeType, v1LifeSeconds)...)
		a = append(a, v1TLV(v1AttrLifeDuration, binary.BigEndian.AppendUint32(nil, t.LifeSeconds))...)
	}
	return a
}

func v1TV(typ, val uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, 0x8000|typ)
	return binary.BigEndian.AppendUint16(b, val)
}

func v1TLV(typ uint16, val []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(val)))
	return append(b, val...)
}
