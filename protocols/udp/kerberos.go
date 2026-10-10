package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

const (
	maxKerberosPayload = 1024
	asn1ClassApp       = 1
	asn1ClassContext   = 2
	kerberosASReq      = 10
	kerberosTGSReq     = 12
	kerberosError      = 30

	kdcErrPreauthRequired = 25
	paEncTimestamp        = 2
	paETypeInfo2          = 19
)

// kerberosNow is the KRB-ERROR stime clock; tests swap it for determinism.
var kerberosNow = time.Now

var (
	errDERTruncated   = errors.New("truncated DER")
	errDERUnsupported = errors.New("unsupported DER")
	errDERNotSequence = errors.New("expected SEQUENCE")
	errDERUnexpected  = errors.New("unexpected DER class or tag")
)

var kerberosMsgNames = map[int]string{
	kerberosASReq:  "AS-REQ",
	kerberosTGSReq: "TGS-REQ",
	kerberosError:  "KRB-ERROR",
}

type parsedKerberos struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Path      string `json:"path,omitempty"`
	MsgType   int    `json:"msg_type,omitempty"`
	MsgName   string `json:"msg_name,omitempty"`
	Status    string `json:"status,omitempty"`
	PVNO      int    `json:"pvno,omitempty"`
	Realm     string `json:"realm,omitempty"`
	SName     string `json:"sname,omitempty"`
	CName     string `json:"cname,omitempty"`
	ETypes    []int  `json:"etypes,omitempty"`
	From      string `json:"from,omitempty"`
	Nonce     int    `json:"nonce,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type derValue struct {
	class       int
	constructed bool
	tag         int
	content     []byte
}

func derEncode(tag byte, content []byte) []byte {
	n := len(content)
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func derCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func derInt(n int) []byte {
	b := []byte{byte(n)}
	for v := n >> 8; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derEncode(0x02, b)
}

func derCtx(tag int, content []byte) []byte { return derEncode(0xa0|byte(tag), content) }

func derGeneralString(s string) []byte { return derEncode(0x1b, []byte(s)) }

func derPrincipal(nameType int, parts ...string) []byte {
	var strs []byte
	for _, p := range parts {
		strs = append(strs, derGeneralString(p)...)
	}
	return derEncode(0x30, derCat(derCtx(0, derInt(nameType)), derCtx(1, derEncode(0x30, strs))))
}

// buildKerberosPreauthRequired builds the KRB-ERROR a KDC sends for an AS-REQ
// without pre-authentication: KDC_ERR_PREAUTH_REQUIRED with METHOD-DATA naming
// PA-ENC-TIMESTAMP and PA-ETYPE-INFO2. Clients answer with a second AS-REQ
// carrying an encrypted timestamp, which is the next request we want to see.
func buildKerberosPreauthRequired(req parsedKerberos, now time.Time) []byte {
	etype := 18
	for _, e := range req.ETypes {
		if e == 18 || e == 17 || e == 23 {
			etype = e
			break
		}
	}
	entry := derCtx(0, derInt(etype))
	if req.CName != "" && etype != 23 {
		entry = derCat(entry, derCtx(1, derGeneralString(req.Realm+strings.ReplaceAll(req.CName, "/", ""))))
	}
	info2 := derEncode(0x30, derEncode(0x30, entry))
	methodData := derEncode(0x30, derCat(
		derEncode(0x30, derCat(derCtx(1, derInt(paETypeInfo2)), derCtx(2, derEncode(0x04, info2)))),
		derEncode(0x30, derCat(derCtx(1, derInt(paEncTimestamp)), derCtx(2, derEncode(0x04, nil)))),
	))
	now = now.UTC()
	body := derCat(
		derCtx(0, derInt(5)),
		derCtx(1, derInt(kerberosError)),
		derCtx(4, derEncode(0x18, []byte(now.Format("20060102150405Z")))),
		derCtx(5, derInt(now.Nanosecond()/1000)),
		derCtx(6, derInt(kdcErrPreauthRequired)),
		derCtx(9, derGeneralString(req.Realm)),
		derCtx(10, derPrincipal(2, "krbtgt", req.Realm)),
		derCtx(12, derEncode(0x04, methodData)),
	)
	return derEncode(0x60|kerberosError, derEncode(0x30, body))
}

func kerberosMsgName(msgType int) string {
	if name, ok := kerberosMsgNames[msgType]; ok {
		return name
	}
	return "UNKNOWN"
}

func parseDERLength(data []byte) (length, headerLen int, err error) {
	if len(data) < 1 {
		return 0, 0, errDERTruncated
	}
	b := data[0]
	if b&0x80 == 0 {
		return int(b), 1, nil
	}
	n := int(b & 0x7f)
	if n == 0 {
		return 0, 0, errDERUnsupported // indefinite form
	}
	if n > 4 || 1+n > len(data) {
		return 0, 0, errDERTruncated
	}
	var l int
	for i := 0; i < n; i++ {
		l = (l << 8) | int(data[1+i])
	}
	return l, 1 + n, nil
}

func parseDER(data []byte) (derValue, []byte, error) {
	if len(data) < 2 {
		return derValue{}, nil, errDERTruncated
	}
	b := data[0]
	class := int(b >> 6)
	constructed := b&0x20 != 0
	tag := int(b & 0x1f)
	if tag == 0x1f {
		return derValue{}, nil, errDERUnsupported
	}
	length, headerLen, err := parseDERLength(data[1:])
	if err != nil {
		return derValue{}, nil, err
	}
	off := 1 + headerLen
	if length < 0 || off+length > len(data) {
		return derValue{}, nil, errDERTruncated
	}
	return derValue{class: class, constructed: constructed, tag: tag, content: data[off : off+length]}, data[off+length:], nil
}

func parseDERInteger(content []byte) (int, error) {
	if len(content) == 0 || len(content) > 8 {
		return 0, errDERUnsupported
	}
	padded := make([]byte, 8)
	copy(padded[8-len(content):], content)
	if content[0]&0x80 != 0 {
		for i := 0; i < 8-len(content); i++ {
			padded[i] = 0xff
		}
	}
	return int(int64(binary.BigEndian.Uint64(padded))), nil
}

func expectUniversal(v derValue, tag int) error {
	if v.class != 0 || v.tag != tag {
		return errDERUnexpected
	}
	return nil
}

func walkSequence(content []byte, fn func(derValue) error) error {
	for len(content) > 0 {
		v, rest, err := parseDER(content)
		if err != nil {
			return err
		}
		if err := fn(v); err != nil {
			return err
		}
		content = rest
	}
	return nil
}

func unwrapContext(v derValue, tag int) (derValue, error) {
	if v.class != asn1ClassContext || v.tag != tag {
		return derValue{}, errDERUnexpected
	}
	inner, rest, err := parseDER(v.content)
	if err != nil {
		return derValue{}, err
	}
	if len(rest) != 0 {
		return derValue{}, errDERUnexpected
	}
	return inner, nil
}

func parseKerberosString(v derValue) (string, error) {
	// GeneralString (27), UTF8String (12), IA5String (22), PrintableString (19),
	// or an untagged OCTET STRING-like payload from some scanners.
	if v.class != 0 {
		return "", errDERUnexpected
	}
	return string(v.content), nil
}

func parsePrincipalName(content []byte) (string, error) {
	seq, rest, err := parseDER(content)
	if err != nil {
		return "", err
	}
	if err := expectUniversal(seq, 16); err != nil || !seq.constructed {
		return "", errDERNotSequence
	}
	if len(rest) != 0 {
		return "", errDERUnexpected
	}
	var parts []string
	err = walkSequence(seq.content, func(v derValue) error {
		if v.class != asn1ClassContext {
			return nil
		}
		if v.tag != 1 {
			return nil
		}
		inner, err := unwrapContext(v, 1)
		if err != nil {
			return err
		}
		if err := expectUniversal(inner, 16); err != nil || !inner.constructed {
			return errDERNotSequence
		}
		return walkSequence(inner.content, func(s derValue) error {
			name, err := parseKerberosString(s)
			if err != nil {
				return err
			}
			if name != "" {
				parts = append(parts, name)
			}
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return strings.Join(parts, "/"), nil
}

func parseETypes(content []byte) ([]int, error) {
	seq, rest, err := parseDER(content)
	if err != nil {
		return nil, err
	}
	if err := expectUniversal(seq, 16); err != nil || !seq.constructed {
		return nil, errDERNotSequence
	}
	if len(rest) != 0 {
		return nil, errDERUnexpected
	}
	var etypes []int
	err = walkSequence(seq.content, func(v derValue) error {
		if err := expectUniversal(v, 2); err != nil {
			return err
		}
		n, err := parseDERInteger(v.content)
		if err != nil {
			return err
		}
		etypes = append(etypes, n)
		return nil
	})
	return etypes, err
}

func parseKDCReqBody(content []byte, frame *parsedKerberos) error {
	seq, rest, err := parseDER(content)
	if err != nil {
		return err
	}
	if err := expectUniversal(seq, 16); err != nil || !seq.constructed {
		return errDERNotSequence
	}
	if len(rest) != 0 {
		return errDERUnexpected
	}
	return walkSequence(seq.content, func(v derValue) error {
		if v.class != asn1ClassContext {
			return nil
		}
		switch v.tag {
		case 1:
			name, err := parsePrincipalName(v.content)
			if err != nil {
				return err
			}
			frame.CName = name
		case 2:
			inner, err := unwrapContext(v, 2)
			if err != nil {
				return err
			}
			frame.Realm, err = parseKerberosString(inner)
			if err != nil {
				return err
			}
		case 3:
			name, err := parsePrincipalName(v.content)
			if err != nil {
				return err
			}
			frame.SName = name
		case 4:
			inner, err := unwrapContext(v, 4)
			if err != nil {
				return err
			}
			frame.From = string(inner.content)
		case 7:
			inner, err := unwrapContext(v, 7)
			if err != nil {
				return err
			}
			if err := expectUniversal(inner, 2); err != nil {
				return err
			}
			frame.Nonce, err = parseDERInteger(inner.content)
			if err != nil {
				return err
			}
		case 8:
			frame.ETypes, err = parseETypes(v.content)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func parseKDCReq(content []byte, frame *parsedKerberos) error {
	seq, rest, err := parseDER(content)
	if err != nil {
		return err
	}
	if err := expectUniversal(seq, 16); err != nil || !seq.constructed {
		return errDERNotSequence
	}
	if len(rest) != 0 {
		return errDERUnexpected
	}
	return walkSequence(seq.content, func(v derValue) error {
		if v.class != asn1ClassContext {
			return nil
		}
		switch v.tag {
		case 1:
			inner, err := unwrapContext(v, 1)
			if err != nil {
				return err
			}
			if err := expectUniversal(inner, 2); err != nil {
				return err
			}
			frame.PVNO, err = parseDERInteger(inner.content)
			return err
		case 2:
			inner, err := unwrapContext(v, 2)
			if err != nil {
				return err
			}
			if err := expectUniversal(inner, 2); err != nil {
				return err
			}
			n, err := parseDERInteger(inner.content)
			if err != nil {
				return err
			}
			if frame.MsgType == 0 {
				frame.MsgType = n
				frame.MsgName = kerberosMsgName(n)
			}
			return nil
		case 4:
			return parseKDCReqBody(v.content, frame)
		}
		return nil
	})
}

func parseKerberos(data []byte) parsedKerberos {
	frame := parsedKerberos{Direction: "read", Payload: data}
	if len(data) == 0 {
		frame.MsgName = "UNKNOWN"
		frame.Command = frame.MsgName
		return frame
	}

	outer, _, err := parseDER(data)
	if err != nil || outer.class != asn1ClassApp || !outer.constructed {
		frame.MsgName = "UNKNOWN"
		frame.Command = frame.MsgName
		return frame
	}

	frame.MsgType = outer.tag
	frame.MsgName = kerberosMsgName(outer.tag)
	frame.Command = frame.MsgName
	if err := parseKDCReq(outer.content, &frame); err != nil {
		frame.Path = frame.SName
		return frame
	}
	frame.Path = frame.SName
	return frame
}

func looksLikeKerberos(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	b := data[0]
	class := int(b >> 6)
	constructed := b&0x20 != 0
	tag := int(b & 0x1f)
	if class != asn1ClassApp || !constructed || (tag != kerberosASReq && tag != kerberosTGSReq) {
		return false
	}
	length, headerLen, err := parseDERLength(data[1:])
	if err != nil {
		return false
	}
	off := 1 + headerLen
	if off >= len(data) {
		return false
	}
	return data[off] == 0x30 && length >= 0
}

// HandleKerberos parses a Kerberos UDP datagram (typically AS-REQ / TGS-REQ on
// port 88) and emits one producer event. An AS-REQ with a realm is answered
// with KDC_ERR_PREAUTH_REQUIRED so the client retries with an encrypted
// timestamp (revealing its principal); TGS-REQ and unparseable input stay
// parse-only. No AS-REP is ever produced: there is no real KDC behind this.
func HandleKerberos(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxKerberosPayload))
	copy(payload, data[:len(payload)])

	events := []parsedKerberos{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("kerberos", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedKerberos](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "kerberos"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	frame := parseKerberos(payload)
	frame.Truncated = len(data) > maxKerberosPayload
	events = append(events, frame)

	if frame.MsgName == "UNKNOWN" {
		logger.Debug("Kerberos packet was not a parseable AS-REQ/TGS-REQ",
			slog.String("protocol", "kerberos"),
			slog.Int("bytes", len(payload)),
			slog.Int("msg_type", frame.MsgType),
		)
	}

	logger.Info("Kerberos UDP packet received",
		slog.String("handler", "kerberos"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("msg_name", frame.MsgName),
		slog.Int("msg_type", frame.MsgType),
		slog.String("realm", frame.Realm),
		slog.String("sname", frame.SName),
	)

	if frame.MsgType != kerberosASReq || frame.Realm == "" {
		return nil
	}
	resp := buildKerberosPreauthRequired(frame, kerberosNow())
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send Kerberos reply", slog.String("protocol", "kerberos"), producer.ErrAttr(err))
		return nil
	}
	events = append(events, parsedKerberos{
		Direction: "write",
		Command:   "KRB-ERROR",
		Path:      "krbtgt/" + frame.Realm,
		MsgType:   kerberosError,
		MsgName:   "KRB-ERROR",
		Status:    "KDC_ERR_PREAUTH_REQUIRED",
		Realm:     frame.Realm,
		SName:     "krbtgt/" + frame.Realm,
		Payload:   resp,
	})
	return nil
}
