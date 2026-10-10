package banners

import (
	"bytes"
	"regexp"
)

// mglnddProbe matches the MGLNDD scanner probe, "MGLNDD_<target ip>_<target
// port>" plus a newline, sent to any port by an Azure-hosted census scanner.
// It expects no protocol answer.
var mglnddProbe = regexp.MustCompile(`^MGLNDD_[^_\s]+_\d+\r?\n?$`)

// rootDSE is an OpenLDAP-style root DSE, returned for every anonymous base
// search of the empty DN regardless of the requested attributes.
var rootDSE = []struct {
	attr   string
	values []string
}{
	{"objectClass", []string{"top", "OpenLDAProotDSE"}},
	{"namingContexts", []string{"dc=corp,dc=local"}},
	{"subschemaSubentry", []string{"cn=Subschema"}},
	{"supportedLDAPVersion", []string{"3"}},
	{"supportedSASLMechanisms", []string{"DIGEST-MD5", "CRAM-MD5"}},
	{"supportedExtension", []string{"1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.4203.1.11.3"}},
}

// berTLV reads one BER element from data and returns its tag, content and
// the bytes after it. Only definite lengths of up to four octets are allowed.
func berTLV(data []byte) (tag byte, content, rest []byte, ok bool) {
	if len(data) < 2 {
		return 0, nil, nil, false
	}
	tag, l := data[0], int(data[1])
	data = data[2:]
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(data) < n {
			return 0, nil, nil, false
		}
		l = 0
		for _, b := range data[:n] {
			l = l<<8 | int(b)
		}
		data = data[n:]
	}
	if l > len(data) {
		return 0, nil, nil, false
	}
	return tag, data[:l], data[l:], true
}

// berEncode builds a BER element with a definite length.
func berEncode(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	out := []byte{tag}
	switch l := len(body); {
	case l < 0x80:
		out = append(out, byte(l))
	case l <= 0xff:
		out = append(out, 0x81, byte(l))
	default:
		out = append(out, 0x82, byte(l>>8), byte(l))
	}
	return append(out, body...)
}

// ldapRootDSEQuery reports whether data is an LDAPMessage carrying a
// SearchRequest for the root DSE (empty baseObject, scope baseObject) and
// returns the raw messageID INTEGER content to echo.
func ldapRootDSEQuery(data []byte) ([]byte, bool) {
	tag, msg, _, ok := berTLV(data)
	if !ok || tag != 0x30 {
		return nil, false
	}
	tag, msgID, msg, ok := berTLV(msg)
	if !ok || tag != 0x02 || len(msgID) == 0 || len(msgID) > 4 {
		return nil, false
	}
	tag, req, _, ok := berTLV(msg)
	if !ok || tag != 0x63 { // [APPLICATION 3] SearchRequest
		return nil, false
	}
	tag, base, req, ok := berTLV(req)
	if !ok || tag != 0x04 || len(base) != 0 {
		return nil, false
	}
	tag, scope, _, ok := berTLV(req)
	if !ok || tag != 0x0a || !bytes.Equal(scope, []byte{0x00}) {
		return nil, false
	}
	return msgID, true
}

// ldapRootDSEReply builds a SearchResultEntry with the root DSE followed by
// a successful SearchResultDone, both under the client's messageID.
func ldapRootDSEReply(msgID []byte) []byte {
	id := berEncode(0x02, msgID)
	attrs := make([][]byte, 0, len(rootDSE))
	for _, a := range rootDSE {
		vals := make([][]byte, 0, len(a.values))
		for _, v := range a.values {
			vals = append(vals, berEncode(0x04, []byte(v)))
		}
		attrs = append(attrs, berEncode(0x30, berEncode(0x04, []byte(a.attr)), berEncode(0x31, vals...)))
	}
	entry := berEncode(0x30, id, berEncode(0x64, berEncode(0x04), berEncode(0x30, attrs...)))
	// resultCode success, empty matchedDN and diagnosticMessage
	done := berEncode(0x30, id, berEncode(0x65, berEncode(0x0a, []byte{0x00}), berEncode(0x04), berEncode(0x04)))
	return append(entry, done...)
}
