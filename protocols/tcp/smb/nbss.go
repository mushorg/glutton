package smb

import (
	"fmt"
	"strings"
)

// NetBIOS Session Service packet types (RFC 1002 4.3.1). Direct TCP (445)
// only carries session messages; NBT on port 139 starts with a session request.
const (
	NBSSSessionMessage   = 0x00
	NBSSSessionRequest   = 0x81
	NBSSPositiveResponse = 0x82
	NBSSNegativeResponse = 0x83
	NBSSRetargetResponse = 0x84
	NBSSKeepAlive        = 0x85
)

var nbssTypeNames = map[byte]string{
	NBSSSessionMessage:   "NBSS_SESSION_MESSAGE",
	NBSSSessionRequest:   "NBSS_SESSION_REQUEST",
	NBSSPositiveResponse: "NBSS_POSITIVE_SESSION_RESPONSE",
	NBSSNegativeResponse: "NBSS_NEGATIVE_SESSION_RESPONSE",
	NBSSRetargetResponse: "NBSS_RETARGET_SESSION_RESPONSE",
	NBSSKeepAlive:        "NBSS_SESSION_KEEP_ALIVE",
}

// NBSSTypeName returns the session packet type mnemonic, or NBSS_0xNN for unknowns.
func NBSSTypeName(t byte) string {
	if name, ok := nbssTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("NBSS_0x%02X", t)
}

// MakePositiveSessionResponse builds the 4-byte NBSS positive session response.
func MakePositiveSessionResponse() []byte {
	return []byte{NBSSPositiveResponse, 0x00, 0x00, 0x00}
}

// ParseSessionRequest decodes the called and calling NetBIOS names from a
// session request body (after the 4-byte NBSS header). ok is false when either
// name is not a valid first-level encoded name.
func ParseSessionRequest(body []byte) (called, calling string, ok bool) {
	called, n, ok := decodeNetBIOSName(body)
	if !ok {
		return "", "", false
	}
	calling, _, ok = decodeNetBIOSName(body[n:])
	if !ok {
		return "", "", false
	}
	return called, calling, true
}

// decodeNetBIOSName decodes one first-level encoded name (RFC 1001 14.1):
// a 0x20 length byte, 32 'A'..'P' half-ASCII characters, then scope labels up
// to a zero byte. The 16th byte (service suffix) and space padding are dropped;
// n is the number of bytes consumed including the scope.
func decodeNetBIOSName(b []byte) (name string, n int, ok bool) {
	const encodedLen = 32
	if len(b) < 1+encodedLen || b[0] != encodedLen {
		return "", 0, false
	}
	raw := make([]byte, encodedLen/2)
	for i := range raw {
		hi, lo := b[1+2*i]-'A', b[2+2*i]-'A'
		if hi > 0x0f || lo > 0x0f {
			return "", 0, false
		}
		raw[i] = hi<<4 | lo
	}
	n = 1 + encodedLen
	for n < len(b) && b[n] != 0 {
		n += 1 + int(b[n])
	}
	if n >= len(b) {
		return "", 0, false
	}
	n++ // terminating zero label
	return strings.TrimRight(string(raw[:15]), " \x00"), n, true
}
