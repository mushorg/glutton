package smb

import (
	"fmt"

	"github.com/mushorg/glutton/protocols/helpers/netbios"
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
	called, _, n, ok := netbios.Decode(body)
	if !ok {
		return "", "", false
	}
	calling, _, _, ok = netbios.Decode(body[n:])
	if !ok {
		return "", "", false
	}
	return called, calling, true
}

// PeekLen is how many client bytes LooksLikeSMB needs: the 4-byte NBSS header
// plus the SMB magic, or the first byte of a session request's called name.
const PeekLen = 8

// LooksLikeSMB reports whether b opens an SMB conversation on any port: a
// session message whose body starts with \xffSMB (SMB1) or \xfeSMB (SMB2),
// or an NBSS session request (port 139 style) whose called name is a
// first-level encoded NetBIOS name.
func LooksLikeSMB(b []byte) bool {
	if len(b) < PeekLen || b[1]&^0x01 != 0 {
		return false
	}
	length := int(b[1]&0x01)<<16 | int(b[2])<<8 | int(b[3])
	switch b[0] {
	case NBSSSessionMessage:
		switch {
		case b[4] == 0xff && string(b[5:8]) == "SMB":
			return length >= 32
		case b[4] == 0xfe && string(b[5:8]) == "SMB":
			return length >= 64
		}
	case NBSSSessionRequest:
		return b[4] == 0x20 && length >= 34
	}
	return false
}
