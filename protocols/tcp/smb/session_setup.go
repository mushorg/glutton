package smb

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Trans2SetupName returns a stable name for a TRANS2 Setup word.
func Trans2SetupName(setup uint16) string {
	switch setup {
	case trans2FindFirst2:
		return "TRANS2_FIND_FIRST2"
	case trans2SessionSetup:
		return "TRANS2_SESSION_SETUP"
	default:
		return fmt.Sprintf("0x%04x", setup)
	}
}

// SessionSetupFields holds client identity strings from Session Setup AndX
// (password / NTLM blob bytes are not copied).
type SessionSetupFields struct {
	Account      string
	NativeOS     string
	NativeLanMan string
}

// SessionSetupIdentity extracts account and Native OS/LanMan from an SMB1
// Session Setup AndX request body (after the 32-byte header).
func SessionSetupIdentity(header SMBHeader, body []byte) SessionSetupFields {
	if len(body) < 1 {
		return SessionSetupFields{}
	}
	wc := int(body[0])
	unicode := flags2(header)&flags2Unicode != 0
	var off int
	switch wc {
	case 13:
		const fixed = 1 + 12*2 + 2
		if len(body) < 19 {
			return SessionSetupFields{}
		}
		oemLen := int(binary.LittleEndian.Uint16(body[15:17]))
		uniLen := int(binary.LittleEndian.Uint16(body[17:19]))
		off = fixed + oemLen + uniLen
	case 12:
		const fixed = 1 + 11*2 + 2
		if len(body) < 17 {
			return SessionSetupFields{}
		}
		blobLen := int(binary.LittleEndian.Uint16(body[15:17]))
		off = fixed + blobLen
	default:
		return SessionSetupFields{}
	}
	if off > len(body) {
		return SessionSetupFields{}
	}
	strs := readSessionSetupStrings(body, off, unicode)
	return assignSessionSetupStrings(strs, wc == 12)
}

func readSessionSetupStrings(body []byte, off int, unicode bool) []string {
	try := func(start int) []string {
		o := start
		var out []string
		for i := 0; i < 4 && o < len(body); i++ {
			if unicode && (32+o)%2 != 0 && o < len(body) {
				o++
			}
			if o >= len(body) {
				break
			}
			var s string
			var n int
			if unicode {
				s, n = decodeUnicodeString(body[o:])
			} else {
				s, n = decodeOEMString(body[o:])
			}
			if n == 0 {
				break
			}
			o += n
			out = append(out, s)
		}
		return out
	}
	best := try(off)
	alt := try(off + 1)
	if scoreIdentity(alt) > scoreIdentity(best) {
		return alt
	}
	return best
}

func scoreIdentity(strs []string) int {
	n := 0
	for _, s := range strs {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	return n
}

func assignSessionSetupStrings(strs []string, extended bool) SessionSetupFields {
	var f SessionSetupFields
	if extended {
		if len(strs) >= 1 {
			f.NativeOS = strs[0]
		}
		if len(strs) >= 2 {
			f.NativeLanMan = strs[1]
		}
		return f
	}
	if len(strs) >= 1 {
		f.Account = strs[0]
	}
	if len(strs) >= 3 {
		f.NativeOS = strs[2]
	}
	if len(strs) >= 4 {
		f.NativeLanMan = strs[3]
	} else if len(strs) == 2 {
		f.NativeOS = strs[0]
		f.NativeLanMan = strs[1]
		f.Account = ""
	}
	return f
}
