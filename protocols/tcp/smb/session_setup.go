package smb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

// SessionSetupFields holds client identity strings from Session Setup AndX.
// For a basic (WordCount 13) request, Password is the plaintext guess when
// the client sent one; LM/NTLM challenge responses are kept as hex in
// LMResponse / NTLMResponse instead.
type SessionSetupFields struct {
	Account      string
	Password     string
	LMResponse   string
	NTLMResponse string
	NativeOS     string
	NativeLanMan string
}

// ntlmResponseLen is the size of an LM, NTLMv1 or LMv2 challenge response.
const ntlmResponseLen = 24

// isNTLMv2Response reports whether b looks like an NTLMv2 response: a 16-byte
// NTProofStr followed by a blob starting with RespType=1, HiRespType=1.
func isNTLMv2Response(b []byte) bool {
	return len(b) > ntlmResponseLen && bytes.Equal(b[16:20], []byte{0x01, 0x01, 0x00, 0x00})
}

// sessionSetupPasswords classifies the OEM (case-insensitive) and Unicode
// (case-sensitive) password fields of a basic Session Setup AndX request.
// 24-byte fields and NTLMv2 blobs are challenge responses; anything else is a
// plaintext password.
func sessionSetupPasswords(oem, uni []byte, unicode bool) (password, lm, nt string) {
	hashed := len(oem) == ntlmResponseLen || len(uni) == ntlmResponseLen || isNTLMv2Response(uni)
	if hashed {
		if len(oem) > 0 {
			lm = hex.EncodeToString(oem)
		}
		if len(uni) > 0 {
			nt = hex.EncodeToString(uni)
		}
		return "", lm, nt
	}
	if len(uni) > 0 {
		password, _ = decodeUnicodeString(uni)
		if password != "" {
			return password, "", ""
		}
	}
	if len(oem) > 0 {
		if unicode && len(oem)%2 == 0 && len(oem) >= 2 && oem[1] == 0 {
			password, _ = decodeUnicodeString(oem)
		} else {
			password, _ = decodeOEMString(oem)
		}
	}
	return password, "", ""
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
	var password, lm, nt string
	switch wc {
	case 13:
		const fixed = 1 + 13*2 + 2
		if len(body) < 19 {
			return SessionSetupFields{}
		}
		oemLen := int(binary.LittleEndian.Uint16(body[15:17]))
		uniLen := int(binary.LittleEndian.Uint16(body[17:19]))
		off = fixed + oemLen + uniLen
		if off <= len(body) {
			password, lm, nt = sessionSetupPasswords(body[fixed:fixed+oemLen], body[fixed+oemLen:off], unicode)
		}
	case 12:
		const fixed = 1 + 12*2 + 2
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
	f := assignSessionSetupStrings(strs, wc == 12)
	f.Password, f.LMResponse, f.NTLMResponse = password, lm, nt
	return f
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
