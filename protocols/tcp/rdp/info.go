package rdp

import (
	"encoding/binary"
)

// ClientInfo is what the client sent in its Client Info PDU (TS_INFO_PACKET,
// MS-RDPBCGR 2.2.1.11.1.1). The password itself is never kept: only its
// length in characters.
type ClientInfo struct {
	Domain         string `json:"domain,omitempty"`
	Username       string `json:"username,omitempty"`
	PasswordLen    int    `json:"password_len,omitempty"`
	AlternateShell string `json:"alternate_shell,omitempty"`
	WorkingDir     string `json:"working_dir,omitempty"`
	ClientAddress  string `json:"client_address,omitempty"`
	ClientDir      string `json:"client_dir,omitempty"`
	Autologon      bool   `json:"autologon,omitempty"`
	Encrypted      bool   `json:"encrypted,omitempty"`
}

// ParseClientInfo parses Send Data user data that starts with a basic
// security header flagged SEC_INFO_PKT. ok is false when the flag is unset.
// When the client encrypted the packet (standard RDP security), only
// Encrypted is set.
func ParseClientInfo(payload []byte) (ci ClientInfo, ok bool) {
	flags := SecurityFlags(payload)
	if flags&secInfoPkt == 0 {
		return ci, false
	}
	if flags&secEncrypt != 0 {
		ci.Encrypted = true
		return ci, true
	}
	b := payload[4:]
	if len(b) < 18 {
		return ci, true
	}
	infoFlags := binary.LittleEndian.Uint32(b[4:8])
	ci.Autologon = infoFlags&infoAutologon != 0
	unicode := infoFlags&infoUnicode != 0
	nul := 1
	if unicode {
		nul = 2
	}
	var cb [5]int
	for i := range cb {
		cb[i] = int(binary.LittleEndian.Uint16(b[8+2*i:]))
	}
	off := 18
	field := func(n int) ([]byte, bool) {
		end := off + n + nul
		if end > len(b) {
			return nil, false
		}
		v := b[off : off+n]
		off = end
		return v, true
	}
	str := func(v []byte) string {
		if unicode {
			return decodeUTF16Z(v)
		}
		return decodeANSIZ(v)
	}

	v, more := field(cb[0])
	ci.Domain = str(v)
	if more {
		v, more = field(cb[1])
		ci.Username = str(v)
	}
	if more {
		_, more = field(cb[2])
		if more {
			ci.PasswordLen = cb[2]
			if unicode {
				ci.PasswordLen /= 2
			}
		}
	}
	if more {
		v, more = field(cb[3])
		ci.AlternateShell = str(v)
	}
	if more {
		v, more = field(cb[4])
		ci.WorkingDir = str(v)
	}
	if !more {
		return ci, true
	}

	// TS_EXTENDED_INFO_PACKET: family(2), cbClientAddress(2), address,
	// cbClientDir(2), dir. Both strings are UTF-16LE and include the NUL.
	ext := b[off:]
	if len(ext) < 4 {
		return ci, true
	}
	n := int(binary.LittleEndian.Uint16(ext[2:4]))
	if 4+n > len(ext) {
		return ci, true
	}
	ci.ClientAddress = decodeUTF16Z(ext[4 : 4+n])
	ext = ext[4+n:]
	if len(ext) < 2 {
		return ci, true
	}
	n = int(binary.LittleEndian.Uint16(ext[0:2]))
	if 2+n > len(ext) {
		return ci, true
	}
	ci.ClientDir = decodeUTF16Z(ext[2 : 2+n])
	return ci, true
}

func decodeANSIZ(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
