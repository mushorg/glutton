package firebird

import "encoding/binary"

// Parameter block versions (ibase.h).
const (
	dpbVersion1 = 1
	dpbVersion2 = 2 // Firebird 3+: four-byte lengths
	spbVersion1 = 1
	spbVersion2 = 2 // isc_spb_version, followed by isc_spb_current_version
	spbVersion3 = 3 // Firebird 3+: four-byte lengths
)

// DPB/SPB tags (isc_dpb_*; the SPB attach tags share the values).
const (
	tagUserName      = 28
	tagPassword      = 29
	tagPasswordEnc   = 30
	tagLCCtype       = 48
	tagSQLRoleName   = 60
	tagProcessID     = 71
	tagProcessName   = 74
	tagClientVersion = 80
	tagHostName      = 82
	tagOSUser        = 83
)

// Params holds the attach parameters worth recording. Password is the
// isc_dpb_password as sent, or the isc_dpb_password_enc bytes as sent; both are
// guessing attempts and recorded in full.
type Params struct {
	Username      string
	Password      string
	Role          string
	Charset       string
	ProcessID     uint32
	ProcessName   string
	ClientVersion string
	HostName      string
	OSUser        string
}

// ParseDPB decodes a database parameter block. Unknown versions yield
// empty Params.
func ParseDPB(b []byte) Params {
	if len(b) == 0 {
		return Params{}
	}
	switch b[0] {
	case dpbVersion1:
		return parseClumplets(b[1:], false)
	case dpbVersion2:
		return parseClumplets(b[1:], true)
	}
	return Params{}
}

// ParseSPB decodes a service attach parameter block.
func ParseSPB(b []byte) Params {
	if len(b) == 0 {
		return Params{}
	}
	switch b[0] {
	case spbVersion1:
		return parseClumplets(b[1:], false)
	case spbVersion2:
		if len(b) < 2 {
			return Params{}
		}
		return parseClumplets(b[2:], false)
	case spbVersion3:
		return parseClumplets(b[1:], true)
	}
	return Params{}
}

// parseClumplets walks tag/length/value items; wide items have a four-byte
// little-endian length instead of one byte.
func parseClumplets(b []byte, wide bool) Params {
	var p Params
	lenSize := 1
	if wide {
		lenSize = 4
	}
	for len(b) >= 1+lenSize {
		tag := b[0]
		n := int(b[1])
		if wide {
			n = int(binary.LittleEndian.Uint32(b[1:5]))
		}
		b = b[1+lenSize:]
		if n < 0 || n > len(b) {
			return p
		}
		val := b[:n]
		b = b[n:]
		switch tag {
		case tagUserName:
			p.Username = string(val)
		case tagPassword, tagPasswordEnc:
			p.Password = string(val)
		case tagSQLRoleName:
			p.Role = string(val)
		case tagLCCtype:
			p.Charset = string(val)
		case tagProcessID:
			if len(val) == 4 {
				p.ProcessID = binary.LittleEndian.Uint32(val)
			}
		case tagProcessName:
			p.ProcessName = string(val)
		case tagClientVersion:
			p.ClientVersion = string(val)
		case tagHostName:
			p.HostName = string(val)
		case tagOSUser:
			p.OSUser = string(val)
		}
	}
	return p
}
