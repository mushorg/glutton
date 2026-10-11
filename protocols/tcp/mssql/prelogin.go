package mssql

import (
	"encoding/binary"
	"fmt"
)

// PRELOGIN option tokens (MS-TDS 2.2.6.5).
const (
	optVersion    = 0x00
	optEncryption = 0x01
	optInstOpt    = 0x02
	optThreadID   = 0x03
	optMARS       = 0x04
	optTraceID    = 0x05
	optFedAuth    = 0x06
	optNonce      = 0x07
	optTerminator = 0xff
)

// ENCRYPTION option values.
const (
	EncryptOff    = 0x00
	EncryptOn     = 0x01
	EncryptNotSup = 0x02
	EncryptReq    = 0x03
)

var encryptionNames = map[byte]string{
	EncryptOff:    "off",
	EncryptOn:     "on",
	EncryptNotSup: "not_sup",
	EncryptReq:    "req",
}

// Prelogin holds the client PRELOGIN options a scanner fingerprint is made of.
type Prelogin struct {
	// Version is the client's major.minor.build.subbuild.
	Version    string
	Encryption string
	Instance   string
	ThreadID   uint32
	MARS       bool
	FedAuth    bool
}

// ParsePrelogin reads the option table of a PRELOGIN message body. Options
// that point outside the body are skipped.
func ParsePrelogin(data []byte) (Prelogin, error) {
	var p Prelogin
	for i := 0; ; i += 5 {
		if i >= len(data) {
			return p, fmt.Errorf("PRELOGIN option table has no terminator")
		}
		token := data[i]
		if token == optTerminator {
			return p, nil
		}
		if i+5 > len(data) {
			return p, fmt.Errorf("PRELOGIN option %d is truncated", token)
		}
		off := int(binary.BigEndian.Uint16(data[i+1 : i+3]))
		n := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
		if off+n > len(data) {
			continue
		}
		v := data[off : off+n]
		switch token {
		case optVersion:
			if n >= 6 {
				p.Version = fmt.Sprintf("%d.%d.%d.%d", v[0], v[1],
					binary.BigEndian.Uint16(v[2:4]), binary.BigEndian.Uint16(v[4:6]))
			}
		case optEncryption:
			if n >= 1 {
				if name, ok := encryptionNames[v[0]]; ok {
					p.Encryption = name
				} else {
					p.Encryption = fmt.Sprintf("0x%02x", v[0])
				}
			}
		case optInstOpt:
			p.Instance = cString(v)
		case optThreadID:
			if n >= 4 {
				p.ThreadID = binary.BigEndian.Uint32(v[:4])
			}
		case optMARS:
			p.MARS = n >= 1 && v[0] == 1
		case optFedAuth:
			p.FedAuth = n >= 1 && v[0] == 1
		}
	}
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ServerVersion is the PRELOGIN VERSION the server reports: SQL Server 2019
// RTM (15.0.2000), matching the Windows Server 2019 build in the NTLM
// CHALLENGE VERSION block.
var ServerVersion = [6]byte{0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00}

// BuildPreloginResponse builds the server PRELOGIN reply. Encryption is
// ENCRYPT_NOT_SUP so the client sends LOGIN7 in the clear.
func BuildPreloginResponse() []byte {
	type option struct {
		token byte
		value []byte
	}
	opts := []option{
		{optVersion, ServerVersion[:]},
		{optEncryption, []byte{EncryptNotSup}},
		{optInstOpt, []byte{0x00}},
		{optThreadID, nil},
		{optMARS, []byte{0x00}},
	}
	off := len(opts)*5 + 1
	var table, values []byte
	for _, o := range opts {
		table = append(table, o.token)
		table = binary.BigEndian.AppendUint16(table, uint16(off+len(values)))
		table = binary.BigEndian.AppendUint16(table, uint16(len(o.value)))
		values = append(values, o.value...)
	}
	table = append(table, optTerminator)
	return packet(TypeTabular, append(table, values...))
}
