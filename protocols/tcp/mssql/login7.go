package mssql

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/mushorg/glutton/protocols/helpers/ntlm"
)

// LOGIN7 layout (MS-TDS 2.2.6.4): a fixed header, then an offset/length
// table whose offsets are relative to the start of the LOGIN7 body.
const (
	login7MinLen     = 86 // TDS 7.1: through ibAtchDBFile/cchAtchDBFile
	login7ExtLen     = 94 // TDS 7.2+: adds ibChangePassword and cbSSPILong
	offHostName      = 36
	offUserName      = 40
	offPassword      = 44
	offAppName       = 48
	offServerName    = 52
	offCltIntName    = 60
	offLanguage      = 64
	offDatabase      = 68
	offClientID      = 72
	offSSPI          = 78
	offCbSSPILong    = 90
	optionFlags2     = 25
	fIntSecurity     = 0x80
	tdsVersion72     = 0x72090002
	sspiLongSentinel = 0xffff
)

// Login7 holds the LOGIN7 fields the handler records. The password is never
// decoded; PasswordSet only says whether the client sent one.
type Login7 struct {
	TDSVersion      uint32
	PacketSize      uint32
	ClientProgVer   uint32
	ClientPID       uint32
	ClientLCID      uint32
	IntegratedAuth  bool
	HostName        string
	UserName        string
	PasswordSet     bool
	AppName         string
	ServerName      string
	ClientInterface string
	Language        string
	Database        string
	ClientID        string
	SSPI            []byte
}

// ParseLogin7 parses a LOGIN7 message body. Fields whose offset/length point
// outside the body are left empty.
func ParseLogin7(data []byte) (Login7, error) {
	if len(data) < login7MinLen {
		return Login7{}, fmt.Errorf("LOGIN7 too short: %d bytes", len(data))
	}
	le := binary.LittleEndian
	l := Login7{
		TDSVersion:     le.Uint32(data[4:8]),
		PacketSize:     le.Uint32(data[8:12]),
		ClientProgVer:  le.Uint32(data[12:16]),
		ClientPID:      le.Uint32(data[16:20]),
		ClientLCID:     le.Uint32(data[32:36]),
		IntegratedAuth: data[optionFlags2]&fIntSecurity != 0,
	}
	l.HostName = utf16Field(data, offHostName)
	l.UserName = utf16Field(data, offUserName)
	_, pwLen := field(data, offPassword)
	l.PasswordSet = pwLen > 0
	l.AppName = utf16Field(data, offAppName)
	l.ServerName = utf16Field(data, offServerName)
	l.ClientInterface = utf16Field(data, offCltIntName)
	l.Language = utf16Field(data, offLanguage)
	l.Database = utf16Field(data, offDatabase)
	if mac := data[offClientID : offClientID+6]; !allZero(mac) {
		l.ClientID = net.HardwareAddr(mac).String()
	}

	sspiOff := int(le.Uint16(data[offSSPI:]))
	sspiLen := int(le.Uint16(data[offSSPI+2:]))
	if sspiLen == sspiLongSentinel && len(data) >= login7ExtLen && l.TDSVersion >= tdsVersion72 {
		sspiLen = int(le.Uint32(data[offCbSSPILong:]))
	}
	if sspiLen > 0 && sspiOff+sspiLen <= len(data) {
		l.SSPI = append([]byte(nil), data[sspiOff:sspiOff+sspiLen]...)
	}
	return l, nil
}

// TDSVersionString formats a LOGIN7 TDSVersion as MS-TDS lists it.
func TDSVersionString(v uint32) string {
	return fmt.Sprintf("0x%08x", v)
}

// LegacyTDS reports whether v predates TDS 7.2, which widened DONE row counts
// and ERROR line numbers.
func LegacyTDS(v uint32) bool {
	return v < tdsVersion72
}

// field returns the byte offset and character count at an offset/length pair,
// or 0, 0 when it does not fit in data.
func field(data []byte, at int) (off, chars int) {
	off = int(binary.LittleEndian.Uint16(data[at:]))
	chars = int(binary.LittleEndian.Uint16(data[at+2:]))
	if chars == 0 || off+chars*2 > len(data) {
		return 0, 0
	}
	return off, chars
}

func utf16Field(data []byte, at int) string {
	off, chars := field(data, at)
	if chars == 0 {
		return ""
	}
	return ntlm.DecodeUTF16LE(data[off : off+chars*2])
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
