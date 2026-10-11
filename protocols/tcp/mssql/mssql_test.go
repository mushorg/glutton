package mssql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/mushorg/glutton/protocols/helpers/ntlm"
	"github.com/stretchr/testify/require"
)

// Nmap ms-sql-ntlm-info PRELOGIN from Ochi event
// 024dea0c-f1a6-418f-b1a0-c2f50b093e1e.
var nmapPrelogin = []byte{
	0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
	0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03, 0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
	0x55, 0x00, 0x00, 0x02, 0x4d, 0x53, 0x53, 0x51, 0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00,
	0x00, 0x00, 0x31, 0x32,
}

// The LOGIN7 from the same event, ServerName swapped for 198.51.100.10 (same
// length): TDS 7.1, integrated auth, NTLMSSP NEGOTIATE in the SSPI field.
var nmapLogin7 = []byte{
	0x10, 0x01, 0x00, 0xc3, 0x00, 0x00, 0x01, 0x00, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x71,
	0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xaa, 0x56, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xa0, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x00, 0x04, 0x00,
	0x5e, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x08, 0x00, 0x6e, 0x00, 0x0d, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x88, 0x00, 0x09, 0x00, 0x9a, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x21, 0x00, 0xbb, 0x00, 0x00, 0x00, 0x4e, 0x00,
	0x6d, 0x00, 0x61, 0x00, 0x70, 0x00, 0x4e, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x70, 0x00, 0x20, 0x00,
	0x4e, 0x00, 0x53, 0x00, 0x45, 0x00, 0x31, 0x00, 0x39, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x35, 0x00,
	0x31, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x30, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x30, 0x00,
	0x6d, 0x00, 0x73, 0x00, 0x73, 0x00, 0x71, 0x00, 0x6c, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x75, 0x00,
	0x61, 0x00, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xb2,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
	0x00, 0x00, 0x2e,
}

func TestReadMessageSinglePacket(t *testing.T) {
	msg, err := ReadMessage(bytes.NewReader(nmapPrelogin), 1024)
	require.NoError(t, err)
	require.Equal(t, byte(TypePrelogin), msg.Type)
	require.Equal(t, nmapPrelogin, msg.Raw)
	require.Equal(t, nmapPrelogin[HeaderLen:], msg.Data)
	require.False(t, msg.Truncated)
}

func TestReadMessageReassembles(t *testing.T) {
	first := []byte{TypeSQLBatch, 0x00, 0x00, 0x0a, 0, 0, 1, 0, 'a', 'b'}
	last := []byte{TypeSQLBatch, 0x01, 0x00, 0x09, 0, 0, 2, 0, 'c'}
	msg, err := ReadMessage(bytes.NewReader(append(append([]byte{}, first...), last...)), 1024)
	require.NoError(t, err)
	require.Equal(t, []byte("abc"), msg.Data)
	require.Len(t, msg.Raw, len(first)+len(last))
}

func TestReadMessageCap(t *testing.T) {
	notLast := []byte{TypeSQLBatch, 0x00, 0x00, 0x0a, 0, 0, 1, 0, 'a', 'b'}
	stream := bytes.Repeat(notLast, 10)
	msg, err := ReadMessage(bytes.NewReader(stream), 25)
	require.NoError(t, err)
	require.True(t, msg.Truncated)
	require.Len(t, msg.Raw, 30)
}

func TestReadMessageErrors(t *testing.T) {
	_, err := ReadMessage(bytes.NewReader([]byte{0x12, 0x01, 0x00, 0x04, 0, 0, 0, 0}), 1024)
	require.ErrorIs(t, err, ErrBadHeader)

	_, err = ReadMessage(bytes.NewReader(nmapPrelogin[:20]), 1024)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	_, err = ReadMessage(bytes.NewReader(nil), 1024)
	require.ErrorIs(t, err, io.EOF)

	mixed := []byte{TypeSQLBatch, 0x00, 0x00, 0x09, 0, 0, 1, 0, 'a', TypeRPC, 0x01, 0x00, 0x09, 0, 0, 2, 0, 'b'}
	_, err = ReadMessage(bytes.NewReader(mixed), 1024)
	require.ErrorIs(t, err, ErrBadHeader)

	_, err = ReadMessage(bytes.NewReader([]byte{TypeSQLBatch, 0x00, 0x00, 0x09, 0, 0, 1, 0, 'a'}), 1024)
	require.True(t, errors.Is(err, io.ErrUnexpectedEOF))
}

func TestLooksLikePrelogin(t *testing.T) {
	require.True(t, LooksLikePrelogin(nmapPrelogin))
	require.True(t, LooksLikePrelogin(nmapPrelogin[:HeaderLen+1]))
	require.False(t, LooksLikePrelogin(nmapPrelogin[:HeaderLen]))
	require.False(t, LooksLikePrelogin(nmapLogin7))
	notLast := append([]byte{}, nmapPrelogin...)
	notLast[1] = 0x00
	require.False(t, LooksLikePrelogin(notLast))
	badOpt := append([]byte{}, nmapPrelogin...)
	badOpt[HeaderLen] = 0x42
	require.False(t, LooksLikePrelogin(badOpt))
	tooShort := []byte{0x12, 0x01, 0x00, 0x09, 0, 0, 0, 0, 0}
	require.False(t, LooksLikePrelogin(tooShort))
}

func TestParsePrelogin(t *testing.T) {
	p, err := ParsePrelogin(nmapPrelogin[HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, Prelogin{
		Version:    "8.0.341.0",
		Encryption: "not_sup",
		Instance:   "MSSQLServer",
		ThreadID:   0x3132,
	}, p)
}

func TestParsePreloginMalformed(t *testing.T) {
	_, err := ParsePrelogin([]byte{0x00, 0x00, 0x05})
	require.Error(t, err)
	_, err = ParsePrelogin([]byte{0x00, 0x00, 0x06, 0x00, 0x06})
	require.Error(t, err, "no terminator")
	// an option pointing past the body is skipped
	p, err := ParsePrelogin([]byte{0x00, 0x00, 0x40, 0x00, 0x06, 0xff})
	require.NoError(t, err)
	require.Empty(t, p.Version)
}

func TestBuildPreloginResponse(t *testing.T) {
	resp := BuildPreloginResponse()
	require.Equal(t, byte(TypeTabular), resp[0])
	require.Equal(t, byte(0x01), resp[1])
	require.Equal(t, len(resp), int(binary.BigEndian.Uint16(resp[2:4])))

	p, err := ParsePrelogin(resp[HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, "15.0.2000.0", p.Version)
	require.Equal(t, "not_sup", p.Encryption)
	require.False(t, p.MARS)
}

func TestParseLogin7Nmap(t *testing.T) {
	l, err := ParseLogin7(nmapLogin7[HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, uint32(0x71000001), l.TDSVersion)
	require.True(t, LegacyTDS(l.TDSVersion))
	require.Equal(t, "0x71000001", TDSVersionString(l.TDSVersion))
	require.Zero(t, l.PacketSize)
	require.Equal(t, uint32(7), l.ClientProgVer)
	require.True(t, l.IntegratedAuth)
	require.Equal(t, "Nmap", l.HostName)
	require.Empty(t, l.UserName)
	require.Empty(t, l.Password)
	require.Equal(t, "Nmap NSE", l.AppName)
	require.Equal(t, "198.51.100.10", l.ServerName)
	require.Equal(t, "mssql.lua", l.ClientInterface)
	require.Empty(t, l.ClientID)
	require.Len(t, l.SSPI, 0x21)
	msg, ok := ntlm.Find(l.SSPI)
	require.True(t, ok)
	require.Equal(t, uint32(ntlm.MsgNegotiate), ntlm.MessageType(msg))
}

// buildLogin7 builds a TDS 7.4 SQL-auth LOGIN7 body.
func buildLogin7(user, password string) []byte {
	fixed := make([]byte, login7ExtLen)
	binary.LittleEndian.PutUint32(fixed[4:], 0x74000004)
	binary.LittleEndian.PutUint32(fixed[8:], 4096)
	copy(fixed[offClientID:], []byte{0x00, 0x0c, 0x29, 0x01, 0x02, 0x03})
	var vars []byte
	put := func(at int, s string, enc func([]byte) []byte) {
		b := ntlm.EncodeUTF16LE(s)
		if enc != nil {
			b = enc(b)
		}
		binary.LittleEndian.PutUint16(fixed[at:], uint16(login7ExtLen+len(vars)))
		binary.LittleEndian.PutUint16(fixed[at+2:], uint16(len(b)/2))
		vars = append(vars, b...)
	}
	scramble := func(b []byte) []byte {
		for i, c := range b {
			b[i] = (c<<4 | c>>4) ^ 0xa5
		}
		return b
	}
	put(offHostName, "WS01", nil)
	put(offUserName, user, nil)
	put(offPassword, password, scramble)
	put(offAppName, "OSQL-32", nil)
	put(offServerName, "198.51.100.10", nil)
	put(offCltIntName, "ODBC", nil)
	put(offLanguage, "", nil)
	put(offDatabase, "master", nil)
	put(offSSPI, "", nil)
	body := append(fixed, vars...)
	binary.LittleEndian.PutUint32(body[0:], uint32(len(body)))
	return body
}

func TestParseLogin7SQLAuth(t *testing.T) {
	l, err := ParseLogin7(buildLogin7("sa", "hunter2"))
	require.NoError(t, err)
	require.False(t, l.IntegratedAuth)
	require.False(t, LegacyTDS(l.TDSVersion))
	require.Equal(t, "sa", l.UserName)
	require.Equal(t, "hunter2", l.Password)
	require.Equal(t, "OSQL-32", l.AppName)
	require.Equal(t, "master", l.Database)
	require.Equal(t, "00:0c:29:01:02:03", l.ClientID)
	require.Nil(t, l.SSPI)
}

func TestParseLogin7Malformed(t *testing.T) {
	_, err := ParseLogin7(nmapLogin7[HeaderLen : HeaderLen+40])
	require.Error(t, err)

	// offsets past the body leave the field empty instead of panicking
	body := append([]byte{}, nmapLogin7[HeaderLen:]...)
	binary.LittleEndian.PutUint16(body[offAppName:], 0xfff0)
	binary.LittleEndian.PutUint16(body[offSSPI:], 0xfff0)
	l, err := ParseLogin7(body)
	require.NoError(t, err)
	require.Empty(t, l.AppName)
	require.Nil(t, l.SSPI)
	require.Equal(t, "Nmap", l.HostName)
}

func TestBuildSSPIChallenge(t *testing.T) {
	l, err := ParseLogin7(nmapLogin7[HeaderLen:])
	require.NoError(t, err)
	opts := ChallengeOptions{
		ServerChallenge: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Computer:        "WIN-ABCDEFGHIJK",
		Domain:          "WORKGROUP",
		Now:             time.Date(2026, 10, 11, 13, 14, 16, 0, time.UTC),
	}
	resp := BuildSSPIChallenge(l.SSPI, opts)
	require.Equal(t, byte(TypeTabular), resp[0])
	require.Equal(t, len(resp), int(binary.BigEndian.Uint16(resp[2:4])))
	require.Equal(t, byte(tokenSSPI), resp[HeaderLen])
	tokLen := int(binary.LittleEndian.Uint16(resp[HeaderLen+1:]))
	challenge := resp[HeaderLen+3:]
	require.Len(t, challenge, tokLen)
	require.Equal(t, uint32(ntlm.MsgChallenge), ntlm.MessageType(challenge))
	require.Equal(t, opts.ServerChallenge, challenge[24:32])
	require.True(t, bytes.Contains(challenge, ntlm.EncodeUTF16LE("WIN-ABCDEFGHIJK")))

	// a SPNEGO blob gets a SPNEGO answer
	spnego := BuildSSPIChallenge(ntlm.NegTokenChallenge(l.SSPI), opts)
	require.Equal(t, byte(0xa1), spnego[HeaderLen+3])

	require.Nil(t, BuildSSPIChallenge(l.SSPI, ChallengeOptions{}))
}

func TestBuildLoginError(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		resp := BuildLoginError(LoginFailed("sa", "WIN-ABCDEFGHIJK", legacy))
		require.Equal(t, byte(TypeTabular), resp[0])
		require.Equal(t, len(resp), int(binary.BigEndian.Uint16(resp[2:4])))
		body := resp[HeaderLen:]
		require.Equal(t, byte(tokenError), body[0])
		errLen := int(binary.LittleEndian.Uint16(body[1:3]))
		tok := body[3 : 3+errLen]
		require.Equal(t, uint32(ErrLoginFailed), binary.LittleEndian.Uint32(tok[0:4]))
		require.Equal(t, []byte{1, 14}, tok[4:6])
		msgChars := int(binary.LittleEndian.Uint16(tok[6:8]))
		require.Equal(t, "Login failed for user 'sa'.", ntlm.DecodeUTF16LE(tok[8:8+msgChars*2]))
		rest := tok[8+msgChars*2:]
		serverChars := int(rest[0])
		require.Equal(t, "WIN-ABCDEFGHIJK", ntlm.DecodeUTF16LE(rest[1:1+serverChars*2]))
		rest = rest[1+serverChars*2:]
		require.Equal(t, byte(0), rest[0], "empty ProcName")
		lineLen, doneLen := 4, 13
		if legacy {
			lineLen, doneLen = 2, 9
		}
		require.Len(t, rest[1:], lineLen)
		done := body[3+errLen:]
		require.Len(t, done, doneLen)
		require.Equal(t, byte(tokenDone), done[0])
		require.Equal(t, uint16(doneError), binary.LittleEndian.Uint16(done[1:3]))
	}
}

func TestTypeName(t *testing.T) {
	require.Equal(t, "login7", TypeName(TypeLogin7))
	require.Equal(t, "type_0x42", TypeName(0x42))
}
