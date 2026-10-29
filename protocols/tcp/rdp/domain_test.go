package rdp

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// MCS Connect-Initial from ochi.mushmush.org/events/b4baa7aa-2d18-4e6e-83db-847c038a993e.
var mcsConnectInitialFixture = mustHex("0300019c02f0807f658201900401010401010101ff30190201220201020201000201010201000201010202ffff020102301902010102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff0201020482012f000500147c00018126000800100001c00044756361811801c0d400040008000005200301ca03aa09080000280a000045004d0050002d004c00410050002d003000300031003400000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca010000000000100007000100370036003400380037002d004f0045004d002d0030003000310031003900300033002d0030003000310030003700000000000000000000000000000000000000000004c00c00090000000000000002c00c00100000000000000003c02c0003000000726470647200000000008080636c6970726472000000a0c0726470736e640000000000c0")

func TestParseClientData(t *testing.T) {
	cd := ParseClientData(mcsConnectInitialFixture)
	require.NotNil(t, cd)
	require.Equal(t, ClientData{
		ClientName:        "EMP-LAP-0014",
		ClientBuild:       2600,
		DesktopWidth:      1280,
		DesktopHeight:     800,
		KeyboardLayout:    0x0809,
		HighColorDepth:    16,
		EncryptionMethods: 0x10,
		Channels:          []string{"rdpdr", "cliprdr", "rdpsnd"},
	}, *cd)
}

func TestParseClientDataMalformed(t *testing.T) {
	require.Nil(t, ParseClientData(nil))
	require.Nil(t, ParseClientData([]byte("Duca")))
	// Block length larger than the data must not panic or read past it.
	require.Nil(t, ParseClientData(append([]byte("Duca\x08"), 0x01, 0xc0, 0xff, 0x00, 0, 0, 0, 0)))
	// Truncated fixture keeps whatever complete blocks there are.
	cut := mcsConnectInitialFixture[:len(mcsConnectInitialFixture)-60]
	cd := ParseClientData(cut)
	require.NotNil(t, cd)
	require.Equal(t, "EMP-LAP-0014", cd.ClientName)
	require.Empty(t, cd.Channels)
}

func TestMCSConnectResponseChannels(t *testing.T) {
	_, resp := MCSConnectResponse(ProtocolSSL, 3)
	// SC_NET: type, length 16, I/O 1003, count 3, IDs 1004-1006, pad.
	require.Contains(t, string(resp), string(mustHex("030c1000eb030300ec03ed03ee030000")))
	require.Equal(t, len(resp), int(binary.BigEndian.Uint16(resp[2:4])))

	_, resp = MCSConnectResponse(ProtocolSSL, 2)
	require.Contains(t, string(resp), string(mustHex("030c0c00eb030200ec03ed03")))
}

func TestMCSDomainPDUs(t *testing.T) {
	erect := mustHex("0300000c02f0800401000100")
	attach := mustHex("0300000802f08028")
	join := mustHex("0300000c02f08038000603ef")
	require.Equal(t, CmdErectDomainRequest, FrameCommand(erect))
	require.Equal(t, CmdAttachUserRequest, FrameCommand(attach))
	require.Equal(t, CmdChannelJoinRequest, FrameCommand(join))
	require.Equal(t, CmdMCSConnectInitial, FrameCommand(mcsConnectInitialFixture))
	require.Equal(t, CmdX224Data, FrameCommand(mustHex("0300000802f080ff")))

	initiator, channel, ok := ChannelJoinRequest(join)
	require.True(t, ok)
	require.Equal(t, uint16(6), initiator)
	require.Equal(t, uint16(1007), channel)
	_, _, ok = ChannelJoinRequest(attach)
	require.False(t, ok)

	// MS-RDPBCGR 4.1.7 and 4.1.9.
	_, auc := AttachUserConfirm()
	require.Equal(t, mustHex("0300000b02f0802e000006"), auc)
	_, cjc := ChannelJoinConfirm(6, 1007)
	require.Equal(t, mustHex("0300000f02f0803e00000603ef03ef"), cjc)
	require.Equal(t, CmdChannelJoinConfirm, FrameCommand(cjc))
}

func TestServerDenySequence(t *testing.T) {
	// MS-RDPBCGR 4.1.12: License Error PDU, valid client.
	_, lic := LicenseValidClient()
	require.Equal(t, mustHex("0300002202f08068000103eb701480000000ff031000070000000200000004000000"), lic)

	_, ei := SetErrorInfo(ErrInfoServerDeniedConnection)
	require.Equal(t, mustHex("0300002402f08068000103eb7016"), ei[:14])
	share := ei[14:]
	require.Len(t, share, 22)
	require.Equal(t, uint16(22), binary.LittleEndian.Uint16(share[0:2]))
	require.Equal(t, uint16(0x17), binary.LittleEndian.Uint16(share[2:4]))
	require.Equal(t, byte(0x2f), share[14])
	require.Equal(t, uint32(7), binary.LittleEndian.Uint32(share[18:22]))

	_, dpu := DisconnectProviderUltimatum()
	require.Equal(t, mustHex("0300000902f0802180"), dpu)
	require.Equal(t, CmdDisconnectProviderUltimatum, FrameCommand(dpu))
}

func TestSplitTPKT(t *testing.T) {
	erect := mustHex("0300000c02f0800401000100")
	attach := mustHex("0300000802f08028")

	pdus, rest := SplitTPKT(append(append([]byte{}, erect...), attach...))
	require.Equal(t, [][]byte{erect, attach}, pdus)
	require.Empty(t, rest)

	pdus, rest = SplitTPKT(append(append([]byte{}, erect...), attach[:5]...))
	require.Equal(t, [][]byte{erect}, pdus)
	require.Equal(t, attach[:5], rest)

	pdus, rest = SplitTPKT([]byte{0x03, 0x00})
	require.Empty(t, pdus)
	require.Equal(t, []byte{0x03, 0x00}, rest)

	junk := []byte("GET / HTTP/1.1\r\n\r\n")
	pdus, rest = SplitTPKT(junk)
	require.Equal(t, [][]byte{junk}, pdus)
	require.Empty(t, rest)
}

// clientInfoPayload builds Send Data user data: a basic security header with
// SEC_INFO_PKT and a Unicode TS_INFO_PACKET with extended info.
func clientInfoPayload(domain, user, password string) []byte {
	enc := func(s string) []byte { return utf16LE(s) }
	fields := [][]byte{enc(domain), enc(user), enc(password), enc(""), enc("")}
	b := []byte{0x40, 0x00, 0x00, 0x00}
	hdr := make([]byte, 18)
	binary.LittleEndian.PutUint32(hdr[4:8], infoUnicode|infoAutologon)
	for i, f := range fields {
		binary.LittleEndian.PutUint16(hdr[8+2*i:], uint16(len(f)))
	}
	b = append(b, hdr...)
	for _, f := range fields {
		b = append(append(b, f...), 0, 0)
	}
	addr := append(enc("10.0.0.5"), 0, 0)
	dir := append(enc(`C:\Windows\System32\mstscax.dll`), 0, 0)
	b = binary.LittleEndian.AppendUint16(b, 2)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(addr)))
	b = append(b, addr...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(dir)))
	return append(b, dir...)
}

func TestParseClientInfo(t *testing.T) {
	ci, ok := ParseClientInfo(clientInfoPayload("CORP", "administrator", "Winter2024!"))
	require.True(t, ok)
	require.Equal(t, ClientInfo{
		Domain:        "CORP",
		Username:      "administrator",
		Password:      "Winter2024!",
		ClientAddress: "10.0.0.5",
		ClientDir:     `C:\Windows\System32\mstscax.dll`,
		Autologon:     true,
	}, ci)
	js, err := json.Marshal(ci)
	require.NoError(t, err)
	require.Contains(t, string(js), `"password":"Winter2024!"`)
}

func TestParseClientInfoANSI(t *testing.T) {
	b := []byte{0x40, 0x00, 0x00, 0x00}
	hdr := make([]byte, 18)
	binary.LittleEndian.PutUint16(hdr[10:12], 4) // cbUserName
	binary.LittleEndian.PutUint16(hdr[12:14], 3) // cbPassword
	b = append(b, hdr...)
	b = append(b, 0)                     // domain
	b = append(b, []byte("root\x00")...) // user
	b = append(b, []byte("abc\x00")...)  // password
	b = append(b, 0, 0)                  // shell, dir
	ci, ok := ParseClientInfo(b)
	require.True(t, ok)
	require.Equal(t, ClientInfo{Username: "root", Password: "abc"}, ci)
}

func TestParseClientInfoEdgeCases(t *testing.T) {
	_, ok := ParseClientInfo(nil)
	require.False(t, ok)
	_, ok = ParseClientInfo([]byte{0x01, 0x00, 0x00, 0x00, 0xaa})
	require.False(t, ok, "security exchange is not client info")

	ci, ok := ParseClientInfo([]byte{0x48, 0x00, 0x00, 0x00, 0xde, 0xad})
	require.True(t, ok)
	require.Equal(t, ClientInfo{Encrypted: true}, ci)

	// Truncated after the username: keep what was complete.
	full := clientInfoPayload("", "guest", "pw")
	ci, ok = ParseClientInfo(full[:4+18+2+12])
	require.True(t, ok)
	require.Equal(t, "guest", ci.Username)
	require.Empty(t, ci.Password)
}

func TestParseCredSSPNTLMVersion(t *testing.T) {
	msg := make([]byte, 64)
	copy(msg, ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:12], NTLMMsgAuthenticate)
	for _, tc := range []struct {
		ntLen uint16
		want  string
	}{{0, "anonymous"}, {24, "NTLMv1"}, {300, "NTLMv2"}, {10, ""}} {
		binary.LittleEndian.PutUint16(msg[20:22], tc.ntLen)
		require.Equal(t, tc.want, ParseCredSSP(WrapTSRequest(msg)).NTLMVersion)
	}
}

// MCS Connect-Initial and Client Info PDU from a TLS brute-forcer that writes
// ASCII "FREERDP" into the UTF-16 clientName field and sends a China Standard
// Time zone block (ochi.mushmush.org/events/d4bd8b39-9804-4efd-89b9-a84a8f7548b8).
var (
	asciiNameConnectInitialFixture = mustHex("0300016c02f0807f658201600401010401010101ff301a020122020102020100020101020100020101020300ffff020102301a02010102010102010102010102010002010102020420020102301c020300ffff020300fc04020300ffff020101020100020101020300ffff0201020481fb000500147c000180f2000801310001c0044475636180e401c0d800040008000005000401ca03aa09040000ce0e0000465245455244500000000000000000000000000000000000000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca0100000000001800070021000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007000100000002c00c000000000000000000")
	tzClientInfoFixture            = mustHex("0300015102f08064000603eb7081424000000000000000fb43030000000a000c00000000000000410064006d0069006e0000003900380037003600350034000000000000000200100030002e0030002e0030002e0030000000400043003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c006d007300740073006300610078002e0064006c006c00000020feffff2d4efd560768c651f665f495000064006c006c002c002d003500370032000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002d4efd560f59e44ef66500002e0064006c006c002c002d003500370031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4ffffff00000000000000000000")
)

func TestParseClientDataASCIIName(t *testing.T) {
	cd := ParseClientData(asciiNameConnectInitialFixture)
	require.NotNil(t, cd)
	require.Equal(t, ClientData{
		ClientName:     "FREERDP",
		ClientNameANSI: true,
		ClientBuild:    3790,
		DesktopWidth:   1280,
		DesktopHeight:  1024,
		KeyboardLayout: 0x0409,
		HighColorDepth: 24,
	}, *cd)
}

func TestIsANSIName(t *testing.T) {
	name := func(b []byte) []byte { return append(b, make([]byte, 32-len(b))...) }
	require.True(t, isANSIName(name([]byte("FREERDP"))))
	require.True(t, isANSIName(name([]byte("WORK"))))
	require.False(t, isANSIName(name(utf16LE("EMP-LAP-0014"))))
	require.False(t, isANSIName(name(utf16LE("Ä"))), "one-unit UTF-16 name")
	require.False(t, isANSIName(name(nil)))
	require.False(t, isANSIName(name([]byte{0xc4, 0x80, 0x41})), "non-printable bytes stay UTF-16")
}

func TestParseClientInfoTimeZone(t *testing.T) {
	ch, payload, ok := SendDataRequest(tzClientInfoFixture)
	require.True(t, ok)
	require.Equal(t, uint16(1003), ch)
	ci, ok := ParseClientInfo(payload)
	require.True(t, ok)
	bias := int32(-480)
	require.Equal(t, ClientInfo{
		Username:       "Admin",
		Password:       "987654",
		ClientAddress:  "0.0.0.0",
		ClientDir:      `C:\Windows\System32\mstscax.dll`,
		Autologon:      true,
		TZBias:         &bias,
		TZStandardName: "中国标准时间",
		TZDaylightName: "中国夏令时",
	}, ci)
	js, err := json.Marshal(ci)
	require.NoError(t, err)
	require.Contains(t, string(js), `"tz_bias":-480`)

	// Time zone cut short: the earlier fields stay, no partial time zone.
	ci, ok = ParseClientInfo(payload[:len(payload)-100])
	require.True(t, ok)
	require.Equal(t, "Admin", ci.Username)
	require.Equal(t, "987654", ci.Password)
	require.Equal(t, `C:\Windows\System32\mstscax.dll`, ci.ClientDir)
	require.Nil(t, ci.TZBias)
	require.Empty(t, ci.TZStandardName)
}

func TestParseClientInfoUTCTimeZone(t *testing.T) {
	b := clientInfoPayload("", "u", "p")
	tz := make([]byte, timeZoneInfoLen)
	copy(tz[4:], utf16LE("UTC"))
	ci, ok := ParseClientInfo(append(b, tz...))
	require.True(t, ok)
	require.NotNil(t, ci.TZBias, "bias 0 is still reported")
	require.Equal(t, int32(0), *ci.TZBias)
	require.Equal(t, "UTC", ci.TZStandardName)
	require.Empty(t, ci.TZDaylightName)
}
