package smb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
00000000  00 00 00 85 ff 53 4d 42  72 00 00 00 00 18 53 c8  |.....SMBr.....S.|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 ff fe  |................|
00000020  00 00 00 00 00 62 00 02  50 43 20 4e 45 54 57 4f  |.....b..PC NETWO|
00000030  52 4b 20 50 52 4f 47 52  41 4d 20 31 2e 30 00 02  |RK PROGRAM 1.0..|
00000040  4c 41 4e 4d 41 4e 31 2e  30 00 02 57 69 6e 64 6f  |LANMAN1.0..Windo|
00000050  77 73 20 66 6f 72 20 57  6f 72 6b 67 72 6f 75 70  |ws for Workgroup|
00000060  73 20 33 2e 31 61 00 02  4c 4d 31 2e 32 58 30 30  |s 3.1a..LM1.2X00|
00000070  32 00 02 4c 41 4e 4d 41  4e 32 2e 31 00 02 4e 54  |2..LANMAN2.1..NT|
00000080  20 4c 4d 20 30 2e 31 32  00                       | LM 0.12.|
*/

func TestParseSMB(t *testing.T) {
	raw := "00000085ff534d4272000000001853c80000000000000000000000000000fffe00000000006200025043204e4554574f524b" +
		"2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e31610" +
		"0024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200"
	data, _ := hex.DecodeString(raw)

	require.Equal(t, 0, FrameOffset(data))

	buffer, err := ValidateData(data)
	require.NoError(t, err)

	header := SMBHeader{}
	err = ParseHeader(buffer, &header)
	require.NoError(t, err)

	parsed, err := ParseNegotiateProtocolRequest(buffer, header)
	require.NoError(t, err)
	require.Equal(t, string(parsed.Header.Protocol[1:]), "SMB")

	dialectString := bytes.Split(parsed.Data.DialectString, []byte("\x00"))
	require.Equal(t, string(dialectString[0][:]), "\x02PC NETWORK PROGRAM 1.0", "dialect string mismatch")
	require.Equal(t, uint16(5), DialectIndex(parsed.Data.DialectString, "NT LM 0.12"))
}

func TestValidateDataRequiresSMBMagic(t *testing.T) {
	_, err := ValidateData([]byte{0xff, 0x00, 0x01})
	require.Error(t, err)

	buf, err := ValidateData([]byte{0x00, 0x00, 0x00, 0x04, 0xff, 'S', 'M', 'B'})
	require.NoError(t, err)
	require.Equal(t, []byte{0xff, 'S', 'M', 'B'}, buf.Bytes())
	require.Equal(t, 0, FrameOffset([]byte{0x00, 0x00, 0x00, 0x04, 0xff, 'S', 'M', 'B'}))
}

func TestWrapSessionMessage(t *testing.T) {
	pdu := []byte{0xff, 'S', 'M', 'B', 0x72}
	framed := WrapSessionMessage(pdu)
	require.Equal(t, byte(0x00), framed[0])
	require.Equal(t, []byte{0x00, 0x00, 0x05}, framed[1:4])
	require.Equal(t, pdu, framed[4:])
}

func TestMakeResponses(t *testing.T) {
	req := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x72,
		Flags:    0x18,
		Flags2:   [2]byte{0x53, 0xc8},
		PIDLow:   [2]byte{0xff, 0xfe},
		MID:      [2]byte{0x40, 0x00},
	}

	tests := []struct {
		name string
		cmd  byte
		run  func(SMBHeader) (SMBHeader, []byte, error)
	}{
		{name: "MakeHeaderResponse", cmd: 0x72, run: MakeHeaderResponse},
		{name: "MakeNegotiateProtocolResponse", cmd: 0x72, run: func(h SMBHeader) (SMBHeader, []byte, error) {
			return MakeNegotiateProtocolResponse(h, nil)
		}},
		{name: "MakeSessionSetupAndXResponse", cmd: 0x73, run: func(h SMBHeader) (SMBHeader, []byte, error) {
			return MakeSessionSetupAndXResponse(h, 1)
		}},
		{name: "MakeTreeConnectAndXResponse", cmd: 0x75, run: func(h SMBHeader) (SMBHeader, []byte, error) {
			return MakeTreeConnectAndXResponse(h, 1, "C$")
		}},
		{name: "MakeNtCreateAndXResponse", cmd: CmdNtCreateAndX, run: func(h SMBHeader) (SMBHeader, []byte, error) {
			return MakeNtCreateAndXResponse(h, 1)
		}},
		{name: "MakeComTransaction2Response", cmd: 0x32, run: MakeComTransaction2Response},
		{name: "MakeComTransactionResponse", cmd: 0x25, run: MakeComTransactionResponse},
		{name: "MakeComTransaction2Error", cmd: 0x32, run: MakeComTransaction2Error},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := req
			h.Command = test.cmd
			responseHeader, data, err := test.run(h)
			require.NoError(t, err)
			require.NotEmpty(t, data)
			require.Equal(t, byte(0xff), data[0])
			require.Equal(t, "SMB", string(data[1:4]))
			require.True(t, responseHeader.Flags&flagsReply != 0, "reply flag must be set")
			require.Equal(t, test.cmd, responseHeader.Command)
		})
	}
}

func TestMakeNegotiateSelectsNTLM(t *testing.T) {
	dialects := []byte("\x02PC NETWORK PROGRAM 1.0\x00\x02NT LM 0.12\x00")
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x72,
		Flags:    0x18,
		Flags2:   [2]byte{0x03, 0xc0}, // Unicode + NT status
	}
	rh, data, err := MakeNegotiateProtocolResponse(header, dialects)
	require.NoError(t, err)
	require.Equal(t, byte(0x72), rh.Command)
	require.True(t, rh.Flags&flagsReply != 0)
	require.GreaterOrEqual(t, len(data), 32+1+2)
	require.Equal(t, byte(17), data[32])                                 // WordCount
	require.Equal(t, uint16(1), binary.LittleEndian.Uint16(data[33:35])) // dialect index of NT LM 0.12
	require.NotContains(t, string(data), "GLUTTON")
	// Server NetBIOS name is UTF-16LE "SERVER".
	require.Contains(t, string(data), string(encodeString(serverName, true)))
}

func TestReplyHeaderClearsExtendedSecurity(t *testing.T) {
	// Flags2 0xc853 includes Unicode, NT status, and EXTENDED_SECURITY (0x0800).
	req := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x74, // LOGOFF_ANDX
		Flags:    0x18,
		Flags2:   [2]byte{0x53, 0xc8},
		MID:      [2]byte{0x01, 0x00},
	}
	rh, data, err := MakeHeaderResponse(req)
	require.NoError(t, err)
	f2 := binary.LittleEndian.Uint16(rh.Flags2[:])
	require.Equal(t, uint16(0), f2&flags2ExtendedSecurity, "EXTENDED_SECURITY must be cleared")
	require.NotEqual(t, uint16(0), f2&flags2NTStatus, "NT status bit must stay set")
	require.Equal(t, f2, binary.LittleEndian.Uint16(data[10:12]))
	require.Equal(t, byte(0x74), rh.Command)
	require.Equal(t, []byte{0x00, 0x00, 0x00}, data[32:35]) // WordCount=0, ByteCount=0
}

func TestMakeNegotiateUTF16AndFlags2(t *testing.T) {
	// Client advertises EXTENDED_SECURITY; negotiate must clear it and force Unicode
	// Domain/Server names (nmap smb.lua always UTF-16-decodes them).
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x72,
		Flags:    0x18,
		Flags2:   [2]byte{0x53, 0xc8}, // 0xc853
	}
	rh, data, err := MakeNegotiateProtocolResponse(header, []byte("\x02NT LM 0.12\x00"))
	require.NoError(t, err)
	f2 := binary.LittleEndian.Uint16(rh.Flags2[:])
	require.Equal(t, uint16(0), f2&flags2ExtendedSecurity)
	require.NotEqual(t, uint16(0), f2&flags2Unicode)
	require.Equal(t, f2, binary.LittleEndian.Uint16(data[10:12]))

	domainUTF16 := encodeString(primaryDomain, true)
	serverUTF16 := encodeString(serverName, true)
	require.Contains(t, string(data), string(domainUTF16))
	require.Contains(t, string(data), string(serverUTF16))
	// Must not appear as OEM (NUL-terminated ASCII) after the challenge.
	require.NotContains(t, string(data), primaryDomain+"\x00"+serverName+"\x00")
}

func TestMakeSessionSetupAssignsUID(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x73,
		Flags:    0x18,
		Flags2:   [2]byte{0x03, 0xc0},
	}
	rh, data, err := MakeSessionSetupAndXResponse(header, 0x41)
	require.NoError(t, err)
	require.Equal(t, uint16(0x41), binary.LittleEndian.Uint16(rh.UID[:]))
	require.Equal(t, []byte{0x41, 0x00}, data[28:30])
	require.Equal(t, byte(3), data[32]) // WordCount
}

func TestMakeTreeConnectAssignsTID(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x75,
		Flags:    0x18,
		Flags2:   [2]byte{0x03, 0xc0},
		UID:      [2]byte{0x41, 0x00},
	}
	rh, data, err := MakeTreeConnectAndXResponse(header, 0x08, "C$")
	require.NoError(t, err)
	require.Equal(t, uint16(0x08), binary.LittleEndian.Uint16(rh.TID[:]))
	require.Equal(t, []byte{0x08, 0x00}, data[24:26])
	require.Equal(t, byte(3), data[32])
	require.Contains(t, string(data[32:]), "A:")
	require.Contains(t, string(data[32:]), "N\x00T\x00F\x00S\x00")
}

func TestMakeTreeConnectIPC(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x75,
		Flags:    0x18,
		Flags2:   [2]byte{0x03, 0xc0},
		UID:      [2]byte{0x01, 0x00},
	}
	rh, data, err := MakeTreeConnectAndXResponse(header, 0x01, "ipc$")
	require.NoError(t, err)
	require.Equal(t, uint16(0x01), binary.LittleEndian.Uint16(rh.TID[:]))
	require.Equal(t, byte(3), data[32])
	body := data[32:]
	require.Contains(t, string(body), "IPC\x00")
	require.NotContains(t, string(body), "A:")
	require.NotContains(t, string(body), "N\x00T\x00F\x00S\x00")
	// Service "IPC\0" then empty Unicode NativeFileSystem ("\0\0").
	require.True(t, bytes.Contains(body, []byte("IPC\x00\x00\x00")))
}

func TestTreeConnectShareFromEvent(t *testing.T) {
	// Tree Connect AndX from ochi event ebd8306b: \\192.168.56.20\IPC$
	raw, err := hex.DecodeString(
		"0000005cff534d4275000000001807c0" +
			"0000000000000000000000000000fffe" +
			"0100400004ff005c00080001003100" +
			"005c005c003100390032002e0031003600" +
			"38002e00350036002e00320030005c00" +
			"490050004300240000003f3f3f3f3f00")
	require.NoError(t, err)

	buf, err := ValidateData(raw)
	require.NoError(t, err)
	header := SMBHeader{}
	require.NoError(t, ParseHeader(buf, &header))
	share := TreeConnectShare(header, buf.Bytes())
	require.Equal(t, "IPC$", share)
	require.True(t, IsIPCShare(share))
}

func TestTrans2SetupSessionSetup(t *testing.T) {
	// Trans2 with Setup 0x000e (TRANS2_SESSION_SETUP) from ochi event ebd8306b.
	raw, err := hex.DecodeString(
		"0000004eff534d4232000000001807c0" +
			"0000000000000000000000000100fffe" +
			"010041000f0c00000001000000000000" +
			"000134ee0000000c00420000004e0001" +
			"000e000d0000000000000000000000000000")
	require.NoError(t, err)

	buf, err := ValidateData(raw)
	require.NoError(t, err)
	header := SMBHeader{}
	require.NoError(t, ParseHeader(buf, &header))
	setup, ok := Trans2Setup(buf.Bytes())
	require.True(t, ok)
	require.Equal(t, uint16(Trans2SessionSetup), setup)

	rh, data, err := MakeComTransaction2Reply(header, setup, ok)
	require.NoError(t, err)
	require.Equal(t, uint32(statusNotImplemented), binary.LittleEndian.Uint32(rh.Status[:]))
	require.Equal(t, byte(0x00), data[32])           // WordCount 0 error body
	require.NotContains(t, string(data), "\x2e\x00") // no FIND_FIRST2 "." entry
}

func TestMakeComTransaction2FindFirst2(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x32,
		Flags:    0x18,
		Flags2:   [2]byte{0x03, 0xc0},
	}
	rh, data, err := MakeComTransaction2Reply(header, Trans2FindFirst2, true)
	require.NoError(t, err)
	require.Equal(t, [4]byte{0, 0, 0, 0}, rh.Status)
	require.Equal(t, byte(0x0A), data[32]) // WordCount of FIND_FIRST2 success
}

func TestMakeNtCreateAndXResponse(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  CmdNtCreateAndX,
		Flags:    0x18,
		Flags2:   [2]byte{0x01, 0x48},
		TID:      [2]byte{0x01, 0x00},
		PIDLow:   [2]byte{0x6c, 0x15},
		UID:      [2]byte{0x01, 0x00},
		MID:      [2]byte{0x00, 0x00},
	}
	rh, data, err := MakeNtCreateAndXResponse(header, 0x0041)
	require.NoError(t, err)
	require.Equal(t, [4]byte{}, rh.Status)
	require.Equal(t, byte(CmdNtCreateAndX), rh.Command)
	require.Equal(t, header.TID, rh.TID)
	require.Equal(t, header.UID, rh.UID)
	require.Equal(t, header.MID, rh.MID)
	require.Equal(t, header.PIDLow, rh.PIDLow)
	require.Equal(t, byte(0x98), rh.Flags)
	require.Equal(t, 32+1+34*2+2, len(data))
	require.Equal(t, byte(34), data[32])
	require.Equal(t, byte(0xff), data[33]) // AndX none
	require.Equal(t, uint16(0x0041), binary.LittleEndian.Uint16(data[38:40]))
	require.Equal(t, uint32(fileOpened), binary.LittleEndian.Uint32(data[40:44]))
	require.Equal(t, uint16(fileTypeMessagePipe), binary.LittleEndian.Uint16(data[96:98]))
	require.Equal(t, []byte{0x00, 0x00}, data[len(data)-2:])
	require.Equal(t, "SMB_COM_NT_CREATE_ANDX", CommandName(CmdNtCreateAndX))
}

func TestNtCreateAndXNameFromEvent(t *testing.T) {
	// NT Create AndX \svcctl from ochi event be40479e (OEM, pysmb).
	raw, err := hex.DecodeString(
		"0000005bff534d42a200000000180148" +
			"00000000000000000000000001006c15" +
			"0100000018ff00000000070016000000" +
			"00000000030000000000000000000000" +
			"80000000010000000100000040000000" +
			"020000000008005c73766363746c00")
	require.NoError(t, err)

	buf, err := ValidateData(raw)
	require.NoError(t, err)
	header := SMBHeader{}
	require.NoError(t, ParseHeader(buf, &header))
	require.Equal(t, byte(CmdNtCreateAndX), header.Command)
	require.Equal(t, `\svcctl`, NtCreateAndXName(header, buf.Bytes()))
}

func TestMakeComTransactionResponseMS17010(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x25,
		Flags:    0x18,
		TID:      [2]byte{0x00, 0x08},
		UID:      [2]byte{0x01, 0x00},
		MID:      [2]byte{0x01, 0x00},
	}

	responseHeader, data, err := MakeComTransactionResponse(header)
	require.NoError(t, err)
	require.Equal(t, statusInsuffServerResources, responseHeader.Status)
	require.Equal(t, byte(0x98), responseHeader.Flags) // request flags | reply
	require.Equal(t, header.Command, responseHeader.Command)
	require.Equal(t, header.TID, responseHeader.TID)
	require.Equal(t, header.UID, responseHeader.UID)
	require.Equal(t, header.MID, responseHeader.MID)

	// Error-style body: WordCount=0, ByteCount=0 after the 32-byte SMB header.
	require.GreaterOrEqual(t, len(data), 35)
	require.Equal(t, byte(0x00), data[32])
	require.Equal(t, []byte{0x00, 0x00}, data[33:35])
	require.Equal(t, statusInsuffServerResources[:], data[5:9])
}

func TestMakeComTransaction2SetsReplyFlag(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x32,
		Flags:    0x18,
		UID:      [2]byte{0x01, 0x00},
		MID:      [2]byte{0x41, 0x00},
	}
	rh, data, err := MakeComTransaction2Response(header)
	require.NoError(t, err)
	require.Equal(t, byte(0x98), rh.Flags)
	require.Equal(t, byte(0x98), data[9])
}

func TestMakeComNtTransactionResponse(t *testing.T) {
	header := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  CmdNtTransact,
		Flags:    0x18,
		TID:      [2]byte{0x01, 0x00},
		UID:      [2]byte{0x01, 0x00},
		MID:      [2]byte{0x02, 0x00},
	}
	rh, data, err := MakeComNtTransactionResponse(header)
	require.NoError(t, err)
	require.Equal(t, [4]byte{}, rh.Status)
	require.Equal(t, byte(CmdNtTransact), rh.Command)
	require.Equal(t, byte(0x98), rh.Flags)
	require.GreaterOrEqual(t, len(data), 32+1+18*2+2)
	require.Equal(t, byte(18), data[32])
	require.Equal(t, []byte{0x00, 0x00}, data[len(data)-2:])
}

func TestMakeSMB2ReplyNegotiate(t *testing.T) {
	req := make([]byte, 64)
	req[0] = 0xfe
	copy(req[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(req[4:6], 64)
	name, pdu, ok := MakeSMB2Reply(req)
	require.True(t, ok)
	require.Equal(t, "SMB2_NEGOTIATE", name)
	require.GreaterOrEqual(t, len(pdu), 64+64)
	require.Equal(t, byte(0xfe), pdu[0])
	require.Equal(t, uint32(1), binary.LittleEndian.Uint32(pdu[16:20])&1)
	require.Equal(t, uint16(0x0202), binary.LittleEndian.Uint16(pdu[64+4:64+6]))
}

func TestMakeSMB2ReplyTooShort(t *testing.T) {
	_, _, ok := MakeSMB2Reply([]byte{0xfe, 'S', 'M', 'B'})
	require.False(t, ok)
}
