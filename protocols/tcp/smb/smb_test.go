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
			return MakeTreeConnectAndXResponse(h, 1)
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
	rh, data, err := MakeTreeConnectAndXResponse(header, 0x08)
	require.NoError(t, err)
	require.Equal(t, uint16(0x08), binary.LittleEndian.Uint16(rh.TID[:]))
	require.Equal(t, []byte{0x08, 0x00}, data[24:26])
	require.Equal(t, byte(3), data[32])
	require.Contains(t, string(data[32:]), "A:")
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
