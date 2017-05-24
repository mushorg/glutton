package smb

import (
	"bytes"
	"encoding/hex"
	"testing"
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
	buffer, err := ValidateData(data)
	if err != nil {
		t.Error(err)
	}
	header := SMBHeader{}
	err = ParseHeader(buffer, &header)
	if err != nil {
		t.Error(err)
	}
	parsed, err := ParseNegotiateProtocolRequest(buffer, header)
	if string(parsed.Header.Protocol[1:]) != "SMB" {
		if err != nil {
			t.Error(err)
		}
		t.Errorf("Protocol doesn't match 'SMB': %+v\n", parsed.Header.Protocol)
	}
	dialectString := bytes.Split(parsed.Data.DialectString, []byte("\x00"))
	if string(dialectString[0][:]) != "PC NETWORK PROGRAM 1.0" {
		t.Errorf("Dialect String mismatch: %s", string(dialectString[0][:]))
	}
	_, err = MakeNegotiateProtocolResponse(header)
	if err != nil {
		t.Error(err)
	}
}
