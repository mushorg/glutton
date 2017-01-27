package rdp

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRDPParseHeader(t *testing.T) {
	raw := "0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000"
	data, _ := hex.DecodeString(raw)
	pdu, err := ParseCRPDU(data)
	if err != nil {
		t.Error(err)
	}
	if string(pdu.Data) != "Cookie: mstshash=hello\r\n" {
		fmt.Printf("%q", string(pdu.Data))
		t.Error("Infalid data field")
	}
	fmt.Printf("Parsed data:\n%+v\n", pdu)
}

/*
00000000  03 00 00 1f 1a e0 00 00  00 00 00 43 6f 6f 6b 69  |...........Cooki|
00000010  65 3a 20 6d 73 74 73 68  61 73 68 3d 61 0d 0a     |e: mstshash=a..|
*/
