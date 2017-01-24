package rdp

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRDPParseHeader(t *testing.T) {
	raw := "0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000"
	data, _ := hex.DecodeString(raw)
	pdu, err := ParsePDU(data)
	if err != nil {
		t.Error(err)
	}
	if string(pdu.Data) != "Cookie: mstshash=hello\r\n" {
		fmt.Printf("%q", string(pdu.Data))
		t.Error("Infalid data field")
	}
	fmt.Printf("Parsed data:\n%+v\n", pdu)
}
