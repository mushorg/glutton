package rdp

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func processRawCR(raw string, t *testing.T) ConnectionRequestPDU {
	data, _ := hex.DecodeString(raw)
	pdu, err := ParseCRPDU(data)
	if err != nil {
		t.Error(err)
	}
	return pdu
}

func TestRDPParseHeader1(t *testing.T) {
	raw := "0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000"
	pdu := processRawCR(raw, t)
	if string(pdu.Data) != "Cookie: mstshash=hello" {
		fmt.Printf("%q\n", string(pdu.Data))
		t.Error("Infalid data field")
	}
	fmt.Printf("Parsed data: %+v\n", pdu)
}

func TestRDPParseHeader2(t *testing.T) {
	raw := "0300001f1ae00000000000436f6f6b69653a206d737473686173683d610d0a"
	pdu := processRawCR(raw, t)
	if string(pdu.Data) != "Cookie: mstshash=a" {
		fmt.Printf("%q\n", string(pdu.Data))
		t.Error("Infalid data field")
	}
	fmt.Printf("Parsed data: %+v\n", pdu)
}

func TestConnectionConfirm(t *testing.T) {
	cc := ConnectionConfirm()
	fmt.Printf("Parsed data: %+v\n", cc)
}

/*
   |e: mstshash=a..|
*/
