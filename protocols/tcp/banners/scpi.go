package banners

import "bytes"

// Test and measurement instruments expose SCPI (IEEE 488.2 commands over a
// raw socket) on tcp/5025, the port Keysight, Rohde & Schwarz and Tektronix
// use. Scanners send the identification query "*IDN?\n" and the instrument
// answers one line: manufacturer, model, serial number and firmware revision,
// comma-separated and LF-terminated (IEEE 488.2 §10.14). Commands that are not
// queries get no reply, so the port keeps the connection open without
// answering.

// scpiIdentity is a Keysight 34465A Truevolt digital multimeter. The four
// fields follow IEEE 488.2; the serial number ("MY" + digits) and firmware
// revision formats are from memory and unverified against a live unit.
var scpiIdentity = []byte("Keysight Technologies,34465A,MY57502461,A.03.01-03.15-03.01-00.52-03-02\n")

// isSCPIIdentify reports whether data is the bare "*IDN?" query (SCPI
// mnemonics are case-insensitive), optionally followed by CR/LF.
func isSCPIIdentify(data []byte) bool {
	return bytes.EqualFold(bytes.TrimRight(data, "\r\n"), []byte("*IDN?"))
}

// scpiReply answers "*IDN?" with the instrument identity line.
func scpiReply(data []byte) (Response, bool) {
	if !isSCPIIdentify(data) {
		return Response{}, false
	}
	return Response{Name: "scpi-idn", Data: scpiIdentity}, true
}
