package banners

import "bytes"

// Mitsubishi MELSEC-Q PLCs answer a 41-byte CPU model read over the
// MELSOFT/GX Developer protocol (subheader 57 00) on their Ethernet ports
// (5006/5007 by default). The query is the one Digital Bond's Redpoint
// melsecq-discover script sends; Censys sends the same bytes to other ports
// (tcp/2103, run-1794266574-2.jsonl event #1). The script checks that the reply
// starts with d7 and reads the CPU model as a NUL-terminated string at offset
// 42, cut to 16 characters. The bytes between the subheader and the model are
// a guess (the query's header echoed, with the LE u16 length at offset 19
// covering everything after offset 21), as no live capture was available.

var melsecCPUInfoQuery = mustHex("57000000001111070000ffff030000fe03000014001c080a0800000000000000040101010000000001")

const (
	melsecLenOff   = 19
	melsecBodyOff  = 21
	melsecModelOff = 42
	melsecModelLen = 16
)

// melsecCPUModel is a Q-series universal model CPU with built-in Ethernet,
// space-padded to 16 characters as the CPU reports it.
var melsecCPUModel = "Q03UDECPU"

func isMelsecCPUInfoQuery(data []byte) bool {
	return bytes.Equal(data, melsecCPUInfoQuery)
}

// melsecCPUInfo builds the CPU model read reply for model.
func melsecCPUInfo(model string) []byte {
	// header, model, then a zero model code that also ends the string
	reply := make([]byte, melsecModelOff+melsecModelLen+2)
	// the 41-byte query echoed, then a zero end code at offset 41
	copy(reply, melsecCPUInfoQuery)
	reply[0] = 0xd7
	n := len(reply) - melsecBodyOff
	reply[melsecLenOff], reply[melsecLenOff+1] = byte(n), byte(n>>8)
	name := bytes.Repeat([]byte(" "), melsecModelLen)
	copy(name, model)
	copy(reply[melsecModelOff:], name)
	return reply
}

func melsecReply(data []byte) (Response, bool) {
	if !isMelsecCPUInfoQuery(data) {
		return Response{}, false
	}
	return Response{Name: "melsec-cpuinfo", Data: melsecCPUInfo(melsecCPUModel)}, true
}
