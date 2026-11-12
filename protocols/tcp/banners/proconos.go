package banners

import "bytes"

// KW-Software ProConOS (the PLC runtime in Phoenix Contact ILC controllers)
// listens on tcp/20547. Digital Bond's Redpoint proconos-info script, and the
// nmap `proconos` probe, send the 10-byte info request below (seen from
// 148.153.189.62 on tcp/20547, run-1794169144-1.jsonl event #8). The reply is
// shaped after nmap's match line:
//
//	match proconos m|^\xcc\x01...\x02\x92\0V\d+\.\d+ProConOS V([\d.]+) \w\w\w +\d+ \d+\0+\0([^\0]+)\0+([^\0]+)\0+([^\0]+)\0+([^\0]+)...|s
//	    p/ProConOS/ v/$1/ i|PLC: $2; project: $3/$4; source: $5|
//
// The ladder logic runtime sits at offset 12, the PLC type at offset 44 and
// the project name at offset 77, then the boot project and the project source
// flag as the NUL-terminated strings that follow. Bytes 2-4
// (the length byte at offset 3 and the 0x40 beside it echo the request) are a
// guess, as no live capture was available.

var proconosInfoRequest = mustHex("cc01000b4002000047ee")

const (
	proconosRuntimeOff = 12
	proconosPLCOff     = 44
	proconosProjectOff = 77
)

var (
	proconosRuntime       = "ProConOS V3.0.1040 Oct 29 2002"
	proconosPLCType       = "ILC 350 ETH"
	proconosProject       = "MAINPRO"
	proconosBootProject   = "MAINPRO"
	proconosProjectSource = "Exist"
)

// proconosInfo builds the info reply nmap and proconos-info parse.
func proconosInfo() []byte {
	reply := make([]byte, proconosProjectOff)
	copy(reply, []byte{0xcc, 0x01, 0x00, 0x00, 0x40, 0x02, 0x92, 0x00})
	copy(reply[8:], "V3.0")
	copy(reply[proconosRuntimeOff:], proconosRuntime)
	copy(reply[proconosPLCOff:], proconosPLCType)
	for _, s := range []string{proconosProject, proconosBootProject, proconosProjectSource} {
		reply = append(reply, s...)
		reply = append(reply, 0)
	}
	reply[3] = byte(len(reply))
	return reply
}

func proconosReply(data []byte) (Response, bool) {
	if !bytes.Equal(data, proconosInfoRequest) {
		return Response{}, false
	}
	return Response{Name: "proconos-info", Data: proconosInfo()}, true
}
