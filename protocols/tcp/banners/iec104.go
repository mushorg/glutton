package banners

// IEC 60870-5-104 (tcp/2404) APCI U-format frames (IEC 60870-5-104 §5.1):
// start byte 0x68, APDU length 4, then four control octets of which the first
// carries one function bit pair and the rest are zero. A controlled station
// answers each *_act with the matching *_con, which is all a scanner needs to
// see a live RTU (Shodan sends a bare TESTFR act). I-format frames (general
// interrogation and other ASDUs) need session state and are not answered here.

const (
	iec104Start     = 0x68
	iec104ULength   = 4
	iec104FrameSize = 2 + iec104ULength
)

// iec104UFrames maps a U-format act control octet to its name and the
// control octet of the confirmation.
var iec104UFrames = map[byte]struct {
	name string
	con  byte
}{
	0x07: {"startdt", 0x0b},
	0x13: {"stopdt", 0x23},
	0x43: {"testfr", 0x83},
}

// iec104Confirmations are U-format con control octets a client may send back
// (a TESTFR con answering the station's keep-alive); they need no reply.
var iec104Confirmations = map[byte]bool{0x0b: true, 0x23: true, 0x83: true}

// iec104Reply answers a read made only of complete U-format frames (several
// may be pipelined) with one confirmation per act frame. A read holding only
// confirmations is recorded without a reply.
func iec104Reply(data []byte) (Response, bool) {
	if len(data) == 0 || len(data)%iec104FrameSize != 0 {
		return Response{}, false
	}
	var reply []byte
	name := ""
	for i := 0; i < len(data); i += iec104FrameSize {
		f := data[i : i+iec104FrameSize]
		if f[0] != iec104Start || f[1] != iec104ULength || f[3]|f[4]|f[5] != 0 {
			return Response{}, false
		}
		if u, ok := iec104UFrames[f[2]]; ok {
			if name == "" {
				name = "iec104-" + u.name
			}
			reply = append(reply, iec104Start, iec104ULength, u.con, 0, 0, 0)
			continue
		}
		if !iec104Confirmations[f[2]] {
			return Response{}, false
		}
	}
	if reply == nil {
		return Response{Name: "iec104", NoReply: true}, true
	}
	return Response{Name: name, Data: reply}, true
}
