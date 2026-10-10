package rdp

import (
	"encoding/binary"
)

const (
	mcsConnectInitialTag  = 0x65 // BER APPLICATION 101
	mcsConnectResponseTag = 0x66 // BER APPLICATION 102
)

// IsMCSConnectInitial reports X.224 DT carrying BER APPLICATION 101 (7f 65).
func IsMCSConnectInitial(data []byte) bool {
	if !IsDataTPDU(data) {
		return false
	}
	mcs := x224UserData(data)
	return len(mcs) >= 2 && mcs[0] == 0x7f && mcs[1] == mcsConnectInitialTag
}

func x224UserData(data []byte) []byte {
	if len(data) < 5 {
		return nil
	}
	off := 5 + int(data[4])
	if off > len(data) {
		return nil
	}
	return data[off:]
}

func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func wrapX224DT(payload []byte) ([]byte, TKIPHeader) {
	total := 7 + len(payload)
	out := make([]byte, total)
	out[0] = 3
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[4] = 2
	out[5] = TPDUData
	out[6] = 0x80
	copy(out[7:], payload)
	return out, ParseTKIPHeader(out)
}

// MCSConnectResponse builds a minimal MCS Connect-Response (APPLICATION 102)
// with GCC Conference Create Response (H.221 key "McDn"), SC_CORE, SC_NET, and
// SC_SECURITY with no encryption. It is enough for probes to accept the PDU;
// it is not a full capability exchange. selected is the protocol chosen in the
// Connection Confirm, echoed in SC_CORE clientRequestedProtocols. channels is
// the number of static channels the client asked for in CS_NET; SC_NET assigns
// each one an ID from 1004 so clients go on to join them.
func MCSConnectResponse(selected uint32, channels int) (TKIPHeader, []byte) {
	// TS_UD_SC_CORE (0x0c01), length 16: version 0x00080004, then
	// clientRequestedProtocols.
	scCore := []byte{0x01, 0x0c, 0x10, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(scCore[8:12], selected)
	// TS_UD_SC_NET (0x0c03): I/O channel 1003, then one ID per static
	// channel, padded to a multiple of four bytes.
	if channels < 0 || channels > maxClientChannels {
		channels = 0
	}
	netLen := 8 + 2*channels + 2*(channels%2)
	scNet := make([]byte, netLen)
	binary.LittleEndian.PutUint16(scNet[0:2], 0x0c03)
	binary.LittleEndian.PutUint16(scNet[2:4], uint16(netLen))
	binary.LittleEndian.PutUint16(scNet[4:6], mcsIOChannel)
	binary.LittleEndian.PutUint16(scNet[6:8], uint16(channels))
	for i := 0; i < channels; i++ {
		binary.LittleEndian.PutUint16(scNet[8+2*i:], uint16(mcsIOChannel+1+i))
	}
	// TS_UD_SC_SEC1 (0x0c02): ENCRYPTION_METHOD_NONE / ENCRYPTION_LEVEL_NONE.
	scSec := []byte{0x02, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	blocks := append(append(append([]byte{}, scCore...), scNet...), scSec...)

	// PER-aligned GCC Conference Create Response prefix from MS-RDPBCGR 4.1.4,
	// then "McDn" and the concatenated server data blocks.
	gccBody := []byte{0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00, 0x00, 0x4d, 0x63, 0x44, 0x6e}
	gccBody = append(gccBody, berLength(len(blocks))...)
	gccBody = append(gccBody, blocks...)

	gcc := []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00}
	gcc = append(gcc, berLength(len(gccBody))...)
	gcc = append(gcc, gccBody...)

	domainParams := []byte{
		0x30, 0x19,
		0x02, 0x01, 0x22, // maxChannelIds 34
		0x02, 0x01, 0x02, // maxUserIds 2
		0x02, 0x01, 0x00, // maxTokenIds 0
		0x02, 0x01, 0x01, // numPriorities 1
		0x02, 0x01, 0x00, // minThroughput 0
		0x02, 0x01, 0x01, // maxHeight 1
		0x02, 0x02, 0xff, 0xff, // maxMCSPDUSize
		0x02, 0x01, 0x02, // protocolVersion 2
	}

	inner := []byte{0x0a, 0x01, 0x00, 0x02, 0x01, 0x00}
	inner = append(inner, domainParams...)
	inner = append(inner, 0x04)
	inner = append(inner, berLength(len(gcc))...)
	inner = append(inner, gcc...)

	mcs := []byte{0x7f, mcsConnectResponseTag}
	mcs = append(mcs, berLength(len(inner))...)
	mcs = append(mcs, inner...)
	out, header := wrapX224DT(mcs)
	return header, out
}
