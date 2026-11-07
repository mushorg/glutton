package banners

import (
	"bytes"
	"encoding/binary"
)

// Microsoft Message Queuing binary protocol (MS-MQQB, tcp/1801). Every packet
// starts with a 16-byte BaseHeader: VersionNumber 0x10, Reserved, Flags (LE
// u16), Signature "LIOR", PacketSize (LE u32, the whole packet) and
// TimeToReachQueue. Session setup packets follow it with a 4-byte
// InternalHeader whose Flags low nibble is the packet type. QueueJumper
// (CVE-2023-21554) scanners open with a 572-byte EstablishConnection
// (198.235.24.86, tcp/1801, 2026-11-07); a queue manager answers it with the
// same packet carrying its own QM GUID as ServerGuid, then the client sends
// ConnectionParameters, which the server echoes back. The reply layout follows
// the MS-MQQB spec from memory and is unverified against a live server.

const (
	msmqVersion        = 0x10
	msmqBaseHeaderLen  = 16
	msmqInternalLen    = 4
	msmqEstablishLen   = 572 // headers, ClientGuid, ServerGuid, TimeStamp, Flags, Reserved, 512-byte padding
	msmqConnParamsLen  = 32  // headers, RecoverableAckTimeout, AckTimeout, Reserved, WindowSize
	msmqServerGuidOff  = msmqBaseHeaderLen + msmqInternalLen + 16
	msmqTypeEstablish  = 0x2
	msmqTypeConnParams = 0x3
)

var msmqSignature = []byte("LIOR")

// msmqServerGUID is the persona's queue manager GUID (wire byte order).
var msmqServerGUID = mustHex("8f1c2e4a7b3d594ca6e2d10f3b7c9e51")

// msmqPacketType returns the InternalHeader packet type of data when it is
// one whole MSMQ session packet (PacketSize equal to len(data)).
func msmqPacketType(data []byte) (uint16, bool) {
	if len(data) < msmqBaseHeaderLen+msmqInternalLen || data[0] != msmqVersion ||
		!bytes.Equal(data[4:8], msmqSignature) ||
		int(binary.LittleEndian.Uint32(data[8:12])) != len(data) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(data[18:20]) & 0xf, true
}

// msmqReply answers EstablishConnection and ConnectionParameters on any port.
func msmqReply(data []byte) (Response, bool) {
	typ, ok := msmqPacketType(data)
	if !ok {
		return Response{}, false
	}
	switch {
	case typ == msmqTypeEstablish && len(data) == msmqEstablishLen:
		reply := bytes.Clone(data)
		copy(reply[msmqServerGuidOff:], msmqServerGUID)
		return Response{Name: "msmq-establish", Data: reply}, true
	case typ == msmqTypeConnParams && len(data) == msmqConnParamsLen:
		return Response{Name: "msmq-connection-parameters", Data: bytes.Clone(data)}, true
	}
	return Response{}, false
}
