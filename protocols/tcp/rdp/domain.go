package rdp

import (
	"encoding/binary"
)

// MCS domain PDU choices (T.125 DomainMCSPDU), PER-encoded in the top six
// bits of the first byte.
const (
	mcsErectDomainRequest          = 1
	mcsDisconnectProviderUltimatum = 8
	mcsAttachUserRequest           = 10
	mcsAttachUserConfirm           = 11
	mcsChannelJoinRequest          = 14
	mcsChannelJoinConfirm          = 15
	mcsSendDataRequest             = 25
	mcsSendDataIndication          = 26

	// Server-side MCS initiator for Send Data Indication (user 1002 - 1001)
	// and the I/O channel announced in SC_NET.
	mcsServerInitiator = 0x0001
	mcsIOChannel       = 1003
	// mcsUserInitiator is handed out in Attach User Confirm (user channel 1007),
	// as in MS-RDPBCGR 4.1.7.
	mcsUserInitiator = 0x0006

	// Basic security header flags (MS-RDPBCGR 2.2.8.1.1.2.1).
	secExchangePkt = 0x0001
	secEncrypt     = 0x0008
	secInfoPkt     = 0x0040
	secLicensePkt  = 0x0080

	// TS_INFO_PACKET flags (MS-RDPBCGR 2.2.1.11.1.1).
	infoAutologon = 0x00000008
	infoUnicode   = 0x00000010

	// ErrInfoServerDeniedConnection is sent in the Set Error Info PDU after the
	// Client Info PDU (MS-RDPBCGR 2.2.5.1.1).
	ErrInfoServerDeniedConnection uint32 = 0x00000007
)

const (
	CmdErectDomainRequest          = "ErectDomainRequest"
	CmdAttachUserRequest           = "AttachUserRequest"
	CmdAttachUserConfirm           = "AttachUserConfirm"
	CmdChannelJoinRequest          = "ChannelJoinRequest"
	CmdChannelJoinConfirm          = "ChannelJoinConfirm"
	CmdSendDataRequest             = "SendDataRequest"
	CmdSecurityExchange            = "SecurityExchange"
	CmdClientInfo                  = "ClientInfo"
	CmdLicenseErrorAlert           = "LicenseErrorAlert"
	CmdSetErrorInfo                = "SetErrorInfo"
	CmdDisconnectProviderUltimatum = "DisconnectProviderUltimatum"
	CmdX224Data                    = "X224Data"

	StatusValidClient            = "STATUS_VALID_CLIENT"
	StatusServerDeniedConnection = "ERRINFO_SERVER_DENIED_CONNECTION"
)

// MCSDomainType returns the DomainMCSPDU choice of an X.224 DT, or -1 when
// data is not a DT or carries a BER Connect PDU instead.
func MCSDomainType(data []byte) int {
	if !IsDataTPDU(data) {
		return -1
	}
	mcs := x224UserData(data)
	if len(mcs) == 0 || mcs[0] == 0x7f {
		return -1
	}
	return int(mcs[0] >> 2)
}

// ChannelJoinRequest returns the initiator and channel ID of an MCS Channel
// Join Request (MS-RDPBCGR 2.2.1.8).
func ChannelJoinRequest(data []byte) (initiator, channel uint16, ok bool) {
	if MCSDomainType(data) != mcsChannelJoinRequest {
		return 0, 0, false
	}
	mcs := x224UserData(data)
	if len(mcs) < 5 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(mcs[1:3]), binary.BigEndian.Uint16(mcs[3:5]), true
}

// SendDataRequest returns the channel and user data of an MCS Send Data
// Request (T.125 SendDataRequest, MS-RDPBCGR 2.2.1.11). The data is cut to
// what was received when the PER length claims more.
func SendDataRequest(data []byte) (channel uint16, payload []byte, ok bool) {
	if MCSDomainType(data) != mcsSendDataRequest {
		return 0, nil, false
	}
	mcs := x224UserData(data)
	// choice, initiator(2), channelId(2), dataPriority+segmentation(1), length
	if len(mcs) < 7 {
		return 0, nil, false
	}
	channel = binary.BigEndian.Uint16(mcs[3:5])
	n, hdr := perLength(mcs[6:])
	if hdr == 0 {
		return channel, nil, false
	}
	payload = mcs[6+hdr:]
	if n < len(payload) {
		payload = payload[:n]
	}
	return channel, payload, true
}

// SecurityFlags returns the basic security header flags at the start of
// Send Data user data, or 0 when it is too short.
func SecurityFlags(payload []byte) uint16 {
	if len(payload) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint16(payload[0:2])
}

// IsSecurityExchange reports Send Data user data flagged SEC_EXCHANGE_PKT:
// the client sent its encrypted random for standard RDP security.
func IsSecurityExchange(payload []byte) bool {
	return SecurityFlags(payload)&secExchangePkt != 0
}

// AttachUserConfirm builds an MCS Attach User Confirm with rt-successful,
// as in MS-RDPBCGR 4.1.7.
func AttachUserConfirm() (TKIPHeader, []byte) {
	out, h := wrapX224DT([]byte{mcsAttachUserConfirm<<2 | 0x02, 0x00, 0x00, mcsUserInitiator})
	return h, out
}

// ChannelJoinConfirm builds an MCS Channel Join Confirm granting channel,
// echoing the requester's initiator (MS-RDPBCGR 2.2.1.9).
func ChannelJoinConfirm(initiator, channel uint16) (TKIPHeader, []byte) {
	pdu := []byte{mcsChannelJoinConfirm<<2 | 0x02, 0x00, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(pdu[2:4], initiator)
	binary.BigEndian.PutUint16(pdu[4:6], channel)
	binary.BigEndian.PutUint16(pdu[6:8], channel)
	out, h := wrapX224DT(pdu)
	return h, out
}

// sendDataIndication wraps payload in an MCS Send Data Indication from the
// server on the I/O channel.
func sendDataIndication(payload []byte) (TKIPHeader, []byte) {
	pdu := []byte{mcsSendDataIndication << 2, 0x00, mcsServerInitiator, byte(mcsIOChannel >> 8), byte(mcsIOChannel & 0xff), 0x70}
	if len(payload) < 0x80 {
		pdu = append(pdu, byte(len(payload)))
	} else {
		pdu = append(pdu, 0x80|byte(len(payload)>>8), byte(len(payload)))
	}
	out, h := wrapX224DT(append(pdu, payload...))
	return h, out
}

// LicenseValidClient builds the Server License Error PDU with
// STATUS_VALID_CLIENT / ST_NO_TRANSITION that lets a client skip licensing
// (MS-RDPELE 2.2.2.7.1, MS-RDPBCGR 4.1.12).
func LicenseValidClient() (TKIPHeader, []byte) {
	b := []byte{
		secLicensePkt, 0x00, 0x00, 0x00, // basic security header
		0xff, 0x03, 0x10, 0x00, // ERROR_ALERT, PREAMBLE_VERSION_3_0, wMsgSize 16
		0x07, 0x00, 0x00, 0x00, // STATUS_VALID_CLIENT
		0x02, 0x00, 0x00, 0x00, // ST_NO_TRANSITION
		0x04, 0x00, 0x00, 0x00, // BB_ERROR_BLOB, empty
	}
	return sendDataIndication(b)
}

// SetErrorInfo builds a Set Error Info PDU (MS-RDPBCGR 2.2.5.1.1) carrying
// errorInfo inside a Share Data Header.
func SetErrorInfo(errorInfo uint32) (TKIPHeader, []byte) {
	b := make([]byte, 22)
	binary.LittleEndian.PutUint16(b[0:2], 22)          // totalLength
	binary.LittleEndian.PutUint16(b[2:4], 0x0017)      // PDUTYPE_DATAPDU | TS_PROTOCOL_VERSION
	binary.LittleEndian.PutUint16(b[4:6], 1002)        // pduSource
	binary.LittleEndian.PutUint32(b[6:10], 0x000103ea) // shareId
	b[11] = 0x01                                       // STREAM_LOW
	binary.LittleEndian.PutUint16(b[12:14], 8)         // uncompressedLength
	b[14] = 0x2f                                       // PDUTYPE2_SET_ERROR_INFO_PDU
	binary.LittleEndian.PutUint32(b[18:22], errorInfo)
	return sendDataIndication(b)
}

// DisconnectProviderUltimatum builds the MCS Disconnect Provider Ultimatum
// a server sends before dropping the connection.
func DisconnectProviderUltimatum() (TKIPHeader, []byte) {
	out, h := wrapX224DT([]byte{mcsDisconnectProviderUltimatum<<2 | 0x01, 0x80})
	return h, out
}

// SplitTPKT splits b into complete TPKT PDUs. rest holds a trailing partial
// PDU. Bytes that do not start a valid TPKT header are returned as one PDU so
// they are still recorded.
func SplitTPKT(b []byte) (pdus [][]byte, rest []byte) {
	for len(b) >= 4 {
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if b[0] != 0x03 || l < 7 {
			return append(pdus, b), nil
		}
		if l > len(b) {
			break
		}
		pdus = append(pdus, b[:l])
		b = b[l:]
	}
	return pdus, b
}
