package rdp

import (
	"bytes"
	"encoding/binary"
	"strings"
)

const (
	CmdConnectionRequest  = "ConnectionRequest"
	CmdConnectionConfirm  = "ConnectionConfirm"
	CmdTLSClientHello     = "TLSClientHello"
	CmdTLSHandshake       = "TLSHandshake"
	CmdMCSConnectInitial  = "MCSConnectInitial"
	CmdMCSConnectResponse = "MCSConnectResponse"
	CmdTSRequest          = "TSRequest"
	CmdNTLMNegotiate      = "NTLMNegotiate"
	CmdNTLMChallenge      = "NTLMChallenge"
	CmdNTLMAuthenticate   = "NTLMAuthenticate"
)

var rdpProtocolBits = []struct {
	bit  uint32
	name string
}{
	{0x1, "TLS"},
	{0x2, "CredSSP"},
	{0x4, "RDSTLS"},
	{0x8, "CredSSP-EarlyAuth"},
	{0x10, "RDSAAD"},
}

// FrameCommand names a TPKT/TLS/MCS PDU for decoded events.
func FrameCommand(data []byte) string {
	if IsTLSRecord(data) {
		return CmdTLSClientHello
	}
	if IsMCSConnectInitial(data) {
		return CmdMCSConnectInitial
	}
	switch TPDUType(data) & tpduTypeMask {
	case TPDUConnectionRequest:
		return CmdConnectionRequest
	case TPDUConnectionConfirm:
		return CmdConnectionConfirm
	case TPDUData:
		return CmdMCSConnectInitial
	}
	return ""
}

// MSTSHASH extracts the Cookie: mstshash= value from a Connection Request.
func MSTSHASH(data []byte) string {
	const prefix = "mstshash="
	i := bytes.Index(data, []byte(prefix))
	if i < 0 {
		return ""
	}
	rest := data[i+len(prefix):]
	if j := bytes.IndexAny(rest, "\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return string(bytes.TrimSpace(rest))
}

// ProtocolMaskName formats an RDP_NEG requested/selected protocol bitmask.
func ProtocolMaskName(val uint32) string {
	if val == 0 {
		return "Standard RDP"
	}
	var names []string
	for _, p := range rdpProtocolBits {
		if val&p.bit != 0 {
			names = append(names, p.name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, "|")
}

// RequestedProtocols names protocols from a parsed Connection Request.
func RequestedProtocols(pdu ConnectionRequestPDU) string {
	if !HasRDPNegReq(pdu) {
		return ""
	}
	return ProtocolMaskName(binary.LittleEndian.Uint32(pdu.RDPNegReq.RequestedProtocols[:]))
}

// SelectedProtocols names protocols from a Connection Confirm with RDP_NEG_RSP.
func SelectedProtocols(cc []byte) string {
	if len(cc) < 19 || cc[11] != rdpNegRspType {
		return ""
	}
	return ProtocolMaskName(binary.LittleEndian.Uint32(cc[15:19]))
}

// IsTSRequest reports a CredSSP TSRequest: a DER SEQUENCE sent over TLS
// instead of a TPKT frame.
func IsTSRequest(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x30
}
