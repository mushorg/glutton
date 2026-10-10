package smb

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	smb2HeaderSize            = 64
	smb2FlagServerToRedir     = 0x00000001
	smb2NegotiateBodySize     = 64
	smb2SessionSetupBodySize  = 8
	smb2TreeConnectBodySize   = 16
	smb2NegotiateStructure    = 65
	smb2SessionSetupStructure = 9
	smb2TreeConnectStructure  = 16
	smb2Dialect202            = 0x0202
	// STATUS_MORE_PROCESSING_REQUIRED, sent with the NTLM challenge.
	smb2StatusMoreProcessing = 0xc0000016
)

// smb2ServerGUID is the ServerGuid in SMB2 Negotiate replies. A Windows server
// keeps one GUID for its lifetime, so it is generated once per process.
var smb2ServerGUID = newServerGUID()

// newServerGUID returns a random (version 4) GUID in its wire byte order.
func newServerGUID() [16]byte {
	var g [16]byte
	_, _ = rand.Read(g[:])
	g[7] = g[7]&0x0f | 0x40 // version 4 (high nibble of the LE Data3 field)
	g[8] = g[8]&0x3f | 0x80 // RFC 4122 variant
	return g
}

// SMB2Command returns the SMB2 command from a PDU starting at \xfeSMB.
func SMB2Command(pdu []byte) (uint16, bool) {
	if len(pdu) < 14 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(pdu[12:14]), true
}

func smb2ReplyHeader(req []byte) []byte {
	h := make([]byte, smb2HeaderSize)
	if len(req) >= smb2HeaderSize {
		copy(h, req[:smb2HeaderSize])
	} else {
		copy(h, req)
		h[0] = 0xfe
		copy(h[1:4], []byte("SMB"))
	}
	binary.LittleEndian.PutUint16(h[4:6], smb2HeaderSize)
	binary.LittleEndian.PutUint32(h[8:12], 0) // NT status success
	binary.LittleEndian.PutUint16(h[14:16], 1)
	flags := binary.LittleEndian.Uint32(h[16:20]) | smb2FlagServerToRedir
	binary.LittleEndian.PutUint32(h[16:20], flags)
	binary.LittleEndian.PutUint32(h[20:24], 0)
	return h
}

func makeSMB2NegotiateResponse(req []byte) []byte {
	h := smb2ReplyHeader(req)
	binary.LittleEndian.PutUint16(h[12:14], SMB2CmdNegotiate)

	body := make([]byte, smb2NegotiateBodySize)
	binary.LittleEndian.PutUint16(body[0:2], smb2NegotiateStructure)
	binary.LittleEndian.PutUint16(body[2:4], 0x0001) // signing enabled
	binary.LittleEndian.PutUint16(body[4:6], smb2Dialect202)
	copy(body[8:24], smb2ServerGUID[:])
	binary.LittleEndian.PutUint32(body[28:32], 65536)
	binary.LittleEndian.PutUint32(body[32:36], 65536)
	binary.LittleEndian.PutUint32(body[36:40], 65536)
	// SecurityBufferOffset / SecurityBufferLength point at an SPNEGO blob that
	// advertises NTLMSSP so the client proceeds to authenticate.
	blob := SPNEGONegTokenInit()
	binary.LittleEndian.PutUint16(body[56:58], uint16(smb2HeaderSize+smb2NegotiateBodySize))
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(blob)))

	return append(append(h, body...), blob...)
}

// makeSMB2SessionSetupResponse answers an SMB2 Session Setup. A Type 1 NTLMSSP
// gets a challenge with STATUS_MORE_PROCESSING_REQUIRED; everything else is
// accepted. moreProcessing reports which happened.
func makeSMB2SessionSetupResponse(req []byte, challenge [8]byte) (pdu []byte, moreProcessing bool) {
	h := smb2ReplyHeader(req)
	binary.LittleEndian.PutUint16(h[12:14], SMB2CmdSessionSetup)
	if binary.LittleEndian.Uint64(h[40:48]) == 0 {
		binary.LittleEndian.PutUint64(h[40:48], 1)
	}

	var blob []byte
	sessionFlags := uint16(0x0001) // GUEST
	if ntlm, ok := FindNTLMSSP(req); ok && NTLMMessageType(ntlm) == ntlmNegotiate {
		blob = SPNEGOChallenge(BuildChallenge(challenge, serverName))
		binary.LittleEndian.PutUint32(h[8:12], smb2StatusMoreProcessing)
		sessionFlags = 0
		moreProcessing = true
	} else if _, ok := FindNTLMSSP(req); ok {
		blob = SPNEGOAccept()
	}

	body := make([]byte, smb2SessionSetupBodySize)
	binary.LittleEndian.PutUint16(body[0:2], smb2SessionSetupStructure)
	binary.LittleEndian.PutUint16(body[2:4], sessionFlags)
	binary.LittleEndian.PutUint16(body[4:6], uint16(smb2HeaderSize+smb2SessionSetupBodySize))
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(blob)))
	return append(append(h, body...), blob...), moreProcessing
}

func makeSMB2TreeConnectResponse(req []byte) []byte {
	h := smb2ReplyHeader(req)
	binary.LittleEndian.PutUint16(h[12:14], SMB2CmdTreeConnect)
	if binary.LittleEndian.Uint32(h[36:40]) == 0 {
		binary.LittleEndian.PutUint32(h[36:40], 1)
	}

	body := make([]byte, smb2TreeConnectBodySize)
	binary.LittleEndian.PutUint16(body[0:2], smb2TreeConnectStructure)
	body[2] = 0x01 // SHARE_TYPE_DISK
	binary.LittleEndian.PutUint32(body[12:16], 0x001f01ff)
	return append(h, body...)
}

// MakeSMB2Reply builds a stub SMB2 Negotiate, Session Setup, or Tree Connect
// success PDU. challenge is the NTLM server challenge used in Session Setup. ok
// is false when the request is too short or the command has no stub (the frame
// should still be stored).
func MakeSMB2Reply(req []byte, challenge [8]byte) (name string, pdu []byte, ok bool) {
	cmd, parsed := SMB2Command(req)
	if !parsed {
		return "", nil, false
	}
	name = SMB2CommandName(cmd)
	switch cmd {
	case SMB2CmdNegotiate:
		return name, makeSMB2NegotiateResponse(req), true
	case SMB2CmdSessionSetup:
		p, _ := makeSMB2SessionSetupResponse(req, challenge)
		return name, p, true
	case SMB2CmdTreeConnect:
		return name, makeSMB2TreeConnectResponse(req), true
	default:
		return name, nil, false
	}
}
