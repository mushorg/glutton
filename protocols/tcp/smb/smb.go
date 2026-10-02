package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf16"
)

const (
	cmdNegotiate     = 0x72
	cmdSessionSetup  = 0x73
	cmdTreeConnect   = 0x75
	flagsReply       = 0x80
	flags2Unicode    = 0x8000
	flags2NTStatus   = 0x4000
	capUnicode       = 0x00000004
	capNTSMBs        = 0x00000010
	capStatus32      = 0x00000040
	capLevel2Oplocks = 0x00000080
	capNTFind        = 0x00000200
	capLargeFiles    = 0x00000008
	capNTLM          = capUnicode | capLargeFiles | capNTSMBs | capStatus32 | capLevel2Oplocks | capNTFind
	nativeOS         = "Windows 5.1"
	nativeLanMan     = "Windows 5.1"
	primaryDomain    = "WORKGROUP"
	ntLMDialect      = "NT LM 0.12"
)

type SMBHeader struct {
	Protocol         [4]byte
	Command          byte
	Status           [4]byte
	Flags            byte
	Flags2           [2]byte
	PIDHigh          [2]byte
	SecurityFeatures [8]byte
	Reserved         [2]byte
	TID              [2]byte
	PIDLow           [2]byte
	UID              [2]byte
	MID              [2]byte
}

type SMBParameters struct {
	WordCount byte
}

type SMBData struct {
	ByteCount     [2]byte
	DialectString []byte
}

type NegotiateProtocolRequest struct {
	Header SMBHeader
	Param  SMBParameters
	Data   SMBData
}

// STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) — unpatched MS17-010 fingerprint.
var statusInsuffServerResources = [4]byte{0x05, 0x02, 0x00, 0xc0}

type ComTransaction2Error struct {
	Header    SMBHeader
	WordCount byte
	ByteCount [2]byte
}

type ComTransaction2Response struct {
	Header                SMBHeader
	WordCount             byte
	TotalParameterCount   [2]byte
	TotalDataCount        [2]byte
	Reserved1             [2]byte
	ParameterCount        [2]byte
	ParameterOffset       [2]byte
	ParameterDisplacement [2]byte
	DataCount             [2]byte
	DataOffset            [2]byte
	DataDisplacement      [2]byte
	SetupCount            byte
	Reserved2             byte
	ByteCount             [2]byte
	Pad1                  byte
	SearchID              [2]byte
	SearchCount           [2]byte
	EndofSearch           [2]byte
	ErrorOffset           [2]byte
	LastNameOffset        [2]byte
	Pad2                  [2]byte
	Data                  [16]byte
	Data1                 [16]byte
	Data2                 [16]byte
	Data3                 [16]byte
	Data4                 [16]byte
	Data5                 [16]byte
	Data6                 [16]byte
	Data7                 [16]byte
	Data8                 [16]byte
	Data9                 [16]byte
	Data10                [16]byte
	Data11                [16]byte
	Data12                [4]byte
}

// ValidateData locates the SMB1 magic (\xffSMB), skipping a Direct TCP / NBT
// session header when present.
func ValidateData(data []byte) (*bytes.Buffer, error) {
	start := bytes.Index(data, []byte("\xffSMB"))
	if start < 0 {
		return nil, errors.New("packet is unrecognizable")
	}
	return bytes.NewBuffer(data[start:]), nil
}

// FrameOffset returns the start of the Direct TCP session header when the
// buffer has at least 4 bytes before \xffSMB; otherwise the SMB magic offset.
func FrameOffset(data []byte) int {
	start := bytes.Index(data, []byte("\xffSMB"))
	if start < 0 {
		return 0
	}
	if start >= 4 {
		return start - 4
	}
	return start
}

// WrapSessionMessage prefixes an SMB PDU with a Direct TCP (port 445) length header.
func WrapSessionMessage(smbPDU []byte) []byte {
	if len(smbPDU) > 0xffffff {
		smbPDU = smbPDU[:0xffffff]
	}
	n := len(smbPDU)
	out := make([]byte, 4+n)
	out[0] = 0x00
	out[1] = byte(n >> 16)
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	copy(out[4:], smbPDU)
	return out
}

func flags2(h SMBHeader) uint16 {
	return binary.LittleEndian.Uint16(h.Flags2[:])
}

func putUint16(b *bytes.Buffer, v uint16) {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	b.Write(tmp[:])
}

func putUint32(b *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	b.Write(tmp[:])
}

func putFiletime(b *bytes.Buffer, t time.Time) {
	const epochAsFiletime int64 = 116444736000000000
	ft := epochAsFiletime + t.UnixNano()/100
	putUint32(b, uint32(ft))
	putUint32(b, uint32(ft>>32))
}

func encodeString(s string, unicode bool) []byte {
	if !unicode {
		return append([]byte(s), 0)
	}
	u := utf16.Encode([]rune(s + "\x00"))
	out := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

func replyHeader(req SMBHeader) SMBHeader {
	h := req
	h.Status = [4]byte{0, 0, 0, 0}
	h.Flags = req.Flags | flagsReply
	// Clear security features on replies; keep client's PID/MID/TID/UID unless overridden.
	h.SecurityFeatures = [8]byte{}
	h.Reserved = [2]byte{}
	f2 := flags2(req) | flags2NTStatus
	binary.LittleEndian.PutUint16(h.Flags2[:], f2)
	return h
}

func headerBytes(h SMBHeader) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, h); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func toBytes(smb interface{}) ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, smb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DialectIndex returns the 0-based index of want in an SMB1 negotiate dialect
// list (BufferFormat 0x02 + OEM string + NUL). Falls back to 0.
func DialectIndex(dialects []byte, want string) uint16 {
	parts := bytes.Split(dialects, []byte{0})
	var idx uint16
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		name := p
		if p[0] == 0x02 && len(p) > 1 {
			name = p[1:]
		}
		if string(name) == want {
			return idx
		}
		idx++
	}
	return 0
}

// MakeHeaderResponse builds a minimal success reply (WordCount=0, ByteCount=0).
func MakeHeaderResponse(header SMBHeader) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	hb, err := headerBytes(h)
	if err != nil {
		return h, nil, err
	}
	return h, append(hb, 0x00, 0x00, 0x00), nil
}

// MakeNegotiateProtocolResponse builds an SMB1 Negotiate response selecting NT LM 0.12.
// dialectBytes is the negotiate data after WordCount/ByteCount (dialect strings); may be nil.
func MakeNegotiateProtocolResponse(header SMBHeader, dialectBytes []byte) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	h.Command = cmdNegotiate
	h.UID = [2]byte{}
	h.TID = [2]byte{}

	dialectIdx := DialectIndex(dialectBytes, ntLMDialect)
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return h, nil, err
	}

	unicode := flags2(h)&flags2Unicode != 0
	domain := encodeString(primaryDomain, unicode)
	server := encodeString("GLUTTON", unicode)

	var body bytes.Buffer
	body.WriteByte(17) // WordCount
	putUint16(&body, dialectIdx)
	body.WriteByte(0x03)      // SecurityMode: user-level + encrypted passwords
	putUint16(&body, 50)      // MaxMpxCount
	putUint16(&body, 1)       // MaxNumberVcs
	putUint32(&body, 16644)   // MaxBufferSize
	putUint32(&body, 65536)   // MaxRawSize
	putUint32(&body, 0)       // SessionKey
	putUint32(&body, capNTLM) // Capabilities
	putFiletime(&body, time.Now().UTC())
	putUint16(&body, 0) // ServerTimeZone
	body.WriteByte(byte(len(challenge)))
	putUint16(&body, uint16(len(challenge)+len(domain)+len(server)))
	body.Write(challenge)
	body.Write(domain)
	body.Write(server)

	hb, err := headerBytes(h)
	if err != nil {
		return h, nil, err
	}
	return h, append(hb, body.Bytes()...), nil
}

// MakeSessionSetupAndXResponse builds an SMB1 Session Setup AndX success reply
// assigning uid to the client.
func MakeSessionSetupAndXResponse(header SMBHeader, uid uint16) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	h.Command = cmdSessionSetup
	binary.LittleEndian.PutUint16(h.UID[:], uid)

	unicode := flags2(h)&flags2Unicode != 0
	nativeOSB := encodeString(nativeOS, unicode)
	nativeLMB := encodeString(nativeLanMan, unicode)
	domainB := encodeString(primaryDomain, unicode)
	byteCount := len(nativeOSB) + len(nativeLMB) + len(domainB)

	var body bytes.Buffer
	body.WriteByte(3)    // WordCount
	body.WriteByte(0xff) // AndXCommand: none
	body.WriteByte(0)    // AndXReserved
	putUint16(&body, 0)  // AndXOffset
	putUint16(&body, 1)  // Action: guest
	putUint16(&body, uint16(byteCount))
	body.Write(nativeOSB)
	body.Write(nativeLMB)
	body.Write(domainB)

	hb, err := headerBytes(h)
	if err != nil {
		return h, nil, err
	}
	return h, append(hb, body.Bytes()...), nil
}

// MakeTreeConnectAndXResponse builds an SMB1 Tree Connect AndX success reply
// assigning tid to the client.
func MakeTreeConnectAndXResponse(header SMBHeader, tid uint16) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	h.Command = cmdTreeConnect
	binary.LittleEndian.PutUint16(h.TID[:], tid)

	unicode := flags2(h)&flags2Unicode != 0
	service := append([]byte("A:"), 0) // disk share
	fs := encodeString("NTFS", unicode)
	byteCount := len(service) + len(fs)

	var body bytes.Buffer
	body.WriteByte(3)    // WordCount
	body.WriteByte(0xff) // AndXCommand: none
	body.WriteByte(0)    // AndXReserved
	putUint16(&body, 0)  // AndXOffset
	putUint16(&body, 1)  // OptionalSupport: SMB_SUPPORT_SEARCH_BITS
	putUint16(&body, uint16(byteCount))
	body.Write(service)
	body.Write(fs)

	hb, err := headerBytes(h)
	if err != nil {
		return h, nil, err
	}
	return h, append(hb, body.Bytes()...), nil
}

func MakeComTransaction2Response(header SMBHeader) (SMBHeader, []byte, error) {
	smb := ComTransaction2Response{}
	smb.Header = replyHeader(header)
	smb.Header.Command = header.Command
	smb.WordCount = 0x0A
	smb.TotalParameterCount = [2]byte{0x0A}
	smb.TotalDataCount = [2]byte{196}
	smb.Reserved1 = [2]byte{0}
	smb.ParameterCount = [2]byte{10}
	smb.ParameterOffset = [2]byte{56}
	smb.ParameterDisplacement = [2]byte{}
	smb.DataCount = [2]byte{196}
	smb.DataOffset = [2]byte{68}
	smb.DataDisplacement = [2]byte{0}
	smb.SetupCount = 0
	smb.Reserved2 = 2
	smb.ByteCount = [2]byte{209}
	smb.Pad1 = 0
	smb.SearchCount = [2]byte{2}
	smb.SearchID = [2]byte{1}
	smb.ErrorOffset = [2]byte{}
	smb.LastNameOffset = [2]byte{96}
	smb.Pad2 = [2]byte{}
	smb.Data = [16]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39, 0xa3, 0xda, 0x08, 0x01, 0xd6, 0xd2, 0x01}
	smb.Data1 = [16]byte{0xba, 0xb0, 0x6e, 0x0a, 0x01, 0xd6, 0xd2, 0x01, 0x39, 0xa3, 0xda, 0x08, 0x01, 0xd6, 0xd2, 0x01}
	smb.Data2 = [16]byte{0x39, 0xa3, 0xda, 0x08, 0x01, 0xd6, 0xd2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data3 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	smb.Data4 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data5 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00}
	smb.Data6 = [16]byte{0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2, 0xaf, 0xca, 0x06, 0xcc, 0xd5, 0xd2, 0x01}
	smb.Data7 = [16]byte{0x9d, 0x76, 0x46, 0x90, 0xcc, 0xd5, 0xd2, 0x01, 0xc2, 0xaf, 0xca, 0x06, 0xcc, 0xd5, 0xd2, 0x01}
	smb.Data8 = [16]byte{0xc2, 0xaf, 0xca, 0x06, 0xcc, 0xd5, 0xd2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data9 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
	smb.Data10 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data11 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x2e}
	smb.Data12 = [4]byte{0x00, 0x00, 0x00, 0x00}

	data, err := toBytes(smb)
	return smb.Header, data, err
}

// MakeComTransactionResponse builds an SMB_COM_TRANSACTION reply that reports
// STATUS_INSUFF_SERVER_RESOURCES, the NT status MS17-010 scanners treat as vulnerable.
func MakeComTransactionResponse(header SMBHeader) (SMBHeader, []byte, error) {
	smb := ComTransaction2Error{}
	smb.Header = replyHeader(header)
	smb.Header.Command = header.Command
	smb.Header.Status = statusInsuffServerResources
	smb.WordCount = 0x00
	smb.ByteCount = [2]byte{}

	data, err := toBytes(smb)
	return smb.Header, data, err
}

func MakeComTransaction2Error(header SMBHeader) (SMBHeader, []byte, error) {
	smb := ComTransaction2Error{}
	smb.Header = replyHeader(header)
	smb.Header.Status = [4]byte{0x02, 0x00, 0x00, 0xc0}
	smb.WordCount = 0x00
	smb.ByteCount = [2]byte{}

	data, err := toBytes(smb)
	return smb.Header, data, err
}

func ParseHeader(buffer *bytes.Buffer, header *SMBHeader) error {
	return binary.Read(buffer, binary.LittleEndian, header)
}

func ParseParam(buffer *bytes.Buffer, param *SMBParameters) error {
	return binary.Read(buffer, binary.LittleEndian, param)
}

func ParseNegotiateProtocolRequest(buffer *bytes.Buffer, header SMBHeader) (NegotiateProtocolRequest, error) {
	smb := NegotiateProtocolRequest{}
	smb.Header = header
	err := ParseParam(buffer, &smb.Param)
	if err != nil {
		return smb, err
	}
	err = binary.Read(buffer, binary.LittleEndian, &smb.Data.ByteCount)
	if err != nil {
		return smb, err
	}
	smb.Data.DialectString = make([]byte, buffer.Len())
	err = binary.Read(buffer, binary.LittleEndian, &smb.Data.DialectString)
	return smb, err
}
