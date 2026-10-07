package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	cmdNegotiate    = 0x72
	cmdSessionSetup = 0x73
	cmdTreeConnect  = 0x75
	flagsReply      = 0x80
	flags2Unicode   = 0x8000
	flags2NTStatus  = 0x4000
	// SMB_FLAGS2_EXTENDED_SECURITY — do not advertise unless NTLMSSP Session Setup is implemented.
	flags2ExtendedSecurity = 0x0800
	capUnicode             = 0x00000004
	capNTSMBs              = 0x00000010
	capStatus32            = 0x00000040
	capLevel2Oplocks       = 0x00000080
	capNTFind              = 0x00000200
	capLargeFiles          = 0x00000008
	capNTLM                = capUnicode | capLargeFiles | capNTSMBs | capStatus32 | capLevel2Oplocks | capNTFind
	nativeOS               = "Windows 5.1"
	nativeLanMan           = "Windows 5.1"
	primaryDomain          = "WORKGROUP"
	serverName             = "SERVER"
	ntLMDialect            = "NT LM 0.12"
	// TRANS2 subcommands (MS-CIFS 2.2.6).
	trans2FindFirst2   = 0x0001
	trans2SessionSetup = 0x000e
	// STATUS_NOT_IMPLEMENTED — plausible for unsupported Trans2 subcommands.
	statusNotImplemented = 0xc0000002
	// STATUS_INVALID_PARAMETER — Windows reply when a fragmented NT_TRANSACT completes.
	statusInvalidParameter = 0xc000000d
	fileOpened             = 0x00000001
	fileTypeMessagePipe    = 0x0002
	ntCreateAndXWordCount  = 34
)

// Trans2FindFirst2 is the TRANS2_FIND_FIRST2 subcommand (0x0001).
const Trans2FindFirst2 = trans2FindFirst2

// Trans2SessionSetup is the TRANS2_SESSION_SETUP subcommand (0x000e).
const Trans2SessionSetup = trans2SessionSetup

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

func decodeOEMString(b []byte) (string, int) {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b), len(b)
	}
	return string(b[:n]), n + 1
}

func decodeUnicodeString(b []byte) (string, int) {
	var runes []uint16
	i := 0
	for i+1 < len(b) {
		v := binary.LittleEndian.Uint16(b[i:])
		i += 2
		if v == 0 {
			break
		}
		runes = append(runes, v)
	}
	return string(utf16.Decode(runes)), i
}

// TreeConnectShare extracts the share name from an SMB_COM_TREE_CONNECT_ANDX
// request body positioned after the 32-byte SMB header. Returns "" on failure.
func TreeConnectShare(header SMBHeader, body []byte) string {
	unicode := flags2(header)&flags2Unicode != 0
	// WordCount(1) + AndXCommand(1) + AndXReserved(1) + AndXOffset(2) +
	// Flags(2) + PasswordLength(2) + ByteCount(2) = 11 bytes of fixed prefix.
	const fixed = 11
	if len(body) < fixed {
		return ""
	}
	passLen := int(binary.LittleEndian.Uint16(body[7:9]))
	off := fixed + passLen
	if off > len(body) {
		return ""
	}
	// Unicode Path is aligned to a 2-byte boundary relative to the SMB header
	// start (32 + off must be even).
	if unicode && (32+off)%2 != 0 {
		off++
		if off > len(body) {
			return ""
		}
	}
	var path string
	if unicode {
		path, _ = decodeUnicodeString(body[off:])
	} else {
		path, _ = decodeOEMString(body[off:])
	}
	return shareFromPath(path)
}

func shareFromPath(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	parts := strings.Split(path, `\`)
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return ""
}

// IsIPCShare reports whether share is the IPC$ named-pipe share.
func IsIPCShare(share string) bool {
	return strings.EqualFold(share, "IPC$")
}

// NtCreateAndXName extracts the filename from an SMB_COM_NT_CREATE_ANDX
// request body positioned after the 32-byte SMB header. Returns "" on failure.
func NtCreateAndXName(header SMBHeader, body []byte) string {
	// WordCount(1) + 24 words (48 bytes) + ByteCount(2).
	const fixed = 1 + 24*2 + 2
	if len(body) < fixed {
		return ""
	}
	unicode := flags2(header)&flags2Unicode != 0
	nameLen := int(binary.LittleEndian.Uint16(body[6:8]))
	off := fixed
	if unicode && (32+off)%2 != 0 {
		off++
		if off > len(body) {
			return ""
		}
	}
	nameBytes := body[off:]
	if nameLen > 0 && off+nameLen <= len(body) {
		nameBytes = body[off : off+nameLen]
	}
	if unicode {
		s, _ := decodeUnicodeString(nameBytes)
		return s
	}
	s, _ := decodeOEMString(nameBytes)
	return s
}

// Trans2Setup returns the first Setup word from an SMB_COM_TRANSACTION2 request
// body positioned after the 32-byte SMB header. ok is false if the body is short.
func Trans2Setup(body []byte) (setup uint16, ok bool) {
	// WordCount(1) + 26 bytes of fixed words through DataOffset, then
	// SetupCount(1) + Reserved3(1) + Setup words.
	const setupCountOff = 1 + 26
	if len(body) < setupCountOff+1 {
		return 0, false
	}
	setupCount := int(body[setupCountOff])
	if setupCount < 1 {
		return 0, false
	}
	setupOff := setupCountOff + 2
	if len(body) < setupOff+2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(body[setupOff:]), true
}

// NtTransactTotalDataCount returns TotalDataCount from an SMB_COM_NT_TRANSACT
// request body positioned after the 32-byte SMB header.
func NtTransactTotalDataCount(body []byte) uint32 {
	// WordCount(1) + MaxSetupCount(1) + Reserved1(2) + TotalParameterCount(4)
	// + TotalDataCount(4).
	const off = 1 + 1 + 2 + 4
	if len(body) < off+4 {
		return 0
	}
	return binary.LittleEndian.Uint32(body[off : off+4])
}

// SecondaryDataRange returns DataDisplacement and DataCount from a secondary
// transaction request body positioned after the 32-byte SMB header.
func SecondaryDataRange(command byte, body []byte) (displacement, count uint32, ok bool) {
	if len(body) < 1 {
		return 0, 0, false
	}
	switch command {
	case CmdTransactionSecondary:
		// WC 8: DataCount USHORT at body[11:13], DataDisplacement at body[15:17].
		if body[0] != 8 || len(body) < 17 {
			return 0, 0, false
		}
		return uint32(binary.LittleEndian.Uint16(body[15:17])),
			uint32(binary.LittleEndian.Uint16(body[11:13])), true
	case CmdTransaction2Secondary:
		// WC 9: same USHORT layout as TRANSACTION_SECONDARY (plus FID after).
		if body[0] != 9 || len(body) < 17 {
			return 0, 0, false
		}
		return uint32(binary.LittleEndian.Uint16(body[15:17])),
			uint32(binary.LittleEndian.Uint16(body[11:13])), true
	case CmdNtTransactSecondary:
		// WC 18: ULONG DataCount at body[24:28], DataDisplacement at body[32:36].
		if body[0] != 18 || len(body) < 36 {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint32(body[32:36]),
			binary.LittleEndian.Uint32(body[24:28]), true
	default:
		return 0, 0, false
	}
}

func echoRequestData(body []byte) []byte {
	// WordCount(1) + EchoCount(2) + ByteCount(2) + data.
	if len(body) < 5 {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(body[3:5]))
	rest := body[5:]
	if n > len(rest) {
		n = len(rest)
	}
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	copy(out, rest[:n])
	return out
}

func replyHeader(req SMBHeader) SMBHeader {
	h := req
	h.Status = [4]byte{0, 0, 0, 0}
	h.Flags = req.Flags | flagsReply
	// Clear security features on replies; keep client's PID/MID/TID/UID unless overridden.
	h.SecurityFeatures = [8]byte{}
	h.Reserved = [2]byte{}
	// Clear EXTENDED_SECURITY so clients use basic Session Setup (not NTLMSSP).
	f2 := (flags2(req) | flags2NTStatus) &^ flags2ExtendedSecurity
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

	// Non-extended negotiate Domain/Server are UTF-16 in practice; nmap's
	// smb.lua always decodes them as UTF-16 regardless of the client's Flags2.
	f2 := flags2(h) | flags2Unicode
	binary.LittleEndian.PutUint16(h.Flags2[:], f2)
	domain := encodeString(primaryDomain, true)
	server := encodeString(serverName, true)

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
// assigning tid to the client. For IPC$ shares the Service is "IPC" with an
// empty NativeFileSystem; other shares get disk Service "A:" and "NTFS".
func MakeTreeConnectAndXResponse(header SMBHeader, tid uint16, share string) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	h.Command = cmdTreeConnect
	binary.LittleEndian.PutUint16(h.TID[:], tid)

	unicode := flags2(h)&flags2Unicode != 0
	var service []byte
	var fs []byte
	if IsIPCShare(share) {
		service = append([]byte("IPC"), 0)
		fs = encodeString("", unicode)
	} else {
		service = append([]byte("A:"), 0) // disk share
		fs = encodeString("NTFS", unicode)
	}
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

// MakeNtCreateAndXResponse builds an SMB_COM_NT_CREATE_ANDX success reply
// (WordCount 34, AndX none, FILE_OPENED) assigning fid. Named-pipe fields are
// filled so clients opening IPC$ pipes such as \svcctl keep the session open.
func MakeNtCreateAndXResponse(header SMBHeader, fid uint16) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	h.Command = CmdNtCreateAndX

	var body bytes.Buffer
	body.WriteByte(ntCreateAndXWordCount)
	body.WriteByte(0xff) // AndXCommand: none
	body.WriteByte(0)    // AndXReserved
	putUint16(&body, 0)  // AndXOffset
	body.WriteByte(0)    // OpLockLevel: none
	putUint16(&body, fid)
	putUint32(&body, fileOpened) // CreateAction: FILE_OPENED
	var zeros8 [8]byte
	body.Write(zeros8[:]) // CreateTime
	body.Write(zeros8[:]) // LastAccessTime
	body.Write(zeros8[:]) // LastWriteTime
	body.Write(zeros8[:]) // ChangeTime
	putUint32(&body, 0)   // ExtFileAttributes
	body.Write(zeros8[:]) // AllocationSize
	body.Write(zeros8[:]) // EndOfFile
	putUint16(&body, fileTypeMessagePipe)
	putUint16(&body, 0x00c5) // NMPipeStatus: message-mode, connected
	body.WriteByte(0)        // Directory: false
	putUint16(&body, 0)      // ByteCount

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

// MakeComTransaction2Reply chooses a Trans2 response from the request Setup
// subcommand. TRANS2_FIND_FIRST2 gets the FIND_FIRST2-style success body;
// unsupported subcommands (including TRANS2_SESSION_SETUP) get an NT error.
func MakeComTransaction2Reply(header SMBHeader, setup uint16, setupOK bool) (SMBHeader, []byte, error) {
	if setupOK && setup == trans2FindFirst2 {
		return MakeComTransaction2Response(header)
	}
	return MakeComTransaction2Error(header)
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

// MakeEchoResponse builds an SMB_COM_ECHO reply: WordCount 1, SequenceNumber 1,
// and the request's echo data copied back.
func MakeEchoResponse(header SMBHeader, body []byte) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	h.Command = CmdEcho
	hb, err := headerBytes(h)
	if err != nil {
		return h, nil, err
	}
	data := echoRequestData(body)
	out := make([]byte, 0, len(hb)+5+len(data))
	out = append(out, hb...)
	out = append(out, 1) // WordCount
	var seq [2]byte
	binary.LittleEndian.PutUint16(seq[:], 1)
	out = append(out, seq[:]...)
	var bc [2]byte
	binary.LittleEndian.PutUint16(bc[:], uint16(len(data)))
	out = append(out, bc[:]...)
	out = append(out, data...)
	return h, out, nil
}

// MakeComNtTransactionResponse builds an empty SMB_COM_NT_TRANSACT success
// reply so clients keep sending secondary / overflow fragments. This is not
// the MS17-010 STATUS_INSUFF_SERVER_RESOURCES fingerprint (that stays on 0x25).
func MakeComNtTransactionResponse(header SMBHeader) (SMBHeader, []byte, error) {
	h := replyHeader(header)
	h.Command = CmdNtTransact
	hb, err := headerBytes(h)
	if err != nil {
		return h, nil, err
	}
	// WordCount=18 (no Setup), 18 zero words, ByteCount=0.
	body := make([]byte, 1+18*2+2)
	body[0] = 18
	return h, append(hb, body...), nil
}

func MakeComTransaction2Error(header SMBHeader) (SMBHeader, []byte, error) {
	smb := ComTransaction2Error{}
	smb.Header = replyHeader(header)
	smb.Header.Command = header.Command
	binary.LittleEndian.PutUint32(smb.Header.Status[:], statusNotImplemented)
	smb.WordCount = 0x00
	smb.ByteCount = [2]byte{}

	data, err := toBytes(smb)
	return smb.Header, data, err
}

// MakeTransactionCompleteResponse builds the STATUS_INVALID_PARAMETER reply
// Windows sends when a fragmented NT_TRANSACT finishes.
func MakeTransactionCompleteResponse(header SMBHeader) (SMBHeader, []byte, error) {
	smb := ComTransaction2Error{}
	smb.Header = replyHeader(header)
	smb.Header.Command = header.Command
	binary.LittleEndian.PutUint32(smb.Header.Status[:], statusInvalidParameter)
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
