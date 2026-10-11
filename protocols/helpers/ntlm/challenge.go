package ntlm

import (
	"encoding/binary"
	"time"
)

// FlagsSMB is the NegotiateFlags set used by SMB Session Setup challenges:
// UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|TARGET_TYPE_SERVER|TARGET_INFO|
// EXTENDED_SESSIONSECURITY.
const FlagsSMB = FlagUnicode | FlagRequestTarget | FlagNTLM |
	FlagAlwaysSign | FlagTargetTypeServer | FlagTargetInfo |
	FlagExtendedSessionSecurity

// FlagsRDP is the NegotiateFlags base used by RDP CredSSP challenges
// (0xe08a8205): UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|TARGET_TYPE_SERVER|
// EXTENDED_SESSIONSECURITY|TARGET_INFO|128|KEY_EXCH|56. NEGOTIATE_VERSION is
// ORed in when the client requests it.
const FlagsRDP uint32 = 0xe08a8205

// ChallengeOptions configures an NTLMSSP Type 2 CHALLENGE message.
type ChallengeOptions struct {
	// ServerChallenge is the 8-byte server challenge (required).
	ServerChallenge []byte
	// TargetName is written into the TargetNameFields. Empty → Domain.
	TargetName string
	// Domain and Computer populate TargetInfo. For a minimal (SMB) challenge
	// only TargetName is needed; Domain defaults to TargetName when empty.
	Domain   string
	Computer string
	// ClientFlags are the NegotiateFlags from the client's Type 1 message.
	// When FlagVersion is set the Challenge includes a VERSION block and the
	// payload shifts from offset 48 to 56.
	ClientFlags uint32
	// Now is used for MsvAvTimestamp when RichTargetInfo is set. Zero → time.Now().
	Now time.Time
	// Flags overrides the NegotiateFlags base. Zero selects FlagsSMB when
	// RichTargetInfo is false, FlagsRDP when true.
	Flags uint32
	// RichTargetInfo builds the Windows-style AvPair set (NbDomain, NbComputer,
	// DnsDomain, DnsComputer, Timestamp, EOL). When false, only NbDomainName
	// (from TargetName/Domain) + EOL are sent, matching the SMB honeypot.
	RichTargetInfo bool
	// TargetNUL appends a UTF-16 NUL to TargetName and the NbDomain AvPair
	// value. SMB historically encoded names this way via encodeString.
	TargetNUL bool
}

// BuildChallenge builds an NTLMSSP Type 2 CHALLENGE.
func BuildChallenge(opts ChallengeOptions) []byte {
	if len(opts.ServerChallenge) != 8 {
		return nil
	}
	name := opts.TargetName
	if name == "" {
		name = opts.Domain
	}
	domain := opts.Domain
	if domain == "" {
		domain = name
	}

	targetName := EncodeUTF16LE(name)
	if opts.TargetNUL {
		targetName = append(targetName, 0, 0)
	}

	var avPairs []byte
	if opts.RichTargetInfo {
		now := opts.Now
		if now.IsZero() {
			now = time.Now()
		}
		avPairs = buildRichAvPairs(domain, opts.Computer, now)
	} else {
		avPairs = buildMinimalAvPairs(targetName)
	}

	flags := opts.Flags
	if flags == 0 {
		if opts.RichTargetInfo {
			flags = FlagsRDP
		} else {
			flags = FlagsSMB
		}
	}
	includeVersion := opts.ClientFlags&FlagVersion != 0
	payloadOff := 48
	if includeVersion {
		flags |= FlagVersion
		payloadOff = 56
	}

	targetNameOff := payloadOff
	targetInfoOff := targetNameOff + len(targetName)
	msg := make([]byte, targetInfoOff+len(avPairs))

	copy(msg[0:8], signature)
	binary.LittleEndian.PutUint32(msg[8:12], MsgChallenge)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(targetNameOff))
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	copy(msg[24:32], opts.ServerChallenge)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(avPairs)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(avPairs)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOff))
	if includeVersion {
		// VERSION (MS-NLMP 2.2.2.10): Windows 10.0 build 17763, NTLM rev 15.
		copy(msg[48:56], []byte{0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f})
	}
	copy(msg[targetNameOff:], targetName)
	copy(msg[targetInfoOff:], avPairs)
	return msg
}

// BuildSMBChallenge is the SMB Session Setup convenience: minimal TargetInfo,
// TargetNUL encoding, FlagsSMB.
func BuildSMBChallenge(serverChallenge [8]byte, targetName string) []byte {
	return BuildChallenge(ChallengeOptions{
		ServerChallenge: serverChallenge[:],
		TargetName:      targetName,
		TargetNUL:       true,
	})
}

func buildMinimalAvPairs(targetUTF16 []byte) []byte {
	var b []byte
	b = appendAvPair(b, AvNbDomainName, targetUTF16)
	b = appendAvPair(b, AvEOL, nil)
	return b
}

func buildRichAvPairs(domain, computer string, now time.Time) []byte {
	var b []byte
	b = appendAvPair(b, AvNbDomainName, EncodeUTF16LE(domain))
	b = appendAvPair(b, AvNbComputerName, EncodeUTF16LE(computer))
	b = appendAvPair(b, AvDnsDomainName, EncodeUTF16LE(domain))
	b = appendAvPair(b, AvDnsComputerName, EncodeUTF16LE(computer))
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, ToFILETIME(now))
	b = appendAvPair(b, AvTimestamp, ts)
	b = appendAvPair(b, AvEOL, nil)
	return b
}

func appendAvPair(b []byte, id uint16, val []byte) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], id)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
	return append(append(b, hdr[:]...), val...)
}
