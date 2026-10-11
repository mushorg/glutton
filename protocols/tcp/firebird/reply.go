package firebird

import "encoding/binary"

// Protocol versions; 11 and later carry FB_PROTOCOL_FLAG.
const (
	protocolFlag      = 0x8000
	ProtocolVersion10 = 10
	ProtocolVersion11 = protocolFlag | 11
	ProtocolVersion12 = protocolFlag | 12
)

// Architectures and packet types (protocol.h).
const (
	ArchGeneric   = 1
	ptypeLazySend = 5
	ptypeMask     = 0xff // Firebird 3+ ORs pflag_compress into max_type
)

// Status vector items and the isc_login error.
const (
	iscArgEnd = 0
	iscArgGDS = 1
	// ISCLogin is "Your user name and password are not defined. Ask your
	// database administrator to set up a Firebird login."
	ISCLogin = 335544472
)

// VersionNumber strips FB_PROTOCOL_FLAG, so 0x800c reads as 12.
func VersionNumber(v uint32) uint32 {
	return v &^ protocolFlag
}

// SelectProtocol picks the protocol a Firebird 2.5 server accepts: version
// 10 to 12 with the generic architecture, the last of the highest weight.
// The accepted type is the client's max type capped at ptype_lazy_send.
func SelectProtocol(offer []Protocol) (Protocol, bool) {
	var best Protocol
	found := false
	for _, p := range offer {
		switch p.Version {
		case ProtocolVersion10, ProtocolVersion11, ProtocolVersion12:
		default:
			continue
		}
		if p.Arch != ArchGeneric || (found && p.Weight < best.Weight) {
			continue
		}
		best, found = p, true
	}
	best.MaxType = min(best.MaxType&ptypeMask, ptypeLazySend)
	return best, found
}

func words(v ...uint32) []byte {
	b := make([]byte, 0, 4*len(v))
	for _, w := range v {
		b = binary.BigEndian.AppendUint32(b, w)
	}
	return b
}

// BuildAccept builds the op_accept for the selected protocol.
func BuildAccept(p Protocol) []byte {
	return words(OpAccept, p.Version, p.Arch, p.MaxType)
}

// BuildReject builds the op_reject sent when no offered protocol fits.
func BuildReject() []byte {
	return words(OpReject)
}

// BuildLoginFailed builds the op_response for a rejected attach: object 0,
// null blob id, empty data, status vector {isc_arg_gds, isc_login, end}.
func BuildLoginFailed() []byte {
	return words(OpResponse, 0, 0, 0, 0, iscArgGDS, ISCLogin, iscArgEnd)
}
