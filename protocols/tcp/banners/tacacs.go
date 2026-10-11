package banners

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
)

const (
	tacacsHeaderLen     = 12
	tacacsMajorVer      = 0xc0
	tacacsTypeAuthen    = 0x01
	tacacsStartFixedLen = 8 // action, priv_lvl, authen_type, service, four lengths
	tacacsStatusError   = 0x07
)

// The server_msg tac_plus F4.0.4 puts in the ERROR reply is
// "<peer> <port>: <reason>" (packet.c send_authen_error); the port is still
// empty for a START and the peer address is not known here, so the message
// keeps only the " : <reason>" part. The body is encrypted, so only its
// length is visible without the key.
const (
	tacacsTooShort  = " : Invalid AUTHEN/START packet (too short)"
	tacacsCheckKeys = " : Invalid AUTHEN/START packet (check keys)"
)

// tacacsKey stands in for the shared secret a tac_plus daemon encrypts
// bodies with; it is random per process and replaced in tests.
var tacacsKey = func() []byte {
	k := make([]byte, 16)
	_, _ = rand.Read(k)
	return k
}()

// isTacacsAuthenStart reports whether data is one whole TACACS+ AUTHEN START
// packet (RFC 8907 4.1): major version 0xC with minor 0 or 1, type AUTHEN,
// seq_no 1 and a body length equal to the bytes after the header.
func isTacacsAuthenStart(data []byte) bool {
	if len(data) < tacacsHeaderLen || data[0]&0xf0 != tacacsMajorVer || data[0]&0x0f > 1 ||
		data[1] != tacacsTypeAuthen || data[2] != 1 {
		return false
	}
	return uint64(binary.BigEndian.Uint32(data[8:12])) == uint64(len(data)-tacacsHeaderLen)
}

// tacacsAuthenError builds the AUTHEN REPLY tac_plus F4.0.4 sends when a START
// fails validation (authen.c): the client's version and session_id, seq_no 2,
// status ERROR and a body encrypted with the shared key, so flags are 0. A
// body shorter than the START fixed fields is "too short"; a longer one is
// decrypted with a key the client does not share, fails the length check and
// gets "check keys".
func tacacsAuthenError(start, key []byte) []byte {
	msg := tacacsTooShort
	if len(start)-tacacsHeaderLen >= tacacsStartFixedLen {
		msg = tacacsCheckKeys
	}
	body := make([]byte, 6+len(msg))
	body[0] = tacacsStatusError
	binary.BigEndian.PutUint16(body[2:4], uint16(len(msg)))
	copy(body[6:], msg)

	b := make([]byte, tacacsHeaderLen, tacacsHeaderLen+len(body))
	b[0] = start[0]
	b[1] = tacacsTypeAuthen
	b[2] = 2
	copy(b[4:8], start[4:8])
	binary.BigEndian.PutUint32(b[8:12], uint32(len(body)))
	tacacsXOR(b, body, key)
	return append(b, body...)
}

// tacacsXOR applies the RFC 8907 4.5 pad to body in place: MD5 over
// session_id, key, version and seq_no, chained with the previous hash for
// every further 16 bytes.
func tacacsXOR(hdr, body, key []byte) {
	var prev []byte
	for i := 0; i < len(body); i += md5.Size {
		in := make([]byte, 0, 4+len(key)+2+len(prev))
		in = append(in, hdr[4:8]...)
		in = append(in, key...)
		in = append(in, hdr[0], hdr[2])
		in = append(in, prev...)
		sum := md5.Sum(in)
		prev = sum[:]
		for j := 0; j < md5.Size && i+j < len(body); j++ {
			body[i+j] ^= sum[j]
		}
	}
}
