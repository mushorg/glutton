// Package ssh parses the unencrypted start of an SSH session (RFC 4253): the
// identification string and the first binary packet, normally SSH_MSG_KEXINIT.
// Key exchange and authentication are left to golang.org/x/crypto/ssh.
package ssh

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// ServerVersion is the identification string the honeypot presents, shared by
// the ssh handler and the catch-all banner.
const ServerVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"

const (
	// MsgKexInit is the SSH_MSG_KEXINIT message number.
	MsgKexInit = 20
	// maxLine is the RFC 4253 limit for the identification string, CR LF
	// included; other pre-version lines get the same bound.
	maxLine = 255
	// maxPacket is the packet size every implementation must accept.
	maxPacket = 35000
)

// Kinds of Message.
const (
	KindLine    = "line"    // a text line before the identification string
	KindVersion = "version" // the SSH-... identification string
	KindKexInit = "kexinit" // the first binary packet, a parsed KEXINIT
	KindPacket  = "packet"  // the first binary packet, not a KEXINIT
	KindInvalid = "invalid" // bytes that do not frame as SSH; the stream stops
)

// Message is one framed unit of the session preamble.
type Message struct {
	Kind    string
	Raw     []byte // wire bytes, framing included
	Version string // KindVersion: the identification string without CR LF
	KexInit *KexInit
	// Truncated is set when the connection ended inside the message.
	Truncated bool
}

// KexInit holds the name-lists of an SSH_MSG_KEXINIT.
type KexInit struct {
	Cookie                  []byte
	KexAlgos                []string
	ServerHostKeyAlgos      []string
	CiphersClientServer     []string
	CiphersServerClient     []string
	MACsClientServer        []string
	MACsServerClient        []string
	CompressionClientServer []string
	CompressionServerClient []string
	LanguagesClientServer   []string
	LanguagesServerClient   []string
	FirstKexFollows         bool
}

var errShort = errors.New("ssh: short kexinit")

// ParseKexInit parses an SSH_MSG_KEXINIT payload, starting at the message
// number.
func ParseKexInit(payload []byte) (*KexInit, error) {
	if len(payload) < 17 || payload[0] != MsgKexInit {
		return nil, errShort
	}
	k := &KexInit{Cookie: append([]byte(nil), payload[1:17]...)}
	rest := payload[17:]
	lists := []*[]string{
		&k.KexAlgos, &k.ServerHostKeyAlgos,
		&k.CiphersClientServer, &k.CiphersServerClient,
		&k.MACsClientServer, &k.MACsServerClient,
		&k.CompressionClientServer, &k.CompressionServerClient,
		&k.LanguagesClientServer, &k.LanguagesServerClient,
	}
	for _, l := range lists {
		if len(rest) < 4 {
			return nil, errShort
		}
		n := binary.BigEndian.Uint32(rest)
		if uint64(n) > uint64(len(rest)-4) {
			return nil, errShort
		}
		if n > 0 {
			*l = strings.Split(string(rest[4:4+n]), ",")
		}
		rest = rest[4+n:]
	}
	// first_kex_packet_follows and the reserved uint32
	if len(rest) < 5 {
		return nil, errShort
	}
	k.FirstKexFollows = rest[0] != 0
	return k, nil
}

// HASSH returns the HASSH fingerprint and its input string. The client
// variant uses the client-to-server lists, the server variant (HASSHServer)
// the server-to-client ones.
func (k *KexInit) HASSH(server bool) (string, string) {
	enc, mac, cmp := k.CiphersClientServer, k.MACsClientServer, k.CompressionClientServer
	if server {
		enc, mac, cmp = k.CiphersServerClient, k.MACsServerClient, k.CompressionServerClient
	}
	algorithms := strings.Join([]string{
		strings.Join(k.KexAlgos, ","),
		strings.Join(enc, ","),
		strings.Join(mac, ","),
		strings.Join(cmp, ","),
	}, ";")
	sum := md5.Sum([]byte(algorithms))
	return hex.EncodeToString(sum[:]), algorithms
}

// Stream splits one direction of an SSH session into Messages: the lines
// before the identification string (one message), the identification string, then the
// first binary packet. Everything after it (key exchange, then encrypted
// traffic) is ignored. Feed it bytes in the order they were read or written.
type Stream struct {
	buf     []byte
	pre     []byte // lines before the identification string
	version bool
	done    bool
}

// Done reports whether the stream has emitted its last message.
func (s *Stream) Done() bool { return s.done }

// Feed appends p and returns the messages it completed.
func (s *Stream) Feed(p []byte) []Message {
	if s.done {
		return nil
	}
	s.buf = append(s.buf, p...)
	var out []Message
	for !s.done {
		m, ok := s.next()
		if !ok {
			break
		}
		// the pre-version lines go out as one message ahead of the version
		if m.Kind == KindVersion && len(s.pre) > 0 {
			out = append(out, Message{Kind: KindLine, Raw: s.pre})
			s.pre = nil
		}
		out = append(out, m)
	}
	return out
}

// Flush returns the bytes of an unfinished message when the connection ends.
func (s *Stream) Flush() (Message, bool) {
	if s.done || len(s.pre)+len(s.buf) == 0 {
		return Message{}, false
	}
	s.done = true
	m := Message{Kind: KindInvalid, Raw: append(s.pre, s.buf...), Truncated: true}
	if len(s.pre) == 0 && bytes.HasPrefix(s.buf, []byte("SSH-")) {
		m.Kind = KindVersion
		m.Version = strings.TrimRight(string(s.buf), "\r\n")
	}
	s.buf, s.pre = nil, nil
	return m, true
}

func (s *Stream) next() (Message, bool) {
	if !s.version {
		return s.nextLine()
	}
	return s.nextPacket()
}

// nextLine collects lines up to the identification string; like the RFC 4253
// limit x/crypto applies, all of them together must fit in maxLine bytes.
func (s *Stream) nextLine() (Message, bool) {
	i := bytes.IndexByte(s.buf, '\n')
	if i < 0 {
		if len(s.pre)+len(s.buf) > maxLine {
			return s.invalid(), true
		}
		return Message{}, false
	}
	if len(s.pre)+i+1 > maxLine {
		return s.invalid(), true
	}
	raw := s.take(i + 1)
	line := strings.TrimRight(string(raw), "\r\n")
	if !strings.HasPrefix(line, "SSH-") {
		s.pre = append(s.pre, raw...)
		return s.next()
	}
	s.version = true
	return Message{Kind: KindVersion, Raw: raw, Version: line}, true
}

func (s *Stream) nextPacket() (Message, bool) {
	if len(s.buf) < 5 {
		return Message{}, false
	}
	length := binary.BigEndian.Uint32(s.buf)
	padding := uint32(s.buf[4])
	// packet_length covers padding_length, the payload (at least the message
	// number) and padding of at least 4 bytes
	if length > maxPacket || length < padding+2 || padding < 4 {
		return s.invalid(), true
	}
	if uint32(len(s.buf)-4) < length {
		return Message{}, false
	}
	raw := s.take(int(length) + 4)
	s.done = true
	payload := raw[5 : 4+length-padding]
	if k, err := ParseKexInit(payload); err == nil {
		return Message{Kind: KindKexInit, Raw: raw, KexInit: k}, true
	}
	return Message{Kind: KindPacket, Raw: raw}, true
}

func (s *Stream) invalid() Message {
	s.done = true
	raw := append(s.pre, s.buf...)
	s.buf, s.pre = nil, nil
	return Message{Kind: KindInvalid, Raw: raw}
}

func (s *Stream) take(n int) []byte {
	raw := append([]byte(nil), s.buf[:n]...)
	s.buf = s.buf[n:]
	return raw
}
