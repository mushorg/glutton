package banners

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// Bitcoin P2P wire format: every message is a 24-byte header (network magic,
// NUL-padded command, little-endian payload length, double-SHA256 checksum)
// followed by the payload.
const (
	btcHeaderLen = 24
	// btcMaxPayload is Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH.
	btcMaxPayload = 4_000_000

	btcProtocolVersion = 70016
	// NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED: a full node with
	// v2transport off, so clients do not try BIP324 on the next connection.
	btcServices  = 1 | 8 | 1024
	btcUserAgent = "/Satoshi:28.1.0/"

	// btcAnchorHeight was mined at btcAnchorTime (the April 2024 halving);
	// the advertised height grows by one block per ten minutes from it.
	btcAnchorHeight = 840000
	btcAnchorTime   = 1713571767
)

// btcMainnet is the mainnet network magic; only mainnet is emulated so the
// advertised height stays plausible.
var btcMainnet = []byte{0xf9, 0xbe, 0xb4, 0xd9}

// btcCommands are the message types that name the response; anything else
// with a valid header is tagged plain "bitcoin".
var btcCommands = map[string]bool{
	"version": true, "verack": true, "ping": true, "pong": true,
	"getaddr": true, "addr": true, "addrv2": true, "sendaddrv2": true,
	"sendheaders": true, "sendcmpct": true, "feefilter": true, "wtxidrelay": true,
	"getheaders": true, "getblocks": true, "headers": true, "inv": true,
	"getdata": true, "notfound": true, "mempool": true, "tx": true, "block": true,
}

// bitcoinNonce is replaced in tests for a stable version reply.
var bitcoinNonce = func() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

type btcMessage struct {
	command string
	payload []byte // may be shorter than the header length on a short read
}

// btcCommand returns the command of a 12-byte header field: printable ASCII
// followed only by NUL padding.
func btcCommand(field []byte) (string, bool) {
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = len(field)
	}
	if end == 0 {
		return "", false
	}
	for _, c := range field[:end] {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	for _, c := range field[end:] {
		if c != 0 {
			return "", false
		}
	}
	return string(field[:end]), true
}

// bitcoinMessages splits data into mainnet Bitcoin P2P messages. The first
// message must have a complete, valid header; parsing stops at trailing bytes
// that are not one.
func bitcoinMessages(data []byte) ([]btcMessage, bool) {
	var msgs []btcMessage
	for len(data) >= btcHeaderLen && bytes.Equal(data[:4], btcMainnet) {
		command, ok := btcCommand(data[4:16])
		length := binary.LittleEndian.Uint32(data[16:20])
		if !ok || length > btcMaxPayload {
			break
		}
		data = data[btcHeaderLen:]
		n := min(int(length), len(data))
		msgs = append(msgs, btcMessage{command: command, payload: data[:n]})
		data = data[n:]
	}
	return msgs, len(msgs) > 0
}

// btcFrame frames a payload with the mainnet header.
func btcFrame(command string, payload []byte) []byte {
	sum := sha256.Sum256(payload)
	sum = sha256.Sum256(sum[:])
	b := make([]byte, btcHeaderLen, btcHeaderLen+len(payload))
	copy(b, btcMainnet)
	copy(b[4:16], command)
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(payload)))
	copy(b[20:24], sum[:4])
	return append(b, payload...)
}

// btcVersion builds Bitcoin Core's version payload: the peer's address and
// our own are sent zeroed, as Core does for peers it cannot vouch for.
func btcVersion() []byte {
	t := now().Unix()
	b := binary.LittleEndian.AppendUint32(nil, btcProtocolVersion)
	b = binary.LittleEndian.AppendUint64(b, btcServices)
	b = binary.LittleEndian.AppendUint64(b, uint64(t))
	b = append(b, make([]byte, 26)...) // addr_recv: services 0, ::, port 0
	b = binary.LittleEndian.AppendUint64(b, btcServices)
	b = append(b, make([]byte, 18)...) // addr_from: ::, port 0
	b = binary.LittleEndian.AppendUint64(b, bitcoinNonce())
	b = append(b, byte(len(btcUserAgent)))
	b = append(b, btcUserAgent...)
	b = binary.LittleEndian.AppendUint32(b, uint32(btcAnchorHeight+max(t-btcAnchorTime, 0)/600))
	return append(b, 1) // relay
}

// bitcoinReply answers mainnet Bitcoin P2P messages like a full node: a
// version gets our version and a verack, a ping gets a pong with its nonce,
// and anything else gets no reply while the connection stays open.
func bitcoinReply(data []byte) (Response, bool) {
	msgs, ok := bitcoinMessages(data)
	if !ok {
		return Response{}, false
	}
	name := "bitcoin"
	if btcCommands[msgs[0].command] {
		name += "-" + msgs[0].command
	}
	var out []byte
	for _, m := range msgs {
		switch {
		case m.command == "version":
			out = append(out, btcFrame("version", btcVersion())...)
			out = append(out, btcFrame("verack", nil)...)
		case m.command == "ping" && len(m.payload) == 8:
			out = append(out, btcFrame("pong", m.payload)...)
		}
	}
	return Response{Name: name, Data: out, NoReply: len(out) == 0}, true
}
