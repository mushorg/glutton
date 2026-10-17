package banners

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// Bitcoin P2P wire format: every message is a 24-byte header (network magic,
// NUL-padded command, little-endian payload length, double-SHA256 checksum)
// followed by the payload. Litecoin Core speaks the same framing with its own
// magic, so both are described by a btcNetwork.
const (
	btcHeaderLen = 24
	// btcMaxPayload is Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH.
	btcMaxPayload = 4_000_000
)

// btcNetwork is one mainnet P2P network: the node personality advertised in
// the version message and the prefix of the response names.
type btcNetwork struct {
	name            string
	magic           []byte
	protocolVersion uint32
	services        uint64
	userAgent       string
	// the advertised height was anchorHeight at anchorTime and grows by one
	// block per blockSeconds from there
	anchorHeight int64
	anchorTime   int64
	blockSeconds int64
}

// bitcoinNet is Bitcoin Core 28.1. Services are NODE_NETWORK | NODE_WITNESS |
// NODE_NETWORK_LIMITED: a full node with v2transport off, so clients do not
// try BIP324 on the next connection. The anchor is the April 2024 halving.
// Only mainnet is emulated so the advertised height stays plausible.
var bitcoinNet = btcNetwork{
	name:            "bitcoin",
	magic:           []byte{0xf9, 0xbe, 0xb4, 0xd9},
	protocolVersion: 70016,
	services:        1 | 8 | 1024,
	userAgent:       "/Satoshi:28.1.0/",
	anchorHeight:    840000,
	anchorTime:      1713571767,
	blockSeconds:    600,
}

// litecoinNet is Litecoin Core 0.21.x. The protocol version, the NODE_MWEB
// service bit (1<<24) and the anchor (the August 2023 halving, block 2520000,
// 2.5 minute blocks) are from memory of the Litecoin sources and public node
// lists, not from a captured node.
var litecoinNet = btcNetwork{
	name:            "litecoin",
	magic:           []byte{0xfb, 0xc0, 0xb6, 0xdb},
	protocolVersion: 70015,
	services:        1 | 8 | 1024 | 1<<24,
	userAgent:       "/LitecoinCore:0.21.4/",
	anchorHeight:    2520000,
	anchorTime:      1690977600,
	blockSeconds:    150,
}

// btcCommands are the message types that name the response; anything else
// with a valid header is tagged with the plain network name.
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

// btcMessages splits data into mainnet P2P messages of network n. The first
// message must have a complete, valid header; parsing stops at trailing bytes
// that are not one.
func btcMessages(n btcNetwork, data []byte) ([]btcMessage, bool) {
	var msgs []btcMessage
	for len(data) >= btcHeaderLen && bytes.Equal(data[:4], n.magic) {
		command, ok := btcCommand(data[4:16])
		length := binary.LittleEndian.Uint32(data[16:20])
		if !ok || length > btcMaxPayload {
			break
		}
		data = data[btcHeaderLen:]
		size := min(int(length), len(data))
		msgs = append(msgs, btcMessage{command: command, payload: data[:size]})
		data = data[size:]
	}
	return msgs, len(msgs) > 0
}

// btcFrame frames a payload with the mainnet header of network n.
func btcFrame(n btcNetwork, command string, payload []byte) []byte {
	sum := sha256.Sum256(payload)
	sum = sha256.Sum256(sum[:])
	b := make([]byte, btcHeaderLen, btcHeaderLen+len(payload))
	copy(b, n.magic)
	copy(b[4:16], command)
	binary.LittleEndian.PutUint32(b[16:20], uint32(len(payload)))
	copy(b[20:24], sum[:4])
	return append(b, payload...)
}

// btcVersion builds a Core version payload: the peer's address and our own
// are sent zeroed, as Core does for peers it cannot vouch for.
func btcVersion(n btcNetwork) []byte {
	t := now().Unix()
	b := binary.LittleEndian.AppendUint32(nil, n.protocolVersion)
	b = binary.LittleEndian.AppendUint64(b, n.services)
	b = binary.LittleEndian.AppendUint64(b, uint64(t))
	b = append(b, make([]byte, 26)...) // addr_recv: services 0, ::, port 0
	b = binary.LittleEndian.AppendUint64(b, n.services)
	b = append(b, make([]byte, 18)...) // addr_from: ::, port 0
	b = binary.LittleEndian.AppendUint64(b, bitcoinNonce())
	b = append(b, byte(len(n.userAgent)))
	b = append(b, n.userAgent...)
	b = binary.LittleEndian.AppendUint32(b, uint32(n.anchorHeight+max(t-n.anchorTime, 0)/n.blockSeconds))
	return append(b, 1) // relay
}

// btcReply answers mainnet P2P messages of network n like a full node: a
// version gets our version and a verack, a ping gets a pong with its nonce,
// and anything else gets no reply while the connection stays open.
func btcReply(n btcNetwork, data []byte) (Response, bool) {
	msgs, ok := btcMessages(n, data)
	if !ok {
		return Response{}, false
	}
	name := n.name
	if btcCommands[msgs[0].command] {
		name += "-" + msgs[0].command
	}
	var out []byte
	for _, m := range msgs {
		switch {
		case m.command == "version":
			out = append(out, btcFrame(n, "version", btcVersion(n))...)
			out = append(out, btcFrame(n, "verack", nil)...)
		case m.command == "ping" && len(m.payload) == 8:
			out = append(out, btcFrame(n, "pong", m.payload)...)
		}
	}
	return Response{Name: name, Data: out, NoReply: len(out) == 0}, true
}

func bitcoinReply(data []byte) (Response, bool) { return btcReply(bitcoinNet, data) }

func litecoinReply(data []byte) (Response, bool) { return btcReply(litecoinNet, data) }
