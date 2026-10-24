package banners

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// SAProuter (tcp/3299) frames every message as an NI packet: a 4-byte
// big-endian length, then the body. When it refuses a client it sends an
// NI_RTERR packet and closes: "NI_RTERR\0", version 2, opcode 0, a padding
// byte, the signed BE return code, the length of the error text, the text (a
// NUL-separated "*ERR*" record) and 4 zero bytes. The record layout and the
// two messages below follow the nmap saprouter match lines: the NULL-probe
// "connection timed out" and "Network packet too big" (rc -93), which
// saprouter sends when the first 4 bytes, read as the NI length, exceed its
// 10024-byte buffer. The release, NI version, source line numbers and SP
// level are guesses.

const (
	saprouterMaxPacket = 10024
	saprouterRelease   = "753"
	saprouterNIVersion = "40"
)

// saprouterHost is the host name in the error location ("SAProuter 40.4
// (SP3) on '<host>'"), drawn once per run so sensors do not share it.
var saprouterHost = fmt.Sprintf("saprouter%02d", 1+rand.IntN(20))

// saprouterUnframed are the router message types a client sends without the
// NI length prefix (Shodan's ROUTER_ADM info request on tcp/3299, Ochi live
// stream 2026-10-24, garden.census.shodan.io).
var saprouterUnframed = [][]byte{[]byte("ROUTER_ADM\x00"), []byte("NI_ROUTE\x00"), []byte("NI_PING\x00")}

// saprouterError builds an NI_RTERR packet. nmap match: p/SAProuter/ v/$2
// SP$3/ i/local time: $1/ h/$4/.
func saprouterError(rc int32, errText, module, line, detail string) []byte {
	fields := []string{
		"*ERR*", "1", errText, strconv.Itoa(int(rc)), "NI (network interface)",
		saprouterRelease, saprouterNIVersion, module, line, detail,
		now().Format("Mon Jan _2 15:04:05 2006"),
		"", "", "", "1",
		"SAProuter " + saprouterNIVersion + ".4 (SP3) on '" + saprouterHost + "'",
		"", "", "", "", "*ERR*",
	}
	text := strings.Join(fields, "\x00") + "\x00"

	var body bytes.Buffer
	body.WriteString("NI_RTERR\x00")
	body.Write([]byte{2, 0, 0}) // version, opcode, padding
	_ = binary.Write(&body, binary.BigEndian, rc)
	_ = binary.Write(&body, binary.BigEndian, uint32(len(text)))
	body.WriteString(text)
	body.Write([]byte{0, 0, 0, 0})

	pkt := binary.BigEndian.AppendUint32(nil, uint32(body.Len()))
	return append(pkt, body.Bytes()...)
}

// saprouterTimeout is what saprouter sends a client that sent no complete
// route request within its 5s timeout, before closing.
func saprouterTimeout() []byte {
	return saprouterError(-5, "connection timed out", "nirout.cpp", "2860",
		"RTPENDLIST::timeoutPend: no route received within 5s (CONNECTED)")
}

// saprouterTooBig is saprouter's reply when the NI length in the first 4
// client bytes exceeds its buffer.
func saprouterTooBig(length uint32) []byte {
	return saprouterError(-93, "Network packet too big", "nibuf.cpp", "4022",
		"NiBufIIn: message length "+strconv.FormatUint(uint64(length), 10)+
			" exceeds max ("+strconv.Itoa(saprouterMaxPacket)+")")
}

// saprouterReply answers a router message sent without its NI length
// prefix: saprouter reads its first 4 bytes as the length.
func saprouterReply(data []byte) (Response, bool) {
	for _, prefix := range saprouterUnframed {
		if bytes.HasPrefix(data, prefix) {
			return Response{Name: "saprouter-too-big", Data: saprouterTooBig(binary.BigEndian.Uint32(data)), Close: true}, true
		}
	}
	return Response{}, false
}
