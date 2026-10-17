// Package dht parses BitTorrent DHT (BEP 5) queries and builds responses.
// It does no I/O and never participates in a real swarm.
package dht

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	NodeIDLen       = 20
	CompactNode4Len = 26 // 20-byte id + 4-byte IPv4 + 2-byte port
	CompactNode6Len = 38 // 20-byte id + 16-byte IPv6 + 2-byte port
	MaxTransaction  = 64
	MaxString       = 256
)

// Query method names (BEP 5).
const (
	MethodPing         = "ping"
	MethodFindNode     = "find_node"
	MethodGetPeers     = "get_peers"
	MethodAnnouncePeer = "announce_peer"
)

var (
	ErrMalformed = errors.New("malformed DHT message")
	ErrNotQuery  = errors.New("not a DHT query")
)

// Query is a parsed DHT query (y=q).
type Query struct {
	Method      string // ping, find_node, get_peers, announce_peer
	Transaction []byte
	ID          []byte // querier node id
	Target      []byte // find_node target
	InfoHash    []byte // get_peers / announce_peer
	Want        []string
	Port        int
	Token       []byte
	ImpliedPort bool
}

// LooksLikeDHT reports whether data is a bencoded DHT query for a known method.
func LooksLikeDHT(data []byte) bool {
	if len(data) < 20 || data[0] != 'd' || data[len(data)-1] != 'e' {
		return false
	}
	if !bytes.Contains(data, []byte("1:y1:q")) {
		return false
	}
	for _, q := range []string{"4:ping", "9:find_node", "9:get_peers", "13:announce_peer"} {
		if bytes.Contains(data, []byte(q)) {
			return true
		}
	}
	return false
}

// ParseQuery decodes a DHT query. Non-query messages return ErrNotQuery.
func ParseQuery(data []byte) (Query, error) {
	v, err := decode(data)
	if err != nil {
		return Query{}, err
	}
	root, ok := v.(map[string]any)
	if !ok {
		return Query{}, ErrMalformed
	}
	y, _ := asBytes(root["y"])
	if string(y) != "q" {
		return Query{}, ErrNotQuery
	}
	qname, _ := asBytes(root["q"])
	t, _ := asBytes(root["t"])
	if len(t) == 0 || len(t) > MaxTransaction {
		return Query{}, ErrMalformed
	}
	method := string(qname)
	switch method {
	case MethodPing, MethodFindNode, MethodGetPeers, MethodAnnouncePeer:
	default:
		return Query{}, fmt.Errorf("%w: unknown method %q", ErrMalformed, method)
	}
	args, _ := root["a"].(map[string]any)
	if args == nil {
		return Query{}, ErrMalformed
	}
	id, _ := asBytes(args["id"])
	if len(id) != NodeIDLen {
		return Query{}, ErrMalformed
	}
	q := Query{
		Method:      method,
		Transaction: append([]byte(nil), t...),
		ID:          append([]byte(nil), id...),
		Want:        parseWant(args["want"]),
	}
	if target, ok := asBytes(args["target"]); ok && len(target) == NodeIDLen {
		q.Target = append([]byte(nil), target...)
	}
	if ih, ok := asBytes(args["info_hash"]); ok && len(ih) == NodeIDLen {
		q.InfoHash = append([]byte(nil), ih...)
	}
	if token, ok := asBytes(args["token"]); ok {
		q.Token = append([]byte(nil), token...)
	}
	if p, ok := asInt(args["port"]); ok && p >= 0 && p <= 65535 {
		q.Port = int(p)
	}
	if ip, ok := asInt(args["implied_port"]); ok && ip != 0 {
		q.ImpliedPort = true
	}
	switch method {
	case MethodFindNode:
		if len(q.Target) != NodeIDLen {
			return Query{}, ErrMalformed
		}
	case MethodGetPeers, MethodAnnouncePeer:
		if len(q.InfoHash) != NodeIDLen {
			return Query{}, ErrMalformed
		}
	}
	return q, nil
}

// Hex returns a hex encoding of b, or "" when empty.
func Hex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}

// CompactNode4 packs a 26-byte IPv4 compact node info.
func CompactNode4(id [NodeIDLen]byte, ip net.IP, port int) []byte {
	ip4 := ip.To4()
	if ip4 == nil || port < 0 || port > 65535 {
		return nil
	}
	out := make([]byte, CompactNode4Len)
	copy(out, id[:])
	copy(out[20:], ip4)
	binary.BigEndian.PutUint16(out[24:], uint16(port))
	return out
}

// CompactNode6 packs a 38-byte IPv6 compact node info.
func CompactNode6(id [NodeIDLen]byte, ip net.IP, port int) []byte {
	if ip == nil || ip.To4() != nil || port < 0 || port > 65535 {
		return nil
	}
	ip6 := ip.To16()
	if ip6 == nil {
		return nil
	}
	out := make([]byte, CompactNode6Len)
	copy(out, id[:])
	copy(out[20:], ip6)
	binary.BigEndian.PutUint16(out[36:], uint16(port))
	return out
}

// BuildResponse builds a BEP 5 response for q. The reply is never larger than
// maxLen (pass the request size). Returns nil when even a minimal reply would
// amplify.
func BuildResponse(q Query, ourID [NodeIDLen]byte, self *net.UDPAddr, maxLen int) []byte {
	if maxLen < 1 || len(q.Transaction) == 0 {
		return nil
	}
	r := map[string]any{
		"id": append([]byte(nil), ourID[:]...),
	}
	switch q.Method {
	case MethodFindNode, MethodGetPeers:
		want4, want6 := wantFlags(q.Want)
		if want4 {
			nodes := []byte{}
			if self != nil {
				if n := CompactNode4(ourID, self.IP, self.Port); n != nil {
					nodes = n
				}
			}
			r["nodes"] = nodes
		}
		if want6 {
			nodes6 := []byte{}
			if self != nil {
				if n := CompactNode6(ourID, self.IP, self.Port); n != nil {
					nodes6 = n
				}
			}
			r["nodes6"] = nodes6
		}
		if q.Method == MethodGetPeers {
			// Short token so announce_peer follow-ups can be correlated; never
			// validated against a real swarm.
			r["token"] = []byte("gt")
		}
	}

	try := func(resp map[string]any) []byte {
		return encode(map[string]any{
			"t": append([]byte(nil), q.Transaction...),
			"y": []byte("r"),
			"r": resp,
		})
	}

	out := try(r)
	if len(out) <= maxLen {
		return out
	}
	// Drop optional fields until the reply fits (never amplify).
	delete(r, "nodes6")
	out = try(r)
	if len(out) <= maxLen {
		return out
	}
	delete(r, "nodes")
	delete(r, "token")
	out = try(r)
	if len(out) <= maxLen {
		return out
	}
	return nil
}

func wantFlags(want []string) (want4, want6 bool) {
	if len(want) == 0 {
		return true, false
	}
	for _, w := range want {
		switch w {
		case "n4":
			want4 = true
		case "n6":
			want6 = true
		}
	}
	return want4, want6
}

func parseWant(v any) []string {
	switch x := v.(type) {
	case []byte:
		s := string(x)
		var out []string
		if strings.Contains(s, "n4") {
			out = append(out, "n4")
		}
		if strings.Contains(s, "n6") {
			out = append(out, "n6")
		}
		return out
	case []any:
		var out []string
		for _, e := range x {
			b, ok := asBytes(e)
			if !ok {
				continue
			}
			switch string(b) {
			case "n4", "n6":
				out = append(out, string(b))
			}
		}
		return out
	}
	return nil
}

func asBytes(v any) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}

func asInt(v any) (int64, bool) {
	n, ok := v.(int64)
	return n, ok
}

func encode(v any) []byte {
	var buf bytes.Buffer
	writeValue(&buf, v)
	return buf.Bytes()
}

func writeValue(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case []byte:
		buf.WriteString(strconv.Itoa(len(x)))
		buf.WriteByte(':')
		buf.Write(x)
	case string:
		writeValue(buf, []byte(x))
	case int:
		writeValue(buf, int64(x))
	case int64:
		buf.WriteByte('i')
		buf.WriteString(strconv.FormatInt(x, 10))
		buf.WriteByte('e')
	case map[string]any:
		buf.WriteByte('d')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			writeValue(buf, []byte(k))
			writeValue(buf, x[k])
		}
		buf.WriteByte('e')
	case []any:
		buf.WriteByte('l')
		for _, e := range x {
			writeValue(buf, e)
		}
		buf.WriteByte('e')
	default:
		// Unsupported types are encoded as empty string so callers stay safe.
		writeValue(buf, []byte{})
	}
}

func decode(data []byte) (any, error) {
	v, n, err := parseValue(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, ErrMalformed
	}
	return v, nil
}

func parseValue(data []byte) (any, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrMalformed
	}
	switch data[0] {
	case 'i':
		end := bytes.IndexByte(data, 'e')
		if end < 2 {
			return nil, 0, ErrMalformed
		}
		n, err := strconv.ParseInt(string(data[1:end]), 10, 64)
		if err != nil {
			return nil, 0, ErrMalformed
		}
		return n, end + 1, nil
	case 'l':
		var list []any
		i := 1
		for i < len(data) && data[i] != 'e' {
			v, n, err := parseValue(data[i:])
			if err != nil {
				return nil, 0, err
			}
			list = append(list, v)
			i += n
		}
		if i >= len(data) || data[i] != 'e' {
			return nil, 0, ErrMalformed
		}
		return list, i + 1, nil
	case 'd':
		m := make(map[string]any)
		i := 1
		for i < len(data) && data[i] != 'e' {
			k, n, err := parseValue(data[i:])
			if err != nil {
				return nil, 0, err
			}
			kb, ok := k.([]byte)
			if !ok || len(kb) > MaxString {
				return nil, 0, ErrMalformed
			}
			i += n
			v, n, err := parseValue(data[i:])
			if err != nil {
				return nil, 0, err
			}
			m[string(kb)] = v
			i += n
		}
		if i >= len(data) || data[i] != 'e' {
			return nil, 0, ErrMalformed
		}
		return m, i + 1, nil
	default:
		if data[0] < '0' || data[0] > '9' {
			return nil, 0, ErrMalformed
		}
		colon := bytes.IndexByte(data, ':')
		if colon < 1 {
			return nil, 0, ErrMalformed
		}
		length, err := strconv.Atoi(string(data[:colon]))
		if err != nil || length < 0 || length > MaxString {
			return nil, 0, ErrMalformed
		}
		start := colon + 1
		end := start + length
		if end > len(data) {
			return nil, 0, ErrMalformed
		}
		return append([]byte(nil), data[start:end]...), end, nil
	}
}
