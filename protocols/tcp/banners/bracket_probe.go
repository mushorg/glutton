package banners

import (
	"bytes"
	"strconv"
)

// bracketProbe matches a length-framed probe Shodan sends to unassigned high
// ports (tcp/55000, 209.38.70.156): three NULs, an outer "[<n>]\x00" whose n
// is the length of the rest, a NUL-terminated tag ("d"), then one or more
// "[<n>]\x00<n bytes>" fields (base64 "Remote"/"remote"):
//
//	\x00\x00\x00[38]\x00d\x00[8]\x00UmVtb3Rl[8]\x00cmVtb3Rl[8]\x00UmVtb3Rl
//
// The service it looks for is unidentified (no nmap match), so the catch-all
// stays silent instead of answering with random bytes no real service sends.
func bracketProbe(data []byte) bool {
	rest, ok := bytes.CutPrefix(data, []byte{0, 0, 0})
	if !ok {
		return false
	}
	n, rest, ok := bracketLen(rest)
	if !ok || n != len(rest) {
		return false
	}
	tag, rest, ok := bytes.Cut(rest, []byte{0})
	if !ok || len(tag) == 0 || bytes.ContainsAny(tag, "[]") {
		return false
	}
	fields := 0
	for len(rest) > 0 {
		n, rest, ok = bracketLen(rest)
		if !ok || n > len(rest) {
			return false
		}
		rest = rest[n:]
		fields++
	}
	return fields > 0
}

// bracketLen parses a leading "[<decimal>]\x00" and returns the number and
// the bytes after it.
func bracketLen(data []byte) (int, []byte, bool) {
	if len(data) < 4 || data[0] != '[' {
		return 0, nil, false
	}
	end := bytes.Index(data, []byte("]\x00"))
	if end < 2 || end > 6 {
		return 0, nil, false
	}
	n, err := strconv.Atoi(string(data[1:end]))
	if err != nil || n < 0 {
		return 0, nil, false
	}
	return n, data[end+2:], true
}
