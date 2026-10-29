// Package netbios encodes and decodes first-level NetBIOS names (RFC 1001 §14.1).
package netbios

// Decode decodes one first-level encoded name: a 0x20 length byte, 32
// 'A'..'P' half-ASCII characters, then scope labels up to a zero byte.
// name is the first 15 bytes with trailing spaces and NULs removed; suffix
// is the 16th byte. n is the number of bytes consumed, including the scope.
func Decode(b []byte) (name string, suffix byte, n int, ok bool) {
	const encodedLen = 32
	if len(b) < 1+encodedLen || b[0] != encodedLen {
		return "", 0, 0, false
	}
	raw := make([]byte, encodedLen/2)
	for i := range raw {
		hi, lo := b[1+2*i]-'A', b[2+2*i]-'A'
		if hi > 0x0f || lo > 0x0f {
			return "", 0, 0, false
		}
		raw[i] = hi<<4 | lo
	}
	n = 1 + encodedLen
	for n < len(b) && b[n] != 0 {
		label := int(b[n])
		if label == 0 || n+1+label > len(b) {
			return "", 0, 0, false
		}
		n += 1 + label
	}
	if n >= len(b) {
		return "", 0, 0, false
	}
	n++ // terminating zero label
	suffix = raw[15]
	name = trimRight(raw[:15])
	return name, suffix, n, true
}

// Encode first-level encodes label padded with spaces to 15 bytes, plus suffix.
// The result has no scope (a single zero label).
func Encode(label string, suffix byte) []byte {
	raw := make([]byte, 16)
	for i := range raw[:15] {
		raw[i] = ' '
	}
	copy(raw[:15], label)
	raw[15] = suffix
	out := make([]byte, 0, 1+32+1)
	out = append(out, 32)
	for _, c := range raw {
		out = append(out, 'A'+c>>4, 'A'+c&0x0f)
	}
	return append(out, 0x00)
}

func trimRight(b []byte) string {
	i := len(b)
	for i > 0 && (b[i-1] == ' ' || b[i-1] == 0) {
		i--
	}
	return string(b[:i])
}
