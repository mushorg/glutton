package ntlm

// Minimal DER encode/parse for SPNEGO tokens and CredSSP TSRequest fields.
// Only definite-length encoding is produced.

// Len encodes a definite length in DER form.
func Len(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0xff)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

// TLV builds a DER TLV with the given tag and value bytes.
func TLV(tag byte, value []byte) []byte {
	lenb := Len(len(value))
	out := make([]byte, 1+len(lenb)+len(value))
	out[0] = tag
	copy(out[1:], lenb)
	copy(out[1+len(lenb):], value)
	return out
}

// Value checks that data begins with the expected tag and returns its value bytes.
func Value(data []byte, tag byte) []byte {
	if len(data) < 2 || data[0] != tag {
		return nil
	}
	v, _, ok := parseLength(data[1:])
	if !ok {
		return nil
	}
	return v
}

// Next splits off the first TLV from data, returning tag, value, and the remaining bytes.
func Next(data []byte) (tag byte, value []byte, rest []byte) {
	if len(data) < 2 {
		return 0, nil, nil
	}
	tag = data[0]
	val, hdr, ok := parseLength(data[1:])
	if !ok {
		return 0, nil, nil
	}
	return tag, val, data[1+hdr+len(val):]
}

func parseLength(data []byte) (value []byte, hdrBytes int, ok bool) {
	if len(data) == 0 {
		return nil, 0, false
	}
	b := data[0]
	if b < 0x80 {
		l := int(b)
		if 1+l > len(data) {
			return nil, 0, false
		}
		return data[1 : 1+l], 1, true
	}
	n := int(b & 0x7f)
	if n == 0 || 1+n > len(data) {
		return nil, 0, false
	}
	var l int
	for i := range n {
		l = l<<8 | int(data[1+i])
	}
	hdr := 1 + n
	if hdr+l > len(data) {
		return nil, 0, false
	}
	return data[hdr : hdr+l], hdr, true
}
