package smb

// Minimal DER/BER encoding, enough to build the SPNEGO tokens that wrap NTLMSSP
// in SMB Session Setup. Only definite-length encoding is produced.

// berLen encodes a definite length in DER form.
func berLen(n int) []byte {
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

// berTLV wraps content in a tag-length-value with the given identifier byte.
func berTLV(tag byte, content []byte) []byte {
	out := append([]byte{tag}, berLen(len(content))...)
	return append(out, content...)
}
