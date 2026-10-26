package helpers

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
)

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ReadLine reads up to and including '\n' like bufio.Reader.ReadBytes, but
// keeps at most limit bytes. The rest of an over-long line is read and dropped,
// so the next call starts on the following line, and truncated reports it.
// Memory stays bounded however long the line is; the connection deadline
// bounds the time spent draining it.
func ReadLine(r *bufio.Reader, limit int) (line []byte, truncated bool, err error) {
	for {
		chunk, err := r.ReadSlice('\n')
		if room := limit - len(line); len(chunk) > room {
			chunk = chunk[:max(room, 0)]
			truncated = true
		}
		line = append(line, chunk...)
		if err != bufio.ErrBufferFull {
			return line, truncated, err
		}
	}
}

func FirstOrEmpty[T any](s []T) T {
	if len(s) > 0 {
		return s[0]
	}
	var t T
	return t
}
