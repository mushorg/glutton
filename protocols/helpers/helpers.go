package helpers

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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

func Store(data []byte, folder string) (string, error) {
	sum := sha256.Sum256(data)
	if err := os.MkdirAll(folder, os.ModePerm); err != nil {
		return "", err
	}
	sha256Hash := hex.EncodeToString(sum[:])
	path := filepath.Join(folder, sha256Hash)
	if _, err := os.Stat(path); err == nil {
		// already stored: same content, same hash
		return sha256Hash, nil
	}
	out, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err = out.Write(data); err != nil {
		return "", err
	}
	return sha256Hash, nil
}
