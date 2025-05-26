package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
)

func FirstOrEmpty[T any](s []T) T {
	if len(s) > 0 {
		return s[0]
	}
	var t T
	return t
}

func StorePayload(data []byte, paths ...string) (string, error) {
	paths = append([]string{"payloads"}, paths...)
	path := path.Join(paths...)
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	sha256Hash := hex.EncodeToString(sum[:])
	filePath := filepath.Join(path, sha256Hash)
	if _, err := os.Stat(filePath); err == nil {
		// file already exists
		return "", nil
	}
	out, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err = out.Write(data); err != nil {
		return "", err
	}
	return sha256Hash, nil
}
