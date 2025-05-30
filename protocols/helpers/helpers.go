package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

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
		// file already exists
		return "", nil
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
