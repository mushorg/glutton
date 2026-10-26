package helpers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func putFile(t *testing.T, s *fileStore, dir string, data string) string {
	t.Helper()
	path := filepath.Join(dir, SHA256Hex([]byte(data)))
	require.NoError(t, s.put(dir, path, []byte(data)))
	return path
}

func TestFileStoreEvictsOldestOverByteLimit(t *testing.T) {
	dir := t.TempDir()
	s := newFileStore(StoreLimits{MaxBytes: 10})
	a := putFile(t, s, dir, "aaaa")
	b := putFile(t, s, dir, "bbbb")
	c := putFile(t, s, dir, "cccc")

	require.NoFileExists(t, a)
	require.FileExists(t, b)
	require.FileExists(t, c)
	require.Equal(t, int64(8), s.bytes)
}

func TestFileStoreEvictsOldestOverFileLimit(t *testing.T) {
	dir := t.TempDir()
	s := newFileStore(StoreLimits{MaxFiles: 2})
	a := putFile(t, s, dir, "a")
	b := putFile(t, s, dir, "b")
	c := putFile(t, s, dir, "c")

	require.NoFileExists(t, a)
	require.FileExists(t, b)
	require.FileExists(t, c)
	require.Equal(t, 2, s.files.Len())
}

func TestFileStoreKnownContentIsNotCountedTwice(t *testing.T) {
	dir := t.TempDir()
	s := newFileStore(StoreLimits{MaxFiles: 2})
	a := putFile(t, s, dir, "a")
	putFile(t, s, dir, "a")
	b := putFile(t, s, dir, "b")

	require.FileExists(t, a)
	require.FileExists(t, b)
	require.Equal(t, 2, s.files.Len())
	require.Equal(t, int64(2), s.bytes)
}

func TestFileStoreRejectsDataOverByteLimit(t *testing.T) {
	dir := t.TempDir()
	s := newFileStore(StoreLimits{MaxBytes: 4})
	a := putFile(t, s, dir, "aaaa")

	err := s.put(dir, filepath.Join(dir, "big"), []byte("toolarge"))
	require.ErrorIs(t, err, ErrStoreTooLarge)
	// nothing was evicted for data that can never fit
	require.FileExists(t, a)
	require.NoFileExists(t, filepath.Join(dir, "big"))
}

func TestFileStoreIndexesExistingFilesOldestFirst(t *testing.T) {
	payloads := t.TempDir()
	samples := t.TempDir()
	now := time.Now()
	old := filepath.Join(payloads, "old")
	older := filepath.Join(samples, "older")
	newer := filepath.Join(samples, "newer")
	for path, age := range map[string]time.Duration{old: 2 * time.Hour, older: 3 * time.Hour, newer: time.Hour} {
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))
		require.NoError(t, os.Chtimes(path, now.Add(-age), now.Add(-age)))
	}
	require.NoError(t, os.Mkdir(filepath.Join(samples, "sub"), 0o755))

	s := newFileStore(StoreLimits{MaxFiles: 3})
	putFile(t, s, payloads, "a") // indexes old, evicts nothing
	require.FileExists(t, old)
	// indexes older and newer (merged by age), then makes room for b
	b := putFile(t, s, samples, "b")
	require.NoFileExists(t, older)
	require.NoFileExists(t, old)
	require.FileExists(t, newer)
	require.FileExists(t, b)
	require.DirExists(t, filepath.Join(samples, "sub"))
	require.Equal(t, 3, s.files.Len())
}

func TestConfigureStoreEvictsToNewLimits(t *testing.T) {
	prev := store
	store = newFileStore(StoreLimits{})
	t.Cleanup(func() { store = prev })
	dir := t.TempDir()

	first, err := Store([]byte("first"), dir)
	require.NoError(t, err)
	second, err := Store([]byte("second"), dir)
	require.NoError(t, err)

	ConfigureStore(StoreLimits{MaxFiles: 1})
	require.NoFileExists(t, filepath.Join(dir, first))
	require.FileExists(t, filepath.Join(dir, second))
}
