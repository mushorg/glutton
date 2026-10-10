package helpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreReturnsHashForKnownContent(t *testing.T) {
	dir := t.TempDir()
	data := []byte("sample")

	first, err := Store(data, dir)
	require.NoError(t, err)
	require.Equal(t, SHA256Hex(data), first)

	// a payload seen before keeps its hash in later events
	again, err := Store(data, dir)
	require.NoError(t, err)
	require.Equal(t, first, again)

	stored, err := os.ReadFile(filepath.Join(dir, first))
	require.NoError(t, err)
	require.Equal(t, data, stored)
}
