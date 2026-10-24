package helpers

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestReadLineCapsAndDrainsLongLine(t *testing.T) {
	// small bufio buffer so the long line spans several ReadSlice calls
	long := strings.Repeat("a", 100)
	r := bufio.NewReaderSize(strings.NewReader(long+"\nnext\npartial"), 16)

	line, truncated, err := ReadLine(r, 10)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Equal(t, strings.Repeat("a", 10), string(line))

	line, truncated, err = ReadLine(r, 10)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, "next\n", string(line))

	line, truncated, err = ReadLine(r, 10)
	require.ErrorIs(t, err, io.EOF)
	require.False(t, truncated)
	require.Equal(t, "partial", string(line))
}

func TestReadLineExactLimitKeepsDelimiter(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("abcd\n"))
	line, truncated, err := ReadLine(r, 5)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, "abcd\n", string(line))
}
