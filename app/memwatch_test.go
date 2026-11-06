package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseStatmRSS(t *testing.T) {
	rss, err := parseStatmRSS([]byte("1141438 421080 1194 9000 0 500000 0\n"), 4096)
	require.NoError(t, err)
	require.Equal(t, uint64(421080*4096), rss)

	_, err = parseStatmRSS([]byte("1141438"), 4096)
	require.Error(t, err)
	_, err = parseStatmRSS([]byte("1 x"), 4096)
	require.Error(t, err)
}

func TestProcRSS(t *testing.T) {
	if _, err := os.Stat("/proc/self/statm"); err != nil {
		t.Skip("no /proc")
	}
	rss, err := procRSS()
	require.NoError(t, err)
	require.Greater(t, rss, uint64(0))
}

func TestMemWatcherDumpsPerStepAndRearms(t *testing.T) {
	const mib = 1 << 20
	dir := t.TempDir()
	w, err := newMemWatcher(memWatchConfig{Threshold: 600 * mib, Step: 256 * mib, Dir: dir, MaxDumps: 3},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	var rss uint64
	w.rss = func() (uint64, error) { return rss, nil }
	clock := time.Date(2026, 11, 6, 14, 30, 0, 0, time.UTC)
	w.now = func() time.Time { clock = clock.Add(time.Second); return clock }

	// spike: one dump at the threshold, another only after a further Step
	steps := []struct {
		rss  uint64
		dump bool
	}{
		{300 * mib, false},
		{599 * mib, false},
		{650 * mib, true},
		{800 * mib, false},
		{906 * mib, true},
		{1000 * mib, false},
		{1200 * mib, true},
		// back below the threshold re-arms; the next crossing dumps again
		{300 * mib, false},
		{610 * mib, true},
	}
	var dumps []string
	for i, s := range steps {
		rss = s.rss
		got := w.check()
		require.Equal(t, s.dump, got != "", "step %d rss %d MiB", i, s.rss/mib)
		if got != "" {
			dumps = append(dumps, got)
		}
	}
	require.Len(t, dumps, 4)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 3, "pruned to MaxDumps")
	_, err = os.Stat(dumps[0])
	require.True(t, os.IsNotExist(err), "oldest dump removed")

	last := dumps[len(dumps)-1]
	require.True(t, strings.HasSuffix(last, "-rss610"), last)
	for _, f := range []string{"goroutine.txt", "status.txt", "heap.pb.gz", "allocs.pb.gz"} {
		st, err := os.Stat(filepath.Join(last, f))
		require.NoError(t, err, f)
		require.Greater(t, st.Size(), int64(0), f)
	}
	status, err := os.ReadFile(filepath.Join(last, "status.txt"))
	require.NoError(t, err)
	require.Contains(t, string(status), "rss_bytes: 639631360")
	require.Contains(t, string(status), "non_go_bytes_estimate:")
	stacks, err := os.ReadFile(filepath.Join(last, "goroutine.txt"))
	require.NoError(t, err)
	require.Contains(t, string(stacks), "goroutine ")
}

func TestNewMemWatcherRequiresThreshold(t *testing.T) {
	_, err := newMemWatcher(memWatchConfig{Dir: t.TempDir()}, slog.Default())
	require.Error(t, err)
}
