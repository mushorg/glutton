package producer

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/mushorg/glutton/protocols/guard"
	"github.com/stretchr/testify/require"
)

func TestSourceLimitHandlerDropsFloodInfo(t *testing.T) {
	// SOCKS flood from 149.86.227.0/24 logged a "SOCKS request" Info line
	// per connection from each address
	SetLogLimit(guard.New(guard.Config{
		Enabled: true, SourceRate: 1 << 20, SourceBurst: 1 << 20,
		SourceRequestRate: 1, SourceRequestBurst: 2,
		SourcePrefixV4: 24,
	}))
	t.Cleanup(func() { SetLogLimit(nil) })

	var buf bytes.Buffer
	logger := slog.New(&sourceLimitHandler{next: slog.NewJSONHandler(&buf, nil)}).With(slog.String("sensorID", "s"))
	for _, ip := range []string{"149.86.227.29", "149.86.227.30", "149.86.227.97", "149.86.227.140", "149.86.227.230"} {
		logger.Info("SOCKS request", slog.String("src_ip", ip))
	}
	logger.Warn("Dropping TCP replies over the reply budget", slog.String("src_ip", "149.86.227.29"))
	logger.Info("Loading configurations")
	logger.Info("SOCKS request", slog.String("src_ip", "198.51.100.7"))

	var msgs []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		require.Equal(t, "s", rec["sensorID"])
		msgs = append(msgs, rec["level"].(string)+" "+rec["msg"].(string))
	}
	require.Equal(t, []string{
		"INFO SOCKS request",
		"INFO SOCKS request",
		"WARN Dropping log lines over the log budget", // once, not per dropped line
		"WARN Dropping TCP replies over the reply budget",
		"INFO Loading configurations",
		"INFO SOCKS request",
	}, msgs)
}

func TestSourceLimitHandlerUnsetPassesAll(t *testing.T) {
	SetLogLimit(nil)
	var buf bytes.Buffer
	logger := slog.New(&sourceLimitHandler{next: slog.NewJSONHandler(&buf, nil)})
	for range 50 {
		logger.Info("SOCKS request", slog.String("src_ip", "149.86.227.29"))
	}
	require.Equal(t, 50, strings.Count(buf.String(), "\n"))
}

func TestLogFileSkipsNonRegularPaths(t *testing.T) {
	// the --logpath default /dev/null was handed to lumberjack, which rotated
	// it at 200 MB: it renamed the device away and created a regular
	// /dev/null in devtmpfs, so every process on the host wrote into RAM
	// until the sensor was OOM-killed
	require.Nil(t, logFile(""))
	require.Nil(t, logFile(os.DevNull))

	fifo := filepath.Join(t.TempDir(), "log.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	require.Nil(t, logFile(fifo))
	require.Nil(t, logFile(t.TempDir()))

	// /dev/null is still the character device
	fi, err := os.Stat(os.DevNull)
	require.NoError(t, err)
	require.NotZero(t, fi.Mode()&os.ModeCharDevice)
}

func TestLogFileWritesRegularPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "glutton.log")
	var stdout bytes.Buffer
	w := &TeeWriter{stdout: &stdout, file: logFile(path)}
	_, err := w.Write([]byte("line\n"))
	require.NoError(t, err)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "line\n", string(got))
	require.Equal(t, "line\n", stdout.String())

	// an existing regular file is appended to
	w = &TeeWriter{stdout: &stdout, file: logFile(path)}
	_, err = w.Write([]byte("more\n"))
	require.NoError(t, err)
	got, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "line\nmore\n", string(got))
}

func TestTeeWriterStdoutOnly(t *testing.T) {
	var stdout bytes.Buffer
	w := &TeeWriter{stdout: &stdout, file: logFile(os.DevNull)}
	n, err := w.Write([]byte("line\n"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, "line\n", stdout.String())
}
