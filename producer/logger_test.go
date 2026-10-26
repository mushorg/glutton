package producer

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
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
