package glutton

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/ipopts"
	"github.com/mushorg/glutton/producer"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestIPOptsDirection(t *testing.T) {
	g := &Glutton{
		publicAddrs: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.1")},
	}
	require.Equal(t, "write", g.ipoptsDirection(net.ParseIP("192.0.2.10")))
	require.Equal(t, "write", g.ipoptsDirection(net.ParseIP("198.51.100.1")))
	require.Equal(t, "read", g.ipoptsDirection(net.ParseIP("203.0.113.10")))
	require.Equal(t, "read", g.ipoptsDirection(nil))
}

func TestProduceIPOptsFlow(t *testing.T) {
	var mu sync.Mutex
	var events []producer.Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var ev producer.Event
		require.NoError(t, json.Unmarshal(body, &ev))
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	prev := map[string]any{
		"producers.http.enabled": viper.Get("producers.http.enabled"),
		"producers.http.remote":  viper.Get("producers.http.remote"),
		"produce_limit.enabled":  viper.Get("produce_limit.enabled"),
	}
	t.Cleanup(func() {
		for k, v := range prev {
			viper.Set(k, v)
		}
	})
	viper.Set("producers.http.enabled", true)
	viper.Set("producers.http.remote", srv.URL)
	viper.Set("produce_limit.enabled", false)

	p, err := producer.New("test-sensor", "v0.0.0")
	require.NoError(t, err)
	g := &Glutton{Producer: p, Logger: slog.Default()}

	flow := ipopts.Flow{
		SrcIP:     net.ParseIP("203.0.113.10").To4(),
		DstIP:     net.ParseIP("192.0.2.10").To4(),
		SrcPort:   54321,
		DstPort:   80,
		Started:   time.Unix(1000, 0).UTC(),
		EndReason: connection.EndTimeout,
		Frames: []ipopts.Frame{{
			Direction: "read",
			Command:   "SYN",
			Options:   []ipopts.Option{{Type: 7, Name: "RR", Length: 7}},
			Payload:   []byte{0x45, 0x00},
		}},
	}
	g.produceIPOptsFlow(flow)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events) >= 1
	}, 2*time.Second, 20*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1)
	ev := events[0]
	require.Equal(t, "ipopts", ev.Handler)
	require.Equal(t, "tcp", ev.Transport)
	require.Equal(t, "203.0.113.10", ev.SrcHost)
	require.Equal(t, "54321", ev.SrcPort)
	require.EqualValues(t, 80, ev.DstPort)
	require.Equal(t, "192.0.2.10", ev.DstHost)
	require.Equal(t, connection.EndTimeout, ev.EndReason)
	require.EqualValues(t, 1, ev.FrameCount)
	require.Equal(t, []string{"tcp", "ipopts"}, ev.Handlers)
}

func TestWatchIPOptsDisabled(t *testing.T) {
	prev := viper.Get("ipopts_watch.enabled")
	t.Cleanup(func() { viper.Set("ipopts_watch.enabled", prev) })
	viper.Set("ipopts_watch.enabled", false)
	g := &Glutton{Logger: slog.Default()}
	g.watchIPOpts() // returns immediately when disabled
}
