package glutton

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/guard"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/rules"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestPort2Protocol(t *testing.T) {
}

func TestNewGlutton(t *testing.T) {
	viper.Set("var-dir", "/tmp/glutton")
	viper.Set("confpath", "./config")
	g, err := New(context.Background())
	require.NoError(t, err, "error initializing glutton")
	require.NotNil(t, g, "nil instance but no error")
}

func TestProduceTCPSkipsWhenRuleProduceFalse(t *testing.T) {
	produceFalse := false
	g := &Glutton{Producer: &producer.Producer{}}
	err := g.ProduceTCP("proxy_tcp", nil, connection.Metadata{
		Rule: &rules.Rule{Produce: &produceFalse},
	}, nil, nil)
	require.NoError(t, err)
}

func TestSanitizePayloadUTF16(t *testing.T) {
	g := &Glutton{publicAddrs: []net.IP{net.ParseIP("192.0.2.10")}}
	ascii := []byte("unc \\\\192.0.2.10\\share")
	require.Equal(t, []byte("unc \\\\1.2.3.4\\share"), g.sanitizePayload(ascii))

	u16 := utf16LE("192.0.2.10")
	in := append([]byte{0xff, 0x00}, append(u16, 0x00, 0x00)...)
	out := g.sanitizePayload(in)
	require.Equal(t, append([]byte{0xff, 0x00}, append(utf16LE("1.2.3.4"), 0x00, 0x00)...), out)
}

func TestProduceUDPSkipsWhenRuleProduceFalse(t *testing.T) {
	produceFalse := false
	g := &Glutton{Producer: &producer.Producer{}}
	err := g.ProduceUDP("udp", nil, nil, connection.Metadata{
		Rule: &rules.Rule{Produce: &produceFalse},
	}, nil, nil)
	require.NoError(t, err)
}

func TestRecallConfig(t *testing.T) {
	keys := []string{"recall.enabled", "recall.visit_gap", "recall.ttl", "recall.max_sources"}
	orig := map[string]any{}
	for _, k := range keys {
		orig[k] = viper.Get(k)
	}
	t.Cleanup(func() {
		for k, v := range orig {
			viper.Set(k, v)
		}
	})

	for _, k := range keys {
		viper.Set(k, nil)
	}
	require.Equal(t, recall.DefaultConfig(), recallConfig(), "enabled with defaults when unset")

	viper.Set("recall.enabled", false)
	viper.Set("recall.visit_gap", 60)
	viper.Set("recall.ttl", 3600)
	viper.Set("recall.max_sources", 10)
	require.Equal(t, recall.Config{Enabled: false, Gap: time.Minute, TTL: time.Hour, Max: 10}, recallConfig())
}

func TestGuardConfig(t *testing.T) {
	for _, tc := range []struct {
		key string
		def guard.Config
	}{
		{"udp_reply_limit", guard.DefaultConfig()},
		{"tcp_reply_limit", guard.DefaultTCPConfig()},
	} {
		t.Run(tc.key, func(t *testing.T) {
			keys := []string{tc.key + ".enabled", tc.key + ".source_rate", tc.key + ".source_burst",
				tc.key + ".global_rate", tc.key + ".global_burst",
				tc.key + ".source_request_rate", tc.key + ".source_request_burst",
				tc.key + ".global_request_rate", tc.key + ".global_request_burst",
				tc.key + ".max_sources", tc.key + ".source_prefix_v4", tc.key + ".source_prefix_v6"}
			orig := map[string]any{}
			for _, k := range keys {
				orig[k] = viper.Get(k)
			}
			t.Cleanup(func() {
				for k, v := range orig {
					viper.Set(k, v)
				}
			})

			for _, k := range keys {
				viper.Set(k, nil)
			}
			require.Equal(t, tc.def, guardConfig(tc.key, tc.def), "enabled with defaults when unset")

			viper.Set(tc.key+".enabled", false)
			viper.Set(tc.key+".source_rate", 10)
			viper.Set(tc.key+".source_burst", 20)
			viper.Set(tc.key+".global_rate", 0)
			viper.Set(tc.key+".global_burst", 40)
			viper.Set(tc.key+".source_request_rate", 5)
			viper.Set(tc.key+".source_request_burst", 8)
			viper.Set(tc.key+".global_request_rate", 0)
			viper.Set(tc.key+".global_request_burst", 16)
			viper.Set(tc.key+".max_sources", 50)
			viper.Set(tc.key+".source_prefix_v4", 24)
			viper.Set(tc.key+".source_prefix_v6", 48)
			require.Equal(t, guard.Config{
				Enabled: false, SourceRate: 10, SourceBurst: 20, GlobalRate: 0, GlobalBurst: 40,
				SourceRequestRate: 5, SourceRequestBurst: 8, GlobalRequestRate: 0, GlobalRequestBurst: 16,
				MaxSources: 50, SourcePrefixV4: 24, SourcePrefixV6: 48,
			}, guardConfig(tc.key, tc.def))
		})
	}
}

func TestReplyUDPDropsOverBudget(t *testing.T) {
	g := &Glutton{udpGuard: guard.New(guard.Config{Enabled: true, SourceRate: 1, SourceBurst: 64})}
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5683}
	// Over budget: dropped before any socket is opened, and not reported as
	// a send error.
	require.NoError(t, g.ReplyUDP(src, dst, make([]byte, 65)))
	sent, err := g.ReplyUDPSent(src, dst, make([]byte, 65))
	require.NoError(t, err)
	require.False(t, sent, "a dropped reply is reported as not sent")
}

func TestGuardConnFailsWritesOverBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	server := <-accepted

	g := &Glutton{tcpGuard: guard.New(guard.Config{Enabled: true, SourceRate: 1, SourceBurst: 64})}
	conn := g.GuardConn(server)
	defer conn.Close()
	_, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok, "half-close stays reachable for proxy_tcp")

	n, err := conn.Write(make([]byte, 64))
	require.NoError(t, err)
	require.Equal(t, 64, n)
	n, err = conn.Write([]byte{1})
	require.ErrorIs(t, err, guard.ErrLimited)
	require.Zero(t, n)
}

func TestDefaultRulesRoutePOP3(t *testing.T) {
	rs, err := rules.Init(bytes.NewReader(defaultRules))
	require.NoError(t, err)
	src := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	for _, tc := range []struct {
		port int
		tls  rules.TLSMode
	}{
		{110, rules.TLSOff},
		{995, rules.TLSOn},
	} {
		match, err := rs.Match("tcp", src, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: tc.port})
		require.NoError(t, err)
		require.NotNil(t, match, "port %d", tc.port)
		require.Equal(t, "pop3", match.Target, "port %d", tc.port)
		require.Equal(t, tc.tls, match.TLS, "port %d", tc.port)
	}
}

func TestRecoverPanicWritesLog(t *testing.T) {
	dir := t.TempDir()
	viper.Set("var-dir", dir)
	g := &Glutton{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	func() {
		defer g.recoverPanic("tcp", "boom")
		panic("kaboom")
	}()
	data, err := os.ReadFile(filepath.Join(dir, "panic.log"))
	require.NoError(t, err)
	require.Contains(t, string(data), "handler=boom panic: kaboom")
}

func TestProduceLimitConfig(t *testing.T) {
	keys := []string{"produce_limit.enabled", "produce_limit.source_rate", "produce_limit.source_burst", "produce_limit.global_rate", "produce_limit.global_burst", "produce_limit.max_sources", "produce_limit.source_prefix_v4", "produce_limit.source_prefix_v6"}
	orig := map[string]any{}
	for _, k := range keys {
		orig[k] = viper.Get(k)
		viper.Set(k, nil)
	}
	t.Cleanup(func() {
		for k, v := range orig {
			viper.Set(k, v)
		}
	})
	cfg := eventLimitConfig("produce_limit")
	require.True(t, cfg.Enabled, "enabled when unset")
	require.Equal(t, defaultProduceSourceRate, cfg.SourceRequestRate)
	require.Equal(t, defaultProduceGlobalRate, cfg.GlobalRequestRate)
	require.Zero(t, cfg.GlobalRate, "events charge no bytes")
	require.Equal(t, 24, cfg.SourcePrefixV4, "a flood spread over a /24 is one source")
	require.Equal(t, 48, cfg.SourcePrefixV6)

	viper.Set("produce_limit.source_burst", 5)
	viper.Set("produce_limit.global_rate", 0)
	cfg = eventLimitConfig("produce_limit")
	require.Equal(t, 5, cfg.SourceRequestBurst)
	require.Zero(t, cfg.GlobalRequestRate, "0 disables the global budget")
}

func TestAllowProduceDropsFloodingSource(t *testing.T) {
	// a SOCKS flood from one source produced one Ochi POST per connection
	g := &Glutton{produceGuard: guard.New(guard.Config{
		Enabled:            true,
		SourceRequestRate:  1,
		SourceRequestBurst: 3,
	})}
	flooder := net.ParseIP("198.51.100.7")
	allowed := 0
	for range 100 {
		if g.allowProduce("socks", flooder) {
			allowed++
		}
	}
	require.Equal(t, 3, allowed, "only the burst gets through")
	require.True(t, g.allowProduce("socks", net.ParseIP("198.51.100.8")), "other sources keep their budget")
	require.True(t, g.allowProduce("socks", nil), "conns without an IP are not limited")
}
