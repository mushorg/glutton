package glutton

import (
	"context"
	"net"
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
				tc.key + ".max_sources"}
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
			require.Equal(t, guard.Config{
				Enabled: false, SourceRate: 10, SourceBurst: 20, GlobalRate: 0, GlobalBurst: 40,
				SourceRequestRate: 5, SourceRequestBurst: 8, GlobalRequestRate: 0, GlobalRequestBurst: 16,
				MaxSources: 50,
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
