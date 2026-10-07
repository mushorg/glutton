package glutton

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
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
