package glutton

import (
	"context"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
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

func TestProduceUDPSkipsWhenRuleProduceFalse(t *testing.T) {
	produceFalse := false
	g := &Glutton{Producer: &producer.Producer{}}
	err := g.ProduceUDP("udp", nil, nil, connection.Metadata{
		Rule: &rules.Rule{Produce: &produceFalse},
	}, nil, nil)
	require.NoError(t, err)
}
