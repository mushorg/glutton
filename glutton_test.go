package glutton

import (
	"context"
	"testing"

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
	g.registerHandlers()
}
