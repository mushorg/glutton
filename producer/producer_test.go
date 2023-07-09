package producer

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/rules"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	p, err := New("test")
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestProducerLog(t *testing.T) {
	p, err := New("test")
	require.NoError(t, err)
	require.NotNil(t, p)

	l, err := net.Listen("tcp", ":1234")
	require.NoError(t, err)
	require.NotNil(t, l)
	defer l.Close()
	conn, err := net.Dial("tcp", ":1234")
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	md := connection.Metadata{
		Rule: &rules.Rule{},
	}

	viper.Set("producers.http.enabled", true)

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svr.Close()

	viper.Set("producers.http.remote", svr.URL)

	err = p.Log("test", conn, &md, nil, []byte{123})
	require.NoError(t, err)
}
