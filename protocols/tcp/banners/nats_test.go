package banners

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNATSInfo(t *testing.T) {
	first := natsInfo()
	require.True(t, bytes.HasPrefix(first, []byte("INFO {")), "%q", first)
	require.True(t, bytes.HasSuffix(first, []byte("}\r\n")), "%q", first)
	require.Equal(t, 1, bytes.Count(first, []byte("\n")))

	var info struct {
		ServerID   string `json:"server_id"`
		ServerName string `json:"server_name"`
		Version    string `json:"version"`
		Proto      int    `json:"proto"`
		Port       int    `json:"port"`
		Headers    bool   `json:"headers"`
		MaxPayload int    `json:"max_payload"`
		ClientID   uint64 `json:"client_id"`
	}
	require.NoError(t, json.Unmarshal(bytes.TrimSuffix(bytes.TrimPrefix(first, []byte("INFO ")), []byte("\r\n")), &info))
	require.Regexp(t, regexp.MustCompile(`^N[A-D][A-Z2-7]{54}$`), info.ServerID)
	require.Equal(t, info.ServerID, info.ServerName)
	require.Equal(t, "2.10.22", info.Version)
	require.Equal(t, 1, info.Proto)
	require.Equal(t, 4222, info.Port)
	require.True(t, info.Headers)
	require.Equal(t, 1048576, info.MaxPayload)

	// every connection gets the next client ID
	next := natsInfo()
	require.Contains(t, string(next), `"client_id":`+jsonUint(info.ClientID+1)+"}")
	require.NotContains(t, string(first), "glutton")
}

func jsonUint(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestNATSFollowUp(t *testing.T) {
	cases := []struct {
		in   string
		want Response
	}{
		// binaryedge on tcp/4222 and tcp/4567
		{"\r\n\r\n", Response{Name: "nats-err", Data: []byte("-ERR 'Unknown Protocol Operation'\r\n"), Close: true}},
		{"GET / HTTP/1.1\r\n\r\n", Response{Name: "nats-err", Data: []byte("-ERR 'Unknown Protocol Operation'\r\n"), Close: true}},
		{"PING\r\n", Response{Name: "nats-pong", Data: []byte("PONG\r\n")}},
		{"CONNECT {\"verbose\":false}\r\nPING\r\n", Response{Name: "nats-pong", Data: []byte("PONG\r\n")}},
		{"connect {}\r\nping\r\n", Response{Name: "nats-pong", Data: []byte("PONG\r\n")}},
		{"CONNECT {\"verbose\":false}\r\n", Response{Name: "nats", NoReply: true}},
		{"SUB > 1\r\n", Response{Name: "nats", NoReply: true}},
	}
	for _, c := range cases {
		resp, ok := NATSFollowUp([]byte(c.in))
		require.True(t, ok, c.in)
		require.Equal(t, c.want, resp, c.in)
	}
}
