package plex2shell

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The query is rebuilt from the one Zeek line public reporting shows, so it is
// synthetic: the real request's other parameters and method are unknown.
const probeQuery = "deviceClass=pc&protocolCapabilities=playback&protocolVersion=1&protocol=http%3A%2F%2F127.0.0.1.45-194-92-222.sslip.io%3A8952" +
	"%2F%3Fidentifier%3Dcom.plexapp.agents.thetvdb%252Ffunction%252FGetResultFromNetwork&commandID=1&X-Plex-Target-Client-Identifier=poc_0cf927be72d2_17471"

func TestInspectProbe(t *testing.T) {
	got := Inspect("/player/timeline/subscribe", probeQuery, http.Header{})
	require.Equal(t, &Request{
		Indicators:       []string{SubscribePath, LoopbackPrefixHost, AgentCallback, PoCClient},
		CallbackHost:     "127.0.0.1.45-194-92-222.sslip.io",
		CallbackIP:       "45.194.92.222",
		CallbackPort:     8952,
		Agent:            "com.plexapp.agents.thetvdb/function/GetResultFromNetwork",
		ClientIdentifier: "poc_0cf927be72d2_17471",
	}, got)
}

func TestInspectHeaderClient(t *testing.T) {
	h := http.Header{}
	h.Set("X-Plex-Target-Client-Identifier", "poc_abc")
	got := Inspect("/other", "", h)
	require.Equal(t, &Request{Indicators: []string{PoCClient}, ClientIdentifier: "poc_abc"}, got)
}

func TestInspectNegative(t *testing.T) {
	for name, tc := range map[string]struct{ path, query string }{
		"identity":       {"/identity", ""},
		"plain loopback": {"/library/sections", "url=http%3A%2F%2F127.0.0.1%3A32400%2Fidentity"},
		"real client":    {"/library/sections", "X-Plex-Token=abc&X-Plex-Client-Identifier=0123"},
		"empty":          {"/", ""},
	} {
		t.Run(name, func(t *testing.T) {
			require.Nil(t, Inspect(tc.path, tc.query, http.Header{}))
		})
	}
}

func TestInspectCaps(t *testing.T) {
	long := "127.0.0.1." + strings.Repeat("a", 240) + ".sslip.io"
	got := Inspect("/x", "h="+long, http.Header{})
	require.NotNil(t, got)
	require.LessOrEqual(t, len(got.CallbackHost), MaxField)

	got = Inspect("/player/timeline/subscribe", strings.Repeat("a", 2*MaxScan), http.Header{})
	require.NotNil(t, got)
	require.True(t, got.Truncated)
}

func TestEmbeddedIPRejectsBadOctets(t *testing.T) {
	require.Equal(t, "", embeddedIP("127.0.0.1.999-1-1-1.sslip.io"))
	require.Equal(t, "1.2.3.4", embeddedIP("localhost.1.2.3.4.nip.io"))
}

func TestRespond(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	id := string(Respond(http.MethodGet, "/identity", now))
	require.Contains(t, id, "HTTP/1.1 200 OK\r\n")
	require.Contains(t, id, "X-Plex-Protocol: 1.0\r\n")
	require.Contains(t, id, "Date: Wed, 21 Oct 2026 12:00:00 GMT\r\n")
	require.Contains(t, id, `version="`+serverVersion+`"`)
	require.Contains(t, id, `machineIdentifier="`+machineIdentifier()+`"`)
	require.Len(t, machineIdentifier(), 40)

	sub := string(Respond(http.MethodGet, "/player/timeline/subscribe", now))
	require.Contains(t, sub, `<Response code="200" status="OK" />`)

	for _, r := range [][]byte{Respond(http.MethodGet, "/library/sections", now), Respond(http.MethodPost, "/identity", now)} {
		require.Contains(t, string(r), "HTTP/1.1 401 Unauthorized\r\n")
	}
	require.NotContains(t, strings.ToLower(id), "glutton")
}
