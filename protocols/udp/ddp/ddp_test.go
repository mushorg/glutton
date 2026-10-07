package ddp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured SRCH probe (Ochi event f2eae484-8a2a-43b7-95b0-f084c2b6232c).
const capturedSearch = "SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00030010\n"

func TestCapturedSearchLength(t *testing.T) {
	require.Len(t, capturedSearch, 59)
}

func TestLooksLikeDDP(t *testing.T) {
	for name, tc := range map[string]struct {
		data string
		want bool
	}{
		"captured search": {capturedSearch, true},
		"crlf search":     {"SRCH * HTTP/1.1\r\ndevice-discovery-protocol-version:00020020\r\n", true},
		"wakeup":          {"WAKEUP * HTTP/1.1\nclient-type:a\n", true},
		"launch":          {"LAUNCH * HTTP/1.1\n", true},
		"no line end":     {"SRCH * HTTP/1.1", false},
		"http get":        {"GET / HTTP/1.1\r\n", false},
		"ssdp":            {"M-SEARCH * HTTP/1.1\r\n", false},
		"lowercase":       {"srch * HTTP/1.1\n", false},
		"garbage":         {"\x00\x01\x02\x03", false},
		"empty":           {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, LooksLikeDDP([]byte(tc.data)))
		})
	}
}

func TestParseCapturedSearch(t *testing.T) {
	req, err := Parse([]byte(capturedSearch))
	require.NoError(t, err)
	require.Equal(t, Request{
		Method:  MethodSearch,
		Headers: map[string]string{HeaderVersion: "00030010"},
	}, req)
	require.Equal(t, "00030010", req.Version())
}

func TestParseCRLFWakeup(t *testing.T) {
	data := "WAKEUP * HTTP/1.1\r\nclient-type:vr\r\nauth-type:R\r\nUser-Credential:12345678\r\ndevice-discovery-protocol-version:00020020\r\n\r\nignored:after-blank\r\n"
	req, err := Parse([]byte(data))
	require.NoError(t, err)
	require.Equal(t, MethodWakeup, req.Method)
	require.Equal(t, map[string]string{
		HeaderClientType:     "vr",
		"auth-type":          "R",
		HeaderUserCredential: "12345678",
		HeaderVersion:        "00020020",
	}, req.Headers)
}

func TestParseGarbage(t *testing.T) {
	_, err := Parse([]byte("\xff\xfe garbage"))
	require.ErrorIs(t, err, ErrNotDDP)
}

func TestConsoleForIsStable(t *testing.T) {
	a := ConsoleFor([]byte("198.51.100.1"), "00020020")
	require.Equal(t, a, ConsoleFor([]byte("198.51.100.1"), "00020020"))
	require.Regexp(t, `^[0-9A-F]{12}$`, a.HostID)
	require.Regexp(t, `^PS4-\d{3}$`, a.HostName)
	require.Equal(t, "PS4", a.HostType)
	require.Equal(t, "00020020", a.Version)

	b := ConsoleFor([]byte("198.51.100.2"), "00020020")
	require.NotEqual(t, a.HostID, b.HostID)
}

func TestConsoleForPS5(t *testing.T) {
	c := ConsoleFor([]byte("198.51.100.1"), "00030010")
	require.Equal(t, "PS5", c.HostType)
	require.Equal(t, "00030010", c.Version)
	require.Regexp(t, `^PS5-\d{3}$`, c.HostName)
	require.Equal(t, "PS4", ConsoleFor([]byte("198.51.100.1"), "").HostType)
}

func TestBuildSearchResponse(t *testing.T) {
	got := BuildSearchResponse(Console{
		HostID:   "0123456789AB",
		HostType: "PS4",
		HostName: "PS4-123",
		Version:  "00020020",
		System:   "11008001",
	})
	require.Equal(t, "HTTP/1.1 620 Server Standby\n"+
		"host-id:0123456789AB\n"+
		"host-type:PS4\n"+
		"host-name:PS4-123\n"+
		"host-request-port:997\n"+
		"device-discovery-protocol-version:00020020\n"+
		"system-version:11008001\n", string(got))
}
