package sadp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Captured datagram (driftnet.io, 193.163.125.68 -> udp/37020, 2026-11-08).
var probe = []byte(`<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>7b1afb58-5904-4d9c-b0ef-090a5ea307f8</Uuid><Types>inquiry</Types></Probe>`)

func TestLooksLikeProbe(t *testing.T) {
	require.True(t, LooksLikeProbe(probe))
	require.True(t, LooksLikeProbe([]byte("\r\n<Probe><Types>inquiry</Types></Probe>")))
	for _, b := range []string{
		"",
		"<Probe>",
		"GET / HTTP/1.1\r\n\r\n",
		`<soap:Envelope xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></soap:Body></soap:Envelope>`,
		`<Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"><Types>x</Types></Probe>`,
	} {
		require.False(t, LooksLikeProbe([]byte(b)), b)
	}
}

func TestParse(t *testing.T) {
	r := Parse(probe)
	require.Equal(t, Request{Uuid: "7b1afb58-5904-4d9c-b0ef-090a5ea307f8", Types: "inquiry"}, r)
	require.Equal(t, "inquiry", r.Command())

	r = Parse([]byte(`<Probe><Uuid>u</Uuid><Types>Activate</Types><Password>12345</Password></Probe>`))
	require.Equal(t, "activate", r.Command())
	require.Equal(t, "12345", r.Password)

	require.Equal(t, "unknown", Parse([]byte("<Probe><Uuid>x")).Command())
	long := Parse([]byte("<Probe><Uuid>" + strings.Repeat("a", 500) + "</Uuid></Probe>"))
	require.Len(t, long.Uuid, maxField)
}

func TestBuildProbeMatch(t *testing.T) {
	d := DeviceFor([]byte("198.51.100.1"))
	require.Equal(t, d, DeviceFor([]byte("198.51.100.1")))
	require.NotEqual(t, d.MAC, DeviceFor([]byte("198.51.100.2")).MAC)
	require.True(t, strings.HasPrefix(d.Serial, d.Model+"20170327AAWR"))

	now := time.Date(2026, 11, 8, 20, 11, 29, 0, time.UTC)
	out := string(BuildProbeMatch(Parse(probe), d, now))
	require.True(t, strings.HasPrefix(out, `<?xml version="1.0" encoding="UTF-8"?><ProbeMatch><Uuid>7b1afb58-5904-4d9c-b0ef-090a5ea307f8</Uuid><Types>inquiry</Types><DeviceType>`))
	require.True(t, strings.HasSuffix(out, "</ProbeMatch>"))
	require.Contains(t, out, "<DeviceDescription>DS-2CD2042WD-I</DeviceDescription>")
	require.Contains(t, out, "<IPv4Address>"+d.IP.String()+"</IPv4Address>")
	require.Contains(t, out, "<MAC>c0-56-e3-")
	require.Contains(t, out, "<BootTime>"+now.Add(-d.Uptime).Format("2006-01-02 15:04:05")+"</BootTime>")
	require.NotContains(t, strings.ToLower(out), "glutton")
	require.NotContains(t, strings.ToLower(out), "honeypot")
}

func TestBuildProbeMatchEscapesEcho(t *testing.T) {
	out := string(BuildProbeMatch(Request{Uuid: "</Uuid><x>", Types: "inquiry"}, DeviceFor(nil), time.Unix(0, 0)))
	require.Contains(t, out, "<Uuid>&lt;/Uuid&gt;&lt;x&gt;</Uuid>")
}
