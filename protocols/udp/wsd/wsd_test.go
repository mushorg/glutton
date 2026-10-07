package wsd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const probe = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
<soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:ce04dad0-5d2c-4026-9146-1aabfc1e4111</wsa:MessageID></soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>`

func TestParseProbe(t *testing.T) {
	m, err := Parse([]byte(probe))
	require.NoError(t, err)
	require.Equal(t, "Probe", m.Command)
	require.Equal(t, "urn:uuid:ce04dad0-5d2c-4026-9146-1aabfc1e4111", m.MessageID)
	require.Equal(t, "wsdp:Device", m.Types)
	require.True(t, m.WantsDevice())
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "hello", "<a/>", "<x xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><unclosed"} {
		_, err := Parse([]byte(in))
		require.Error(t, err, in)
	}
	require.False(t, LooksLikeWSD([]byte("<html>")))
}

func TestBuildProbeMatches(t *testing.T) {
	m, _ := Parse([]byte(probe))
	resp, status := BuildMatches(m, "198.51.100.1")
	require.Equal(t, StatusProbeMatches, status)
	s := string(resp)
	require.Contains(t, s, "<wsa:RelatesTo>urn:uuid:ce04dad0-5d2c-4026-9146-1aabfc1e4111</wsa:RelatesTo>")
	require.Contains(t, s, "/ProbeMatches</wsa:Action>")
	require.Contains(t, s, "<wsd:XAddrs>http://198.51.100.1:5357/")
	require.Less(t, len(resp), 4*len(probe))
	// Parses back as a WS-Discovery message and is deterministic.
	back, err := Parse(resp)
	require.NoError(t, err)
	require.Equal(t, "ProbeMatches", back.Command)
	again, _ := BuildMatches(m, "198.51.100.1")
	require.Equal(t, resp, again)
	other, _ := BuildMatches(m, "198.51.100.2")
	require.NotEqual(t, resp, other)
}

func TestTypedProbeSilent(t *testing.T) {
	onvif := strings.Replace(probe, "wsdp:Device", "dn:NetworkVideoTransmitter", 1)
	m, err := Parse([]byte(onvif))
	require.NoError(t, err)
	resp, _ := BuildMatches(m, "198.51.100.1")
	require.Nil(t, resp)
}

func TestResolve(t *testing.T) {
	addr := DeviceAddress([]byte("198.51.100.1"))
	req := strings.NewReplacer("discovery/Probe", "discovery/Resolve",
		"<wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe>",
		"<wsd:Resolve><wsa:EndpointReference><wsa:Address>"+addr+"</wsa:Address></wsa:EndpointReference></wsd:Resolve>").Replace(probe)
	m, err := Parse([]byte(req))
	require.NoError(t, err)
	require.Equal(t, "Resolve", m.Command)
	resp, status := BuildMatches(m, "198.51.100.1")
	require.Equal(t, StatusResolveMatches, status)
	require.Contains(t, string(resp), "ResolveMatch>")
	wrong, _ := BuildMatches(m, "198.51.100.2")
	require.Nil(t, wrong)
}

func TestMessageIDEscaped(t *testing.T) {
	m, _ := Parse([]byte(probe))
	m.MessageID = "<evil>&"
	resp, _ := BuildMatches(m, "198.51.100.1")
	require.NotContains(t, string(resp), "<evil>")
}
