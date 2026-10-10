package udp

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func kerberosASReqFromEvent() []byte {
	// Ochi event 9f61359e-9c4d-442f-88e6-70b674eace8d: UDP AS-REQ for krbtgt/NM.
	raw, err := hex.DecodeString("6a816e30816ba103020105a20302010aa4815e305ca00703050050800010a2041b024e4da3173015a003020100a10e300c1b066b72627467741b024e4da511180f31393730303130313030303030305aa70602041f1eb9d9a8173015020112020111020110020117020101020103020102")
	if err != nil {
		panic(err)
	}
	return raw
}

func fixedKerberosClock(t *testing.T) {
	t.Helper()
	old := kerberosNow
	kerberosNow = func() time.Time { return time.Date(2026, 10, 10, 16, 56, 18, 159119000, time.UTC) }
	t.Cleanup(func() { kerberosNow = old })
}

func TestHandleKerberosASReq(t *testing.T) {
	fixedKerberosClock(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 41234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 88}
	payload := kerberosASReqFromEvent()

	err := HandleKerberos(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Len(t, h.replies, 1)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, 10, events[0].MsgType)
	require.Equal(t, "AS-REQ", events[0].MsgName)
	require.Equal(t, "AS-REQ", events[0].Command)
	require.Equal(t, "krbtgt/NM", events[0].Path)
	require.Equal(t, 5, events[0].PVNO)
	require.Equal(t, "NM", events[0].Realm)
	require.Equal(t, "krbtgt/NM", events[0].SName)
	require.Empty(t, events[0].CName)
	require.Equal(t, []int{18, 17, 16, 23, 1, 3, 2}, events[0].ETypes)
	require.Equal(t, 0x1f1eb9d9, events[0].Nonce)
	require.Equal(t, payload, events[0].Payload)

	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "KRB-ERROR", events[1].Command)
	require.Equal(t, "KDC_ERR_PREAUTH_REQUIRED", events[1].Status)
	require.Equal(t, "krbtgt/NM", events[1].Path)
	require.Equal(t, h.replies[0], events[1].Payload)
}

func TestHandleKerberosASReqReply(t *testing.T) {
	fixedKerberosClock(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 41234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 26094}
	// Ochi event c82b0743-fa73-4660-b87e-64640d4e2b85: AS-REQ for krbtgt/CE.
	raw, err := hex.DecodeString("6a816e30816ba103020105a20302010aa4815e305ca00703050050008000a2041b024345a3173015a003020100a10e300c1b066b72627467741b024345a511180f31393730303130313030303030305aa70602" + "0403fcf003a8173015020112020111020110020117020101020103020102")
	require.NoError(t, err)

	require.NoError(t, HandleKerberos(context.Background(), src, dst, raw, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)

	// Decode the reply with the package's own DER parser.
	outer, rest, err := parseDER(h.replies[0])
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, asn1ClassApp, outer.class)
	require.Equal(t, kerberosError, outer.tag)
	seq, _, err := parseDER(outer.content)
	require.NoError(t, err)
	fields := map[int]derValue{}
	require.NoError(t, walkSequence(seq.content, func(v derValue) error {
		fields[v.tag] = v
		return nil
	}))
	intField := func(tag int) int {
		inner, err := unwrapContext(fields[tag], tag)
		require.NoError(t, err)
		n, err := parseDERInteger(inner.content)
		require.NoError(t, err)
		return n
	}
	require.Equal(t, 5, intField(0))
	require.Equal(t, kerberosError, intField(1))
	require.Equal(t, kdcErrPreauthRequired, intField(6))
	stime, err := unwrapContext(fields[4], 4)
	require.NoError(t, err)
	require.Equal(t, "20261010165618Z", string(stime.content))
	require.Equal(t, 159119, intField(5))
	realm, err := unwrapContext(fields[9], 9)
	require.NoError(t, err)
	require.Equal(t, "CE", string(realm.content))
	name, err := parsePrincipalName(fields[10].content)
	require.NoError(t, err)
	require.Equal(t, "krbtgt/CE", name)

	// e-data is METHOD-DATA listing PA-ETYPE-INFO2 and PA-ENC-TIMESTAMP.
	edata, err := unwrapContext(fields[12], 12)
	require.NoError(t, err)
	md, _, err := parseDER(edata.content)
	require.NoError(t, err)
	var padata []int
	require.NoError(t, walkSequence(md.content, func(pa derValue) error {
		return walkSequence(pa.content, func(v derValue) error {
			if v.tag == 1 {
				inner, err := unwrapContext(v, 1)
				require.NoError(t, err)
				n, err := parseDERInteger(inner.content)
				require.NoError(t, err)
				padata = append(padata, n)
			}
			return nil
		})
	}))
	require.Equal(t, []int{paETypeInfo2, paEncTimestamp}, padata)
}

func TestKerberosTGSReqNoReply(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 88}
	payload := kerberosASReqFromEvent()
	payload[0] = 0x6c
	require.NoError(t, HandleKerberos(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Len(t, h.produced[0].decoded.([]parsedKerberos), 1)
}

func TestBuildKerberosPreauthRequiredSalt(t *testing.T) {
	resp := buildKerberosPreauthRequired(parsedKerberos{Realm: "EXAMPLE.COM", CName: "alice", ETypes: []int{18}}, time.Unix(0, 0))
	require.Contains(t, string(resp), "EXAMPLE.COMalice")
}

func TestHandleKerberosTruncated(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 88}
	payload := []byte{0x6a, 0x81, 0x6e, 0x30}

	err := HandleKerberos(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "UNKNOWN", events[0].MsgName)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleKerberosNonDER(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 88}
	payload := []byte{0x00, 0x01, 0x02, 0x03}

	err := HandleKerberos(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "UNKNOWN", events[0].MsgName)
	require.Zero(t, events[0].MsgType)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleUDPPeeksKerberos(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 41234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8000}
	payload := kerberosASReqFromEvent()

	err := HandleUDP(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "kerberos", h.produced[0].handler)
	require.Len(t, h.replies, 1)

	events, ok := h.produced[0].decoded.([]parsedKerberos)
	require.True(t, ok)
	require.Equal(t, "AS-REQ", events[0].MsgName)
	require.Equal(t, "NM", events[0].Realm)
	require.Equal(t, "krbtgt/NM", events[0].SName)
}

func TestParseKerberosTGSReqName(t *testing.T) {
	payload := kerberosASReqFromEvent()
	payload[0] = 0x6c // APPLICATION 12
	frame := parseKerberos(payload)
	require.Equal(t, 12, frame.MsgType)
	require.Equal(t, "TGS-REQ", frame.MsgName)
	require.Equal(t, "NM", frame.Realm)
	require.Equal(t, "krbtgt/NM", frame.SName)
}

func TestLooksLikeKerberos(t *testing.T) {
	require.True(t, looksLikeKerberos(kerberosASReqFromEvent()))
	require.False(t, looksLikeKerberos(nil))
	require.False(t, looksLikeKerberos([]byte{0x00, 0x01}))
	require.False(t, looksLikeKerberos([]byte{0x6a, 0x03, 0xff, 0x00, 0x00}))
}
