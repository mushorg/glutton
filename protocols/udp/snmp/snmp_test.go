package snmp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Captured GetBulk from 151.243.11.230
// (Ochi event 7046da12-95f6-463e-8b55-8df479078229).
var getBulkInternet = []byte{
	0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa5, 0x18, 0x02,
	0x04, 0x9e, 0xf9, 0x98, 0xb4, 0x02, 0x01, 0x00, 0x02, 0x02, 0x07, 0xd0, 0x30, 0x09, 0x30, 0x07,
	0x06, 0x03, 0x2b, 0x06, 0x01, 0x05, 0x00,
}

func testAgent() *Agent {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	return NewAgent(1, func() time.Time { return now })
}

// request builds a request message; a and b are error-status/index, or
// non-repeaters/max-repetitions for GetBulk.
func request(version int, community string, pdu byte, id int64, a, b int64, oids ...OID) []byte {
	var vbl []byte
	for _, o := range oids {
		vbl = append(vbl, varbind(o, nullValue)...)
	}
	body := encInt(tagInteger, id)
	body = append(body, encInt(tagInteger, a)...)
	body = append(body, encInt(tagInteger, b)...)
	body = append(body, tlv(tagSequence, vbl)...)
	msg := encInt(tagInteger, int64(version))
	msg = append(msg, tlv(tagOctetString, []byte(community))...)
	msg = append(msg, tlv(pdu, body)...)
	return tlv(tagSequence, msg)
}

func TestParseCapturedGetBulk(t *testing.T) {
	require.True(t, LooksLikeSNMP(getBulkInternet))
	m, err := Parse(getBulkInternet)
	require.NoError(t, err)
	require.Equal(t, Version2c, m.Version)
	require.Equal(t, "public", m.Community)
	require.Equal(t, byte(PDUGetBulk), m.PDUType)
	// 0x9ef998b4 as a signed 32-bit INTEGER.
	require.Equal(t, int64(-1627809612), m.RequestID)
	require.Zero(t, m.NonRepeaters)
	require.Equal(t, int64(2000), m.MaxRepetitions)
	require.Len(t, m.OIDs, 1)
	require.Equal(t, "1.3.6.1", m.OIDs[0].String())
}

func TestEncodeRoundTrip(t *testing.T) {
	for _, v := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129, 2000, -1627809612} {
		got, err := readInt(encInt(tagInteger, v)[2:])
		require.NoError(t, err)
		require.Equal(t, v, got, "value %d", v)
	}
	o := OID{1, 3, 6, 1, 4, 1, 8072, 3, 2, 10}
	dec, err := decodeOID(encOID(o)[2:])
	require.NoError(t, err)
	require.Equal(t, o, dec)
}

func TestLooksLikeSNMP(t *testing.T) {
	require.True(t, LooksLikeSNMP(request(Version1, "x", PDUGet, 1, 0, 0, oidSysDescr)))
	// v3 header: version 3, then msgGlobalData SEQUENCE.
	v3 := tlv(tagSequence, append(encInt(tagInteger, 3), tlv(tagSequence, encInt(tagInteger, 1))...))
	require.True(t, LooksLikeSNMP(v3))

	require.False(t, LooksLikeSNMP(nil))
	require.False(t, LooksLikeSNMP(getBulkInternet[:20]))
	require.False(t, LooksLikeSNMP(append(append([]byte{}, getBulkInternet...), 0)))
	require.False(t, LooksLikeSNMP(request(2, "x", PDUGet, 1, 0, 0)))
	// DER Kerberos-like and plain text must not match.
	require.False(t, LooksLikeSNMP([]byte("\x30\x03\x02\x01\x01")))
	require.False(t, LooksLikeSNMP([]byte("GET / HTTP/1.1\r\n\r\n")))
}

func TestParseMalformed(t *testing.T) {
	for _, bad := range [][]byte{nil, {0x30}, getBulkInternet[:30], {0x30, 0x03, 0x02, 0x01, 0x07}} {
		_, err := Parse(bad)
		require.Error(t, err)
	}
	// Varbind with a bad OID.
	bad := request(Version2c, "public", PDUGet, 1, 0, 0, OID{1, 3})
	bad[len(bad)-3] = 0xab // OID content ends on a continuation byte
	_, err := Parse(bad)
	require.Error(t, err)
}

func TestGetV2c(t *testing.T) {
	a := testAgent()
	req := request(Version2c, "public", PDUGet, 7, 0, 0, oidSysName, oidSysUpTime, OID{1, 3, 6, 1, 2, 1, 1, 9, 0})
	m, err := Parse(req)
	require.NoError(t, err)

	resp, status := a.Respond(m, 1500)
	require.Equal(t, StatusOK, status)
	rm := parseResponse(t, resp)
	require.Equal(t, int64(7), rm.reqID)
	require.Zero(t, rm.errStatus)
	require.Len(t, rm.vbs, 3)
	require.Equal(t, tlv(tagOctetString, []byte(a.name)), rm.vbs[0].val)
	require.Equal(t, byte(tagTimeTicks), rm.vbs[1].val[0])
	require.Equal(t, noSuchObjectValue, rm.vbs[2].val)
}

func TestSysUpTimeAdvances(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	a := NewAgent(1, func() time.Time { return now })
	first := a.mib()[2].val
	now = now.Add(time.Minute)
	require.NotEqual(t, first, a.mib()[2].val)
}

func TestPersonaVariesBySeed(t *testing.T) {
	now := func() time.Time { return time.Unix(1e9, 0) }
	require.NotEqual(t, NewAgent(1, now).descr, NewAgent(2, now).descr)
	require.Equal(t, NewAgent(1, now).descr, NewAgent(1, now).descr)
	require.NotContains(t, NewAgent(1, now).descr, "glutton")
}

func TestGetV1NoSuchName(t *testing.T) {
	a := testAgent()
	req := request(Version1, "public", PDUGet, 9, 0, 0, oidSysName, OID{1, 3, 6, 1, 2, 1, 1, 9, 0})
	m, err := Parse(req)
	require.NoError(t, err)

	resp, status := a.Respond(m, 1500)
	require.Equal(t, StatusNoSuchName, status)
	rm := parseResponse(t, resp)
	require.Equal(t, Version1, rm.version)
	require.Equal(t, int64(ErrNoSuchName), rm.errStatus)
	require.Equal(t, int64(2), rm.errIndex)
}

func TestGetNext(t *testing.T) {
	a := testAgent()
	m, err := Parse(request(Version2c, "public", PDUGetNext, 3, 0, 0, OID{1, 3, 6, 1}, oidSysLocation))
	require.NoError(t, err)
	resp, _ := a.Respond(m, 1500)
	rm := parseResponse(t, resp)
	require.Len(t, rm.vbs, 2)
	require.Equal(t, encOID(oidSysDescr), rm.vbs[0].oid)
	require.Equal(t, endOfMibValue, rm.vbs[1].val)
}

func TestGetBulkWalk(t *testing.T) {
	a := testAgent()
	m, err := Parse(getBulkInternet)
	require.NoError(t, err)

	resp, status := a.Respond(m, 1500)
	require.Equal(t, StatusOK, status)
	rm := parseResponse(t, resp)
	// Six system objects, then endOfMibView once.
	require.Len(t, rm.vbs, 7)
	require.Equal(t, endOfMibValue, rm.vbs[6].val)
}

func TestReplyNeverLargerThanRequest(t *testing.T) {
	a := testAgent()
	m, err := Parse(getBulkInternet)
	require.NoError(t, err)

	// The captured 39-byte probe cannot hold sysDescr, so the agent says
	// tooBig, as a real agent with a small max message size would.
	resp, status := a.Respond(m, len(getBulkInternet))
	require.Equal(t, StatusTooBig, status)
	require.LessOrEqual(t, len(resp), len(getBulkInternet))
	rm := parseResponse(t, resp)
	require.Equal(t, int64(ErrTooBig), rm.errStatus)
	require.Equal(t, m.RequestID, rm.reqID)

	// Every request size yields a reply that fits or no reply at all.
	for limit := 0; limit < 200; limit++ {
		resp, _ := a.Respond(m, limit)
		require.LessOrEqual(t, len(resp), limit)
	}

	// A get that does not fit is tooBig, never truncated.
	g, err := Parse(request(Version2c, "public", PDUGet, 1, 0, 0, oidSysDescr))
	require.NoError(t, err)
	resp, status = a.Respond(g, 40)
	require.Equal(t, StatusTooBig, status)
	require.LessOrEqual(t, len(resp), 40)
}

func TestBulkTruncatesBindings(t *testing.T) {
	a := testAgent()
	m, err := Parse(getBulkInternet)
	require.NoError(t, err)
	full, _ := a.Respond(m, 1500)
	// Room for the first few bindings but not all of them.
	resp, status := a.Respond(m, len(full)-10)
	require.Equal(t, StatusOK, status)
	require.Less(t, len(parseResponse(t, resp).vbs), 7)
}

func TestSet(t *testing.T) {
	a := testAgent()
	for _, tc := range []struct {
		version int
		want    int64
	}{{Version2c, ErrNoAccess}, {Version1, ErrNoSuchName}} {
		m, err := Parse(request(tc.version, "public", PDUSet, 4, 0, 0, oidSysName))
		require.NoError(t, err)
		resp, _ := a.Respond(m, 1500)
		rm := parseResponse(t, resp)
		require.Equal(t, tc.want, rm.errStatus)
		require.Equal(t, int64(1), rm.errIndex)
	}
}

func TestSilentCases(t *testing.T) {
	a := testAgent()
	for name, req := range map[string][]byte{
		"bad community": request(Version2c, "private", PDUGet, 1, 0, 0, oidSysDescr),
		"v1 getbulk":    request(Version1, "public", PDUGetBulk, 1, 0, 5, oidSysDescr),
		"response pdu":  request(Version2c, "public", PDUResponse, 1, 0, 0, oidSysDescr),
		"trap v2":       request(Version2c, "public", PDUTrapV2, 1, 0, 0, oidSysDescr),
	} {
		m, err := Parse(req)
		require.NoError(t, err, name)
		resp, _ := a.Respond(m, 1500)
		require.Nil(t, resp, name)
	}
	v3, err := Parse(tlv(tagSequence, append(encInt(tagInteger, 3), tlv(tagSequence, nil)...)))
	require.NoError(t, err)
	require.Equal(t, Version3, v3.Version)
	resp, _ := a.Respond(v3, 1500)
	require.Nil(t, resp)
}

type respVarbind struct{ oid, val []byte }

type respMsg struct {
	version             int
	reqID               int64
	errStatus, errIndex int64
	vbs                 []respVarbind
}

// parseResponse decodes a reply produced by encodeMessage.
func parseResponse(t *testing.T, b []byte) respMsg {
	t.Helper()
	var r respMsg
	body, _, err := expect(b, tagSequence)
	require.NoError(t, err)
	verBytes, body, err := expect(body, tagInteger)
	require.NoError(t, err)
	ver, err := readInt(verBytes)
	require.NoError(t, err)
	r.version = int(ver)
	_, body, err = expect(body, tagOctetString)
	require.NoError(t, err)
	pdu, _, err := expect(body, PDUResponse)
	require.NoError(t, err)
	r.reqID, pdu, err = intField(pdu)
	require.NoError(t, err)
	r.errStatus, pdu, err = intField(pdu)
	require.NoError(t, err)
	r.errIndex, pdu, err = intField(pdu)
	require.NoError(t, err)
	vbl, _, err := expect(pdu, tagSequence)
	require.NoError(t, err)
	for len(vbl) > 0 {
		var vb []byte
		vb, vbl, err = expect(vbl, tagSequence)
		require.NoError(t, err)
		_, _, rest, err := readTLV(vb)
		require.NoError(t, err)
		oidTLV := vb[:len(vb)-len(rest)]
		r.vbs = append(r.vbs, respVarbind{oid: oidTLV, val: rest})
	}
	return r
}

// v3Discovery is the engine-discovery probe captured from 64.205.72.85
// (Ochi event da656960-b52d-4f05-a47f-da632ad36e57).
var v3Discovery = []byte{
	0x30, 0x4b, 0x02, 0x01, 0x03, 0x30, 0x10, 0x02, 0x04, 0x44, 0xba, 0x33, 0x55, 0x02, 0x02, 0x10,
	0x00, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00,
	0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x22, 0x04, 0x00, 0x04, 0x00, 0xa0,
	0x1c, 0x02, 0x04, 0x4a, 0x85, 0x17, 0xe1, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
	0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x05, 0x00,
}

func TestParseV3Discovery(t *testing.T) {
	m, err := Parse(v3Discovery)
	require.NoError(t, err)
	require.Equal(t, Version3, m.Version)
	require.Equal(t, int64(0x44ba3355), m.MsgID)
	require.Equal(t, int64(4096), m.MaxSize)
	require.Equal(t, byte(FlagReportable), m.Flags)
	require.Equal(t, int64(3), m.SecModel)
	require.True(t, m.usm)
	require.Empty(t, m.EngineID)
	require.Empty(t, m.UserName)
	require.Empty(t, m.ContextName)
	require.Equal(t, byte(PDUGet), m.PDUType)
	require.Equal(t, int64(0x4a8517e1), m.RequestID)
	require.Equal(t, []OID{{1, 3, 6, 1, 2, 1, 1, 2, 0}}, m.OIDs)
}

func TestParseV3Truncated(t *testing.T) {
	// Every prefix with a fixed-up outer length parses without error or panic
	// and never claims a complete USM before the USM parameters end.
	for n := 5; n < len(v3Discovery); n++ {
		cut := append([]byte(nil), v3Discovery[:n]...)
		cut[1] = byte(n - 2)
		m, err := Parse(cut)
		require.NoError(t, err, n)
		require.Equal(t, Version3, m.Version, n)
		if n < 41 { // the USM OCTET STRING ends at byte 41
			require.False(t, m.usm, n)
		}
	}
}

func TestReportToDiscovery(t *testing.T) {
	a := testAgent()
	m, err := Parse(v3Discovery)
	require.NoError(t, err)

	resp, status := a.Respond(m, len(v3Discovery))
	require.Equal(t, StatusUnknownEngineID, status)
	require.NotNil(t, resp)
	// Larger than the 77-byte request, within the Report cap.
	require.Greater(t, len(resp), len(v3Discovery))
	require.LessOrEqual(t, len(resp), reportMaxLen)

	r, err := Parse(resp)
	require.NoError(t, err)
	require.Equal(t, Version3, r.Version)
	require.Equal(t, m.MsgID, r.MsgID)
	require.Equal(t, byte(0), r.Flags)
	require.Equal(t, int64(secModelUSM), r.SecModel)
	require.Equal(t, a.engineID, r.EngineID)
	require.Equal(t, a.engineBoots, r.EngineBoots)
	require.Equal(t, a.engineID, r.ContextEngineID)
	require.Equal(t, byte(PDUReport), r.PDUType)
	require.Equal(t, m.RequestID, r.RequestID)
	require.Equal(t, []OID{oidUnknownEngineIDs}, r.OIDs)

	// RFC 3411: high bit set, enterprise 8072, within 5..32 bytes.
	require.Equal(t, []byte{0x80, 0x00, 0x1f, 0x88}, a.engineID[:4])
	require.GreaterOrEqual(t, len(a.engineID), 5)
	require.LessOrEqual(t, len(a.engineID), maxEngineIDLen)

	// The counter advances on every Report.
	c1 := reportCounter(t, resp)
	resp2, _ := a.Respond(m, len(v3Discovery))
	require.Equal(t, c1+1, reportCounter(t, resp2))
}

// reportCounter reads the trailing Counter32 TLV (tag 0x41, 1-5 content bytes),
// the last element of a Report built by encodeReport.
func reportCounter(t *testing.T, b []byte) int64 {
	t.Helper()
	for n := 1; n <= 5; n++ {
		i := len(b) - n - 2
		if b[i] == tagCounter32 && int(b[i+1]) == n {
			var v int64
			for _, c := range b[i+2:] {
				v = v<<8 | int64(c)
			}
			return v
		}
	}
	t.Fatal("no Counter32 at end of report")
	return 0
}

func TestReportToLearnedEngineID(t *testing.T) {
	a := testAgent()
	m := &Message{Version: Version3, MsgID: 5, Flags: FlagReportable, SecModel: secModelUSM, usm: true, EngineID: a.engineID, UserName: "admin"}
	resp, status := a.Respond(m, 100)
	require.Equal(t, StatusUnknownUserName, status)
	r, err := Parse(resp)
	require.NoError(t, err)
	require.Equal(t, []OID{oidUnknownUserNames}, r.OIDs)
}

func TestV3SilentCases(t *testing.T) {
	a := testAgent()
	base := Message{Version: Version3, Flags: FlagReportable, SecModel: secModelUSM, usm: true}
	for name, mod := range map[string]func(m *Message){
		"not reportable": func(m *Message) { m.Flags = 0 },
		"auth":           func(m *Message) { m.Flags |= FlagAuth },
		"auth priv":      func(m *Message) { m.Flags |= FlagAuth | FlagPriv },
		"other model":    func(m *Message) { m.SecModel = 2 },
		"usm incomplete": func(m *Message) { m.usm = false },
	} {
		m := base
		mod(&m)
		resp, _ := a.Respond(&m, 1500)
		require.Nil(t, resp, name)
	}
	// An engineID over the RFC limit is not decoded as USM.
	long := make([]byte, maxEngineIDLen+1)
	usm := tlv(tagOctetString, long)
	for _, f := range [][]byte{encInt(tagInteger, 0), encInt(tagInteger, 0), tlv(tagOctetString, nil), tlv(tagOctetString, nil), tlv(tagOctetString, nil)} {
		usm = append(usm, f...)
	}
	require.Error(t, parseUSM(&Message{}, tlv(tagSequence, usm)))
}

func TestAgentEngineIDPerSeed(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }
	require.Equal(t, NewAgent(1, now).engineID, NewAgent(1, now).engineID)
	require.NotEqual(t, NewAgent(1, now).engineID, NewAgent(2, now).engineID)
}
