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
