package nettcp

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

const msvsmonVia = "net.tcp://127.0.0.1:4026/Microsoft/VisualStudio/msvsmon"

// Captured msvsmon preamble (tcp/4026): Version 1.0, Mode duplex, Via,
// KnownEncoding 0x08, PreambleEnd.
var capturedPreamble = append(append([]byte{0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x37}, msvsmonVia...), 0x03, 0x08, 0x0c)

func readAll(t *testing.T, data []byte) []Record {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(data))
	var out []Record
	for {
		rec, err := ReadRecord(r, 1024)
		if err == io.EOF {
			return out
		}
		require.NoError(t, err)
		out = append(out, rec)
	}
}

func TestReadCapturedPreamble(t *testing.T) {
	recs := readAll(t, capturedPreamble)
	require.Len(t, recs, 5)
	require.Equal(t, "Version", recs[0].Name)
	require.Equal(t, "1.0", recs[0].Version)
	require.Equal(t, "duplex", recs[1].Mode)
	require.Equal(t, msvsmonVia, recs[2].Via)
	require.Equal(t, "application/soap+msbinsession1", recs[3].ContentType)
	require.Equal(t, "PreambleEnd", recs[4].Name)

	var joined []byte
	for _, r := range recs {
		joined = append(joined, r.Raw...)
	}
	require.Equal(t, capturedPreamble, joined)

	require.Equal(t, []byte{RecordPreambleAck}, Respond(recs[4]).Data)
	for _, r := range recs[:4] {
		require.Equal(t, Reply{}, Respond(r))
	}
}

func TestSizeEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 0x7f, 0x80, 300, 0x3fff, 0x4000, 0x7fffffff} {
		raw := []byte{}
		got, err := readSize(bufio.NewReader(bytes.NewReader(EncodeSize(n))), &raw)
		require.NoError(t, err)
		require.Equal(t, n, got)
	}
	_, err := readSize(bufio.NewReader(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0x01})), new([]byte))
	require.ErrorIs(t, err, ErrBadLength)
}

func TestEnvelopes(t *testing.T) {
	sized := append([]byte{RecordSizedEnvelope, 0x03}, "abc"...)
	unsized := append(append([]byte{RecordUnsizedEnvelope, 0x02}, "ab"...), 0x01, 'c', 0x00)
	recs := readAll(t, append(sized, unsized...))
	require.Len(t, recs, 2)
	require.Equal(t, []byte("abc"), recs[0].Body)
	require.Equal(t, []byte("abc"), recs[1].Body)
	require.Equal(t, unsized, recs[1].Raw)
}

func TestOversizeRecord(t *testing.T) {
	data := append([]byte{RecordVia}, EncodeSize(5000)...)
	data = append(data, bytes.Repeat([]byte{'a'}, 5000)...)
	rec, err := ReadRecord(bufio.NewReader(bytes.NewReader(data)), 16)
	require.ErrorIs(t, err, ErrTooLarge)
	require.True(t, rec.Truncated)
	require.Len(t, rec.Via, 16)
}

func TestUnknownRecord(t *testing.T) {
	_, err := ReadRecord(bufio.NewReader(bytes.NewReader([]byte{0x16, 0x03, 0x01})), 16)
	require.ErrorIs(t, err, ErrUnknownRecord)
}

func TestRespondFaults(t *testing.T) {
	cases := map[string][]byte{
		FaultUnsupportedVersion: {RecordVersion, 0x02, 0x00},
		FaultUnsupportedMode:    {RecordMode, 0x09},
		FaultContentTypeInvalid: {RecordKnownEncoding, 0x42},
		FaultUpgradeInvalid:     append([]byte{RecordUpgradeRequest, 0x14}, "application/negotiate"[:20]...),
	}
	for name, data := range cases {
		rec, err := ReadRecord(bufio.NewReader(bytes.NewReader(data)), 64)
		require.NoError(t, err)
		reply := Respond(rec)
		require.True(t, reply.Close, name)
		parsed := Parse(reply.Data)
		require.Equal(t, "Fault", parsed.Name)
		require.Equal(t, name, FaultName(parsed.Fault))
	}
	upgrade := append([]byte{RecordUpgradeRequest, 0x13}, UpgradeSSLTLS...)
	rec, err := ReadRecord(bufio.NewReader(bytes.NewReader(upgrade)), 64)
	require.NoError(t, err)
	require.Equal(t, UpgradeSSLTLS, rec.ContentType)
	require.Equal(t, Reply{Data: []byte{RecordUpgradeResponse}, StartTLS: true}, Respond(rec))

	end := Respond(Record{Type: RecordEnd})
	require.Equal(t, Reply{Data: []byte{RecordEnd}, Close: true}, end)
}
