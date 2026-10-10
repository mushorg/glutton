package dicom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDataSetImplicit(t *testing.T) {
	ds, err := EncodeDataSet([]Element{
		{Tag: 0x00080052, Value: []byte("STUDY")},
		{Tag: 0x00100010, Value: []byte("*")},
		{Tag: 0x00110010, Value: []byte{0xff, 0xfe}},
	}, ImplicitVRLittleEndian)
	require.NoError(t, err)
	// odd values are padded with a space
	require.Equal(t, mustHex("08005200060000005354554459201000100002000000"+"2a20"+"1100100002000000fffe"), ds)

	elems, err := ParseDataSet(ds, ImplicitVRLittleEndian)
	require.NoError(t, err)
	require.Equal(t, []Element{
		{Tag: 0x00080052, VR: "CS", Value: []byte("STUDY ")},
		{Tag: 0x00100010, VR: "PN", Value: []byte("* ")},
		{Tag: 0x00110010, Value: []byte{0xff, 0xfe}},
	}, elems)
	require.Equal(t, map[string]string{
		"QueryRetrieveLevel": "STUDY",
		"PatientName":        "*",
		"(0011,0010)":        "fffe",
	}, QueryMap(elems))
}

func TestParseDataSetExplicitWithSequence(t *testing.T) {
	var ds []byte
	// (0008,0052) CS "IMAGE"
	ds = append(ds, mustHex("0800520043530600494d41474520")...)
	// (0040,0100) SQ undefined length: one undefined-length item holding
	// (0040,0001) AE "CT1", then item and sequence delimiters
	ds = append(ds, mustHex("4000000153510000ffffffff")...)
	ds = append(ds, mustHex("feff00e0ffffffff")...)
	ds = append(ds, mustHex("400001004145040043543120")...)
	ds = append(ds, mustHex("feff0de000000000feffdde000000000")...)
	// (0010,0020) LO "4021187 " after the sequence
	ds = append(ds, mustHex("100020004c4f08003430323131383720")...)

	elems, err := ParseDataSet(ds, ExplicitVRLittleEndian)
	require.NoError(t, err)
	require.Equal(t, []Element{
		{Tag: 0x00080052, VR: "CS", Value: []byte("IMAGE ")},
		{Tag: 0x00400100, VR: "SQ"},
		{Tag: 0x00100020, VR: "LO", Value: []byte("4021187 ")},
	}, elems)
	require.Equal(t, map[string]string{
		"QueryRetrieveLevel":             "IMAGE",
		"ScheduledProcedureStepSequence": "",
		"PatientID":                      "4021187",
	}, QueryMap(elems))

	// round trip through the encoder: the sequence comes back empty
	out, err := EncodeDataSet(elems, ExplicitVRLittleEndian)
	require.NoError(t, err)
	again, err := ParseDataSet(out, ExplicitVRLittleEndian)
	require.NoError(t, err)
	require.Equal(t, elems, again)
}

// nestedSequences builds n undefined-length sequences, each in an item of the previous.
func nestedSequences(n int) []byte {
	if n == 0 {
		return nil
	}
	out := mustHex("40000001fffffffffeff00e0ffffffff")
	out = append(out, nestedSequences(n-1)...)
	return append(out, mustHex("feff0de000000000feffdde000000000")...)
}

func TestParseDataSetMalformed(t *testing.T) {
	// value length beyond the buffer
	_, err := ParseDataSet(mustHex("10001000ff000000"), ImplicitVRLittleEndian)
	require.ErrorIs(t, err, ErrMalformed)

	// unterminated sequence
	_, err = ParseDataSet(mustHex("40000001fffffffffeff00e0ffffffff"), ImplicitVRLittleEndian)
	require.ErrorIs(t, err, ErrMalformed)

	// well-formed sequences are accepted up to maxDepth levels of nesting
	_, err = ParseDataSet(nestedSequences(maxDepth), ImplicitVRLittleEndian)
	require.NoError(t, err)
	_, err = ParseDataSet(nestedSequences(maxDepth+1), ImplicitVRLittleEndian)
	require.ErrorIs(t, err, ErrMalformed)

	// element count cap
	var many []byte
	for range maxElements + 1 {
		many = append(many, mustHex("1000100000000000")...)
	}
	elems, err := ParseDataSet(many, ImplicitVRLittleEndian)
	require.ErrorIs(t, err, ErrMalformed)
	require.Len(t, elems, maxElements)

	_, err = ParseDataSet(nil, ExplicitVRBigEndian)
	require.ErrorIs(t, err, ErrUnsupportedTransferSyntax)
	_, err = EncodeDataSet(nil, DeflatedExplicitVRLittleEndian)
	require.ErrorIs(t, err, ErrUnsupportedTransferSyntax)
}

func TestQueryMapCapsValues(t *testing.T) {
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'A'
	}
	m := QueryMap([]Element{{Tag: 0x00100010, VR: "PN", Value: long}})
	require.Len(t, m["PatientName"], maxQueryValue)
	require.Nil(t, QueryMap(nil))
}
