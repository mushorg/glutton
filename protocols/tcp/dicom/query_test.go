package dicom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWildcard(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"MIL*", "MILLER^ANNA", true},
		{"*^ANNA", "MILLER^ANNA", true},
		{"M?LLER*", "MILLER^ANNA", true},
		{"MILLER", "MILLER^ANNA", false},
		{"*X*", "MILLER^ANNA", false},
		{"**A", "ANNA", true},
	} {
		require.Equal(t, tc.want, wildcard(tc.pattern, tc.s), "%q ~ %q", tc.pattern, tc.s)
	}
}

func TestMatchValue(t *testing.T) {
	require.True(t, matchValue("PN", "", "MILLER^ANNA"))
	require.True(t, matchValue("PN", "mil*", "MILLER^ANNA"))
	require.True(t, matchValue("UI", "1.2.3\\1.2.4", "1.2.4"))
	require.False(t, matchValue("UI", "1.2.3\\1.2.5", "1.2.4"))
	require.True(t, matchValue("DA", "20240901-20241001", "20240917"))
	require.False(t, matchValue("DA", "20240901-20241001", "20241015"))
	require.True(t, matchValue("DA", "20241001-", "20241015"))
	require.True(t, matchValue("DA", "-20240930", "20240917"))
	require.True(t, matchValue("TM", "0900-1000", "093412"))
	require.False(t, matchValue("TM", "0900-0930", "093412"))
}

func studyIdentifier(name string) []Element {
	return []Element{
		{Tag: 0x00080020, VR: "DA"},
		{Tag: 0x00080052, VR: "CS", Value: []byte("STUDY ")},
		{Tag: 0x00080054, VR: "AE"},
		{Tag: 0x00100010, VR: "PN", Value: []byte(name)},
		{Tag: 0x00100020, VR: "LO"},
		{Tag: 0x0020000D, VR: "UI"},
		{Tag: 0x00321060, VR: "LO"},
	}
}

func TestFind(t *testing.T) {
	matches := Find(StudyRootFind, studyIdentifier("*"), "ANY-SCP")
	require.Len(t, matches, len(Archive))

	matches = Find(PatientRootFind, studyIdentifier("NOVAK*"), "ANY-SCP")
	require.Equal(t, [][]Element{{
		{Tag: 0x00080020, VR: "DA", Value: []byte("20241002")},
		{Tag: 0x00080052, VR: "CS", Value: []byte("STUDY ")},
		{Tag: 0x00080054, VR: "AE", Value: []byte("ANY-SCP")},
		{Tag: 0x00100010, VR: "PN", Value: []byte("NOVAK^PETER")},
		{Tag: 0x00100020, VR: "LO", Value: []byte("4021903")},
		{Tag: 0x0020000D, VR: "UI", Value: []byte("1.2.276.0.7230010.3.1.2.2831156423.4120.1727871055.731")},
		// not in the archive: returned empty
		{Tag: 0x00321060, VR: "LO"},
	}}, matches)

	require.Empty(t, Find(StudyRootFind, studyIdentifier("NOBODY"), "ANY-SCP"))
	// modality worklist and other SOP classes find nothing
	require.Empty(t, Find("1.2.840.10008.5.1.4.31", studyIdentifier("*"), "ANY-SCP"))
}

func TestFindReplies(t *testing.T) {
	req := Command{Field: CFindRQ, MessageID: 4, SOPClassUID: StudyRootFind}
	identifier, err := EncodeDataSet(studyIdentifier("WEBER*"), ExplicitVRLittleEndian)
	require.NoError(t, err)

	replies := FindReplies(req, identifier, ExplicitVRLittleEndian, "PACS")
	require.Len(t, replies, 2)

	pending := replies[0]
	require.Equal(t, Command{Field: 0x8020, RespondedTo: 4, SOPClassUID: StudyRootFind, Status: StatusPending}, pending.Command)
	require.True(t, pending.Command.HasDataSet())
	elems, err := ParseDataSet(pending.DataSet, ExplicitVRLittleEndian)
	require.NoError(t, err)
	q := QueryMap(elems)
	require.Equal(t, "WEBER^THOMAS", q["PatientName"])
	require.Equal(t, "PACS", q["RetrieveAETitle"])

	final := replies[1]
	require.Equal(t, StatusSuccess, final.Command.Status)
	require.False(t, final.Command.HasDataSet())
	require.Nil(t, final.DataSet)

	// no matches: only the final Success
	identifier, err = EncodeDataSet(studyIdentifier("NOBODY"), ImplicitVRLittleEndian)
	require.NoError(t, err)
	replies = FindReplies(req, identifier, ImplicitVRLittleEndian, "PACS")
	require.Len(t, replies, 1)
	require.Equal(t, StatusSuccess, replies[0].Command.Status)

	// undecodable or missing identifier
	for _, bad := range [][]byte{nil, {0x10, 0x00, 0x10, 0x00, 0xff, 0, 0, 0}} {
		replies = FindReplies(req, bad, ImplicitVRLittleEndian, "PACS")
		require.Len(t, replies, 1)
		require.Equal(t, StatusIdentifierMismatch, replies[0].Command.Status)
		require.Equal(t, "IdentifierDoesNotMatchSOPClass", StatusName(replies[0].Command.Status))
	}

	// big endian identifiers are not decoded: success without matches
	replies = FindReplies(req, identifier, ExplicitVRBigEndian, "PACS")
	require.Len(t, replies, 1)
	require.Equal(t, StatusSuccess, replies[0].Command.Status)
}

func TestAcceptedContexts(t *testing.T) {
	rq := AssociateRQ{PresentationContexts: []PresentationContext{
		{ID: 1, TransferSyntaxes: []string{ExplicitVRLittleEndian}},
		{ID: 3, TransferSyntaxes: []string{ExplicitVRLittleEndian, ImplicitVRLittleEndian}},
		{ID: 5},
	}}
	require.Equal(t, map[byte]string{1: ExplicitVRLittleEndian, 3: ImplicitVRLittleEndian}, AcceptedContexts(rq))
}

func TestBuildPDataPDVs(t *testing.T) {
	pdu := BuildPDataPDVs(
		PDV{ContextID: 1, Command: true, Last: true, Data: []byte("cmd")},
		PDV{ContextID: 1, Last: true, Data: []byte("data")},
	)
	pdvs, err := ParsePData(pdu)
	require.NoError(t, err)
	require.Equal(t, []PDV{
		{ContextID: 1, Command: true, Last: true, Data: []byte("cmd")},
		{ContextID: 1, Last: true, Data: []byte("data")},
	}, pdvs)
}
