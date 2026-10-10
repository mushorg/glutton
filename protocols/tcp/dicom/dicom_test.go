package dicom

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// issue50AssociateRQ is the findscu A-ASSOCIATE-RQ from mushorg/glutton#50.
var issue50AssociateRQ = mustHex(
	"01000000010000010000414e592d53435020202020202020202046494e445343" +
		"5520202020202020202000000000000000000000000000000000000000000000" +
		"0000000000000000000010000015312e322e3834302e31303030382e332e312e" +
		"312e31200000610100ff0030000016312e322e3834302e31303030382e352e31" +
		"2e342e333140000013312e322e3834302e31303030382e312e322e3140000013" +
		"312e322e3834302e31303030382e312e322e3240000011312e322e3834302e31" +
		"303030382e312e325000003a51000004000040005200001b312e322e3237362e" +
		"302e373233303031302e332e302e332e362e305500000f4f464649535f44434d" +
		"544b5f333630")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestReadPDU(t *testing.T) {
	pdu, err := ReadPDU(bytes.NewReader(append(append([]byte{}, issue50AssociateRQ...), BuildReleaseRP()...)))
	require.NoError(t, err)
	require.Equal(t, issue50AssociateRQ, pdu)

	_, err = ReadPDU(bytes.NewReader([]byte{0x04, 0, 0xff, 0xff, 0xff, 0xff}))
	require.ErrorIs(t, err, ErrPDUTooLarge)

	_, err = ReadPDU(bytes.NewReader([]byte{0x04, 0, 0, 0, 0, 10, 1, 2}))
	require.Error(t, err)
}

func TestParseAssociateRQIssue50(t *testing.T) {
	rq, err := ParseAssociateRQ(issue50AssociateRQ)
	require.NoError(t, err)
	require.Equal(t, uint16(1), rq.ProtocolVersion)
	require.Equal(t, "ANY-SCP", rq.CalledAE)
	require.Equal(t, "FINDSCU", rq.CallingAE)
	require.Equal(t, ApplicationContextUID, rq.ApplicationContext)
	require.Equal(t, []PresentationContext{{
		ID:             1,
		AbstractSyntax: "1.2.840.10008.5.1.4.31",
		TransferSyntaxes: []string{
			ExplicitVRLittleEndian,
			"1.2.840.10008.1.2.2",
			ImplicitVRLittleEndian,
		},
	}}, rq.PresentationContexts)
	require.Equal(t, uint32(16384), rq.MaxLength)
	require.Equal(t, "1.2.276.0.7230010.3.0.3.6.0", rq.ImplementationClassUID)
	require.Equal(t, "OFFIS_DCMTK_360", rq.ImplementationVersion)
	require.Equal(t, []string{"1.2.840.10008.5.1.4.31"}, rq.AbstractSyntaxes())
}

func TestParseAssociateRQMalformed(t *testing.T) {
	_, err := ParseAssociateRQ(issue50AssociateRQ[:40])
	require.ErrorIs(t, err, ErrMalformed)

	// truncate inside the user info item: AE titles still decode
	rq, err := ParseAssociateRQ(issue50AssociateRQ[:len(issue50AssociateRQ)-4])
	require.ErrorIs(t, err, ErrMalformed)
	require.Equal(t, "ANY-SCP", rq.CalledAE)
}

func TestParseAssociateRQUserIdentity(t *testing.T) {
	ident := []byte{2, 1}
	ident = binary.BigEndian.AppendUint16(ident, 5)
	ident = append(ident, "admin"...)
	ident = binary.BigEndian.AppendUint16(ident, 6)
	ident = append(ident, "secret"...)
	ui := appendItem(nil, itemUserIdentity, ident)

	body := append([]byte{0, 1, 0, 0}, []byte("SCP             SCU             ")...)
	body = append(body, make([]byte, 32)...)
	body = appendItem(body, itemUserInfo, ui)
	rq, err := ParseAssociateRQ(appendPDU(PDUAssociateRQ, body))
	require.NoError(t, err)
	require.Equal(t, "admin", rq.Username)
	require.Equal(t, byte(2), rq.UserIdentityType)
	require.True(t, rq.UserIdentityResponse)

	ac := BuildAssociateAC(rq)
	require.True(t, bytes.Contains(ac, []byte{itemUserIdentityAC, 0, 0, 2, 0, 0}))
}

func TestBuildAssociateAC(t *testing.T) {
	rq, err := ParseAssociateRQ(issue50AssociateRQ)
	require.NoError(t, err)
	ac := BuildAssociateAC(rq)
	require.Equal(t, PDUAssociateAC, ac[0])
	require.Equal(t, uint32(len(ac)-HeaderLen), binary.BigEndian.Uint32(ac[2:6]))
	// called/calling AE titles are echoed byte for byte
	require.Equal(t, issue50AssociateRQ[10:42], ac[10:42])

	items, err := splitItems(ac[HeaderLen+4+2*aeTitleLen+32:])
	require.NoError(t, err)
	require.Len(t, items, 3)
	require.Equal(t, itemApplicationContext, items[0].typ)
	require.Equal(t, ApplicationContextUID, string(items[0].value))

	require.Equal(t, itemPresentationContextA, items[1].typ)
	pc := items[1].value
	require.Equal(t, []byte{1, 0, 0, 0}, pc[:4]) // id 1, accepted
	ts, err := splitItems(pc[4:])
	require.NoError(t, err)
	require.Equal(t, ImplicitVRLittleEndian, string(ts[0].value))

	require.Equal(t, itemUserInfo, items[2].typ)
	ui, err := splitItems(items[2].value)
	require.NoError(t, err)
	require.Equal(t, uint32(MaxReceiveLength), binary.BigEndian.Uint32(ui[0].value))
	require.Equal(t, ImplementationClassUID, string(ui[1].value))
	require.Equal(t, ImplementationVersion, string(ui[2].value))
}

func TestChooseTransferSyntax(t *testing.T) {
	ts, ok := chooseTransferSyntax([]string{"1.2.840.10008.1.2.4.50", ExplicitVRLittleEndian})
	require.True(t, ok)
	require.Equal(t, ExplicitVRLittleEndian, ts)

	ts, ok = chooseTransferSyntax([]string{"1.2.840.10008.1.2.4.50"})
	require.True(t, ok)
	require.Equal(t, "1.2.840.10008.1.2.4.50", ts)

	_, ok = chooseTransferSyntax(nil)
	require.False(t, ok)
}

func echoRQ(msgID uint16) []byte {
	return encodeCommand([]element{
		{tagAffectedSOPClassUID, uiValue(VerificationSOPClass)},
		{tagCommandField, usValue(CEchoRQ)},
		{tagMessageID, usValue(msgID)},
		{tagCommandDataSetType, usValue(noDataSet)},
	})
}

func TestPDataRoundTrip(t *testing.T) {
	pdu := BuildPData(3, true, true, echoRQ(7))
	pdvs, err := ParsePData(pdu)
	require.NoError(t, err)
	require.Len(t, pdvs, 1)
	require.Equal(t, byte(3), pdvs[0].ContextID)
	require.True(t, pdvs[0].Command)
	require.True(t, pdvs[0].Last)

	cmd, err := ParseCommand(pdvs[0].Data)
	require.NoError(t, err)
	require.Equal(t, Command{Field: CEchoRQ, MessageID: 7, SOPClassUID: VerificationSOPClass, DataSetType: noDataSet}, cmd)
	require.Equal(t, "C-ECHO-RQ", CommandName(cmd.Field))

	_, err = ParsePData([]byte{0x04, 0, 0, 0, 0, 4, 0, 0, 0, 9})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestParseCommandMalformed(t *testing.T) {
	_, err := ParseCommand([]byte{0, 0, 0, 1, 0xff, 0, 0, 0})
	require.ErrorIs(t, err, ErrMalformed)
	// no command field
	_, err = ParseCommand(encodeCommand([]element{{tagMessageID, usValue(1)}}))
	require.ErrorIs(t, err, ErrMalformed)
}

func TestResponse(t *testing.T) {
	resp, ok := Response(Command{Field: CEchoRQ, MessageID: 9, DataSetType: noDataSet})
	require.True(t, ok)
	require.Equal(t, Command{Field: 0x8030, RespondedTo: 9, SOPClassUID: VerificationSOPClass, DataSetType: noDataSet}, resp)

	encoded, err := ParseCommand(EncodeCommand(resp))
	require.NoError(t, err)
	require.Equal(t, resp, encoded)
	require.Equal(t, "C-ECHO-RSP", CommandName(resp.Field))

	resp, ok = Response(Command{Field: CStoreRQ, MessageID: 2, SOPClassUID: "1.2.840.10008.5.1.4.1.1.7", SOPInstanceUID: "1.2.3"})
	require.True(t, ok)
	encoded, err = ParseCommand(EncodeCommand(resp))
	require.NoError(t, err)
	require.Equal(t, "1.2.3", encoded.SOPInstanceUID)
	require.Equal(t, StatusSuccess, encoded.Status)

	// C-MOVE/C-GET are refused: no move destinations, no sub-operations
	resp, ok = Response(Command{Field: CMoveRQ, MessageID: 4, MoveDestination: "EVIL"})
	require.True(t, ok)
	encoded, err = ParseCommand(EncodeCommand(resp))
	require.NoError(t, err)
	require.Equal(t, StatusMoveDestinationUnknown, encoded.Status)
	require.Equal(t, "MoveDestinationUnknown", StatusName(resp.Status))
	resp, ok = Response(Command{Field: CGetRQ, MessageID: 5})
	require.True(t, ok)
	require.Equal(t, StatusOutOfResourcesSubOps, resp.Status)
	require.Equal(t, "OutOfResources", StatusName(resp.Status))

	resp, ok = Response(Command{Field: NGetRQ, MessageID: 3})
	require.True(t, ok)
	require.Equal(t, StatusUnrecOp, resp.Status)
	require.Equal(t, "UnrecognizedOperation", StatusName(resp.Status))

	_, ok = Response(Command{Field: CCancelRQ})
	require.False(t, ok)
	_, ok = Response(Command{Field: 0x8030})
	require.False(t, ok)
}

func TestAssembler(t *testing.T) {
	var a Assembler
	store := encodeCommand([]element{
		{tagAffectedSOPClassUID, uiValue("1.2.840.10008.5.1.4.1.1.7")},
		{tagCommandField, usValue(CStoreRQ)},
		{tagMessageID, usValue(1)},
		{tagCommandDataSetType, usValue(0)},
		{tagAffectedSOPInstanceUID, uiValue("1.2.3.4")},
	})

	msg, err := a.Add(PDV{ContextID: 1, Command: true, Data: store[:10]})
	require.NoError(t, err)
	require.Nil(t, msg)
	msg, err = a.Add(PDV{ContextID: 1, Command: true, Last: true, Data: store[10:]})
	require.NoError(t, err)
	require.Nil(t, msg)
	msg, err = a.Add(PDV{ContextID: 1, Data: []byte("DICM")})
	require.NoError(t, err)
	require.Nil(t, msg)
	msg, err = a.Add(PDV{ContextID: 1, Last: true, Data: []byte("data")})
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.Equal(t, CStoreRQ, msg.Command.Field)
	require.Equal(t, "1.2.3.4", msg.Command.SOPInstanceUID)
	require.Equal(t, []byte("DICMdata"), msg.DataSet)
	require.False(t, msg.Truncated)

	// command-only message completes immediately
	msg, err = a.Add(PDV{ContextID: 1, Command: true, Last: true, Data: echoRQ(2)})
	require.NoError(t, err)
	require.Equal(t, CEchoRQ, msg.Command.Field)

	// data without a command is malformed
	_, err = a.Add(PDV{ContextID: 1, Last: true, Data: []byte("x")})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestAssemblerTruncatesDataSet(t *testing.T) {
	var a Assembler
	store := encodeCommand([]element{
		{tagCommandField, usValue(CStoreRQ)},
		{tagCommandDataSetType, usValue(0)},
	})
	_, err := a.Add(PDV{Command: true, Last: true, Data: store})
	require.NoError(t, err)
	_, err = a.Add(PDV{Data: make([]byte, MaxDataSet-1)})
	require.NoError(t, err)
	msg, err := a.Add(PDV{Last: true, Data: []byte{1, 2, 3}})
	require.NoError(t, err)
	require.True(t, msg.Truncated)
	require.Len(t, msg.DataSet, MaxDataSet)
}
