package tcp

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/tcp/dicom"
	"github.com/stretchr/testify/require"
)

// dicomIssue50RQ is the findscu A-ASSOCIATE-RQ from mushorg/glutton#50.
var dicomIssue50RQ, _ = hex.DecodeString(
	"01000000010000010000414e592d53435020202020202020202046494e445343" +
		"5520202020202020202000000000000000000000000000000000000000000000" +
		"0000000000000000000010000015312e322e3834302e31303030382e332e312e" +
		"312e31200000610100ff0030000016312e322e3834302e31303030382e352e31" +
		"2e342e333140000013312e322e3834302e31303030382e312e322e3140000013" +
		"312e322e3834302e31303030382e312e322e3240000011312e322e3834302e31" +
		"303030382e312e325000003a51000004000040005200001b312e322e3237362e" +
		"302e373233303031302e332e302e332e362e305500000f4f464649535f44434d" +
		"544b5f333630")

const (
	worklistFind = "1.2.840.10008.5.1.4.31"
	secondaryCap = "1.2.840.10008.5.1.4.1.1.7"
)

type dicomElem struct {
	tag   uint16
	value []byte
}

func dicomUS(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

func dicomUI(s string) []byte {
	if len(s)%2 == 1 {
		s += "\x00"
	}
	return []byte(s)
}

// dicomCommand encodes a group 0000 command set without a group length.
func dicomCommand(elems ...dicomElem) []byte {
	var b []byte
	for _, e := range elems {
		b = binary.LittleEndian.AppendUint16(b, 0)
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(e.value)))
		b = append(b, e.value...)
	}
	return b
}

func startDICOM(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleDICOM(context.Background(), serverConn, connection.Metadata{TargetPort: 104}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitDICOM(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DICOM handler")
	}
	select {
	case ev := <-hp.produced:
		require.Equal(t, "dicom", ev.protocol)
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced DICOM event")
		return producedTCP{}
	}
}

func dicomRoundTrip(t *testing.T, conn net.Conn, pdus ...[]byte) []byte {
	t.Helper()
	for _, p := range pdus {
		_, err := conn.Write(p)
		require.NoError(t, err)
	}
	reply, err := dicom.ReadPDU(conn)
	require.NoError(t, err)
	return reply
}

func TestHandleDICOMIssue50FindSession(t *testing.T) {
	client, hp, done := startDICOM(t)

	ac := dicomRoundTrip(t, client, dicomIssue50RQ)
	rq, err := dicom.ParseAssociateRQ(dicomIssue50RQ)
	require.NoError(t, err)
	require.Equal(t, dicom.BuildAssociateAC(rq), ac)

	findCmd := dicom.BuildPData(1, true, true, dicomCommand(
		dicomElem{0x0002, dicomUI(worklistFind)},
		dicomElem{0x0100, dicomUS(dicom.CFindRQ)},
		dicomElem{0x0110, dicomUS(5)},
		dicomElem{0x0700, dicomUS(0)},
		dicomElem{0x0800, dicomUS(0)},
	))
	// (0010,0010) PatientName = "*" in Implicit VR LE, the accepted transfer syntax
	findData := dicom.BuildPData(1, false, true, []byte{0x10, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, '*', ' '})
	rsp := dicomRoundTrip(t, client, findCmd, findData)
	pdvs, err := dicom.ParsePData(rsp)
	require.NoError(t, err)
	require.Len(t, pdvs, 1)
	cmd, err := dicom.ParseCommand(pdvs[0].Data)
	require.NoError(t, err)
	require.Equal(t, uint16(0x8020), cmd.Field)
	require.Equal(t, uint16(5), cmd.RespondedTo)
	require.Equal(t, dicom.StatusSuccess, cmd.Status)
	require.False(t, cmd.HasDataSet())

	release := []byte{dicom.PDUReleaseRQ, 0, 0, 0, 0, 4, 0, 0, 0, 0}
	rp := dicomRoundTrip(t, client, release)
	require.Equal(t, dicom.BuildReleaseRP(), rp)

	ev := waitDICOM(t, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, []parsedDICOM{
		{
			Direction:              "read",
			Command:                "A-ASSOCIATE-RQ",
			Path:                   "ANY-SCP",
			PDUType:                "A-ASSOCIATE-RQ",
			CalledAE:               "ANY-SCP",
			CallingAE:              "FINDSCU",
			ApplicationContext:     dicom.ApplicationContextUID,
			AbstractSyntaxes:       []string{worklistFind},
			TransferSyntaxes:       []string{dicom.ExplicitVRLittleEndian, "1.2.840.10008.1.2.2", dicom.ImplicitVRLittleEndian},
			ImplementationClassUID: "1.2.276.0.7230010.3.0.3.6.0",
			ImplementationVersion:  "OFFIS_DCMTK_360",
			Payload:                dicomIssue50RQ,
		},
		{Direction: "write", Command: "A-ASSOCIATE-AC", PDUType: "A-ASSOCIATE-AC", Status: "Accepted", Payload: ac},
		{Direction: "read", Command: "C-FIND-RQ", PDUType: "P-DATA-TF", MessageID: 5, SOPClassUID: worklistFind, Query: map[string]string{"PatientName": "*"}, Payload: append(append([]byte{}, findCmd...), findData...)},
		{Direction: "write", Command: "C-FIND-RSP", PDUType: "P-DATA-TF", Status: "Success", MessageID: 5, SOPClassUID: worklistFind, Payload: rsp},
		{Direction: "read", Command: "A-RELEASE-RQ", PDUType: "A-RELEASE-RQ", Payload: release},
		{Direction: "write", Command: "A-RELEASE-RP", PDUType: "A-RELEASE-RP", Payload: rp},
	}, ev.decoded)
}

func TestHandleDICOMStoreAndEcho(t *testing.T) {
	var mu sync.Mutex
	var stored [][]byte
	prev := storeDicom
	storeDicom = func(data []byte) error {
		mu.Lock()
		defer mu.Unlock()
		stored = append(stored, data)
		return nil
	}
	t.Cleanup(func() { storeDicom = prev })

	client, hp, done := startDICOM(t)
	_ = dicomRoundTrip(t, client, dicomIssue50RQ)

	echo := dicom.BuildPData(1, true, true, dicomCommand(
		dicomElem{0x0100, dicomUS(dicom.CEchoRQ)},
		dicomElem{0x0110, dicomUS(1)},
		dicomElem{0x0800, dicomUS(0x0101)},
	))
	echoRsp := dicomRoundTrip(t, client, echo)
	pdvs, err := dicom.ParsePData(echoRsp)
	require.NoError(t, err)
	cmd, err := dicom.ParseCommand(pdvs[0].Data)
	require.NoError(t, err)
	require.Equal(t, uint16(0x8030), cmd.Field)
	require.Equal(t, dicom.VerificationSOPClass, cmd.SOPClassUID)

	storeCmd := dicom.BuildPData(1, true, true, dicomCommand(
		dicomElem{0x0002, dicomUI(secondaryCap)},
		dicomElem{0x0100, dicomUS(dicom.CStoreRQ)},
		dicomElem{0x0110, dicomUS(2)},
		dicomElem{0x0800, dicomUS(0)},
		dicomElem{0x1000, dicomUI("1.2.3.4.5")},
	))
	part1 := dicom.BuildPData(1, false, false, []byte("first-"))
	part2 := dicom.BuildPData(1, false, true, []byte("second"))
	storeRsp := dicomRoundTrip(t, client, storeCmd, part1, part2)
	pdvs, err = dicom.ParsePData(storeRsp)
	require.NoError(t, err)
	cmd, err = dicom.ParseCommand(pdvs[0].Data)
	require.NoError(t, err)
	require.Equal(t, uint16(0x8001), cmd.Field)
	require.Equal(t, "1.2.3.4.5", cmd.SOPInstanceUID)

	abort := dicom.BuildAbort(0, 0)
	_, err = client.Write(abort)
	require.NoError(t, err)

	ev := waitDICOM(t, hp, done)
	frames := ev.decoded.([]parsedDICOM)
	require.Len(t, frames, 7)
	require.Equal(t, "C-ECHO-RQ", frames[2].Command)
	require.Equal(t, "C-ECHO-RSP", frames[3].Command)
	require.Equal(t, "Success", frames[3].Status)
	require.Equal(t, parsedDICOM{
		Direction:      "read",
		Command:        "C-STORE-RQ",
		PDUType:        "P-DATA-TF",
		MessageID:      2,
		SOPClassUID:    secondaryCap,
		SOPInstanceUID: "1.2.3.4.5",
		PayloadHash:    helpers.SHA256Hex([]byte("first-second")),
		Payload:        append(append(append([]byte{}, storeCmd...), part1...), part2...),
	}, frames[4])
	require.Equal(t, "C-STORE-RSP", frames[5].Command)
	require.Equal(t, parsedDICOM{Direction: "read", Command: "A-ABORT", PDUType: "A-ABORT", Payload: abort}, frames[6])

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, [][]byte{[]byte("first-second")}, stored)
}

func TestHandleDICOMPDataBeforeAssociationAborts(t *testing.T) {
	client, hp, done := startDICOM(t)
	pdata := dicom.BuildPData(1, true, true, dicomCommand(dicomElem{0x0100, dicomUS(dicom.CEchoRQ)}))
	reply := dicomRoundTrip(t, client, pdata)
	require.Equal(t, dicom.BuildAbort(2, 2), reply)

	ev := waitDICOM(t, hp, done)
	require.Equal(t, []parsedDICOM{
		{Direction: "read", Command: "P-DATA-TF", PDUType: "P-DATA-TF", Payload: pdata},
		{Direction: "write", Command: "A-ABORT", PDUType: "A-ABORT", Payload: reply},
	}, ev.decoded)
}

func TestHandleDICOMMalformedAssociateRejects(t *testing.T) {
	client, hp, done := startDICOM(t)
	bad := []byte{dicom.PDUAssociateRQ, 0, 0, 0, 0, 4, 0, 1, 0, 0}
	reply := dicomRoundTrip(t, client, bad)
	require.Equal(t, dicom.BuildAssociateRJ(1, 1, 1), reply)

	ev := waitDICOM(t, hp, done)
	frames := ev.decoded.([]parsedDICOM)
	require.Len(t, frames, 2)
	require.Equal(t, "A-ASSOCIATE-RQ", frames[0].Command)
	require.Equal(t, parsedDICOM{Direction: "write", Command: "A-ASSOCIATE-RJ", PDUType: "A-ASSOCIATE-RJ", Status: "Rejected", Payload: reply}, frames[1])
}

func TestHandleDICOMMalformedPDataAborts(t *testing.T) {
	client, hp, done := startDICOM(t)
	_ = dicomRoundTrip(t, client, dicomIssue50RQ)
	// data set fragment with no preceding command
	pdata := dicom.BuildPData(1, false, true, []byte("orphan"))
	reply := dicomRoundTrip(t, client, pdata)
	require.Equal(t, dicom.BuildAbort(2, 2), reply)

	ev := waitDICOM(t, hp, done)
	frames := ev.decoded.([]parsedDICOM)
	require.Len(t, frames, 4)
	require.Equal(t, parsedDICOM{Direction: "read", Command: "P-DATA-TF", PDUType: "P-DATA-TF", Payload: pdata}, frames[2])
	require.Equal(t, "A-ABORT", frames[3].Command)
}

func TestHandleDICOMEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startDICOM(t)
	require.NoError(t, client.Close())

	ev := waitDICOM(t, hp, done)
	require.Empty(t, ev.decoded)
	require.Equal(t, connection.EndClientClose, ev.endReason)
}

func TestHandleDICOMTruncatedPDUStillProduces(t *testing.T) {
	client, hp, done := startDICOM(t)
	_, err := client.Write(dicomIssue50RQ[:100])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	ev := waitDICOM(t, hp, done)
	require.Empty(t, ev.decoded)
	require.Equal(t, connection.EndReadError, ev.endReason)
}

const studyRootMove = "1.2.840.10008.5.1.4.1.2.2.2"

// dicomAssociateRQ builds a synthetic A-ASSOCIATE-RQ (no user info item).
func dicomAssociateRQ(called, calling string, contexts ...dicom.PresentationContext) []byte {
	item := func(typ byte, v []byte) []byte {
		return append(binary.BigEndian.AppendUint16([]byte{typ, 0}, uint16(len(v))), v...)
	}
	body := []byte{0, 1, 0, 0}
	body = append(body, fmt.Sprintf("%-16s%-16s", called, calling)...)
	body = append(body, make([]byte, 32)...)
	body = append(body, item(0x10, []byte(dicom.ApplicationContextUID))...)
	for _, pc := range contexts {
		v := append([]byte{pc.ID, 0, 0, 0}, item(0x30, []byte(pc.AbstractSyntax))...)
		for _, ts := range pc.TransferSyntaxes {
			v = append(v, item(0x40, []byte(ts))...)
		}
		body = append(body, item(0x20, v)...)
	}
	return append(binary.BigEndian.AppendUint32([]byte{dicom.PDUAssociateRQ, 0}, uint32(len(body))), body...)
}

func dicomReadCommand(t *testing.T, pdu []byte) (dicom.Command, []dicom.PDV) {
	t.Helper()
	pdvs, err := dicom.ParsePData(pdu)
	require.NoError(t, err)
	require.NotEmpty(t, pdvs)
	cmd, err := dicom.ParseCommand(pdvs[0].Data)
	require.NoError(t, err)
	return cmd, pdvs
}

// Synthetic Study Root session as sent by `findscu -S -k PatientName=MIL*`
// followed by `movescu -aem EVIL`: the find returns the matching archive
// entry, the move is refused without connecting anywhere.
func TestHandleDICOMStudyRootFindAndMove(t *testing.T) {
	client, hp, done := startDICOM(t)

	assoc := dicomAssociateRQ("PACS", "FINDSCU",
		dicom.PresentationContext{ID: 1, AbstractSyntax: dicom.StudyRootFind, TransferSyntaxes: []string{dicom.ExplicitVRLittleEndian}},
		dicom.PresentationContext{ID: 3, AbstractSyntax: studyRootMove, TransferSyntaxes: []string{dicom.ExplicitVRLittleEndian}},
	)
	ac := dicomRoundTrip(t, client, assoc)
	require.Equal(t, dicom.PDUAssociateAC, ac[0])

	findCmd := dicom.BuildPData(1, true, true, dicomCommand(
		dicomElem{0x0002, dicomUI(dicom.StudyRootFind)},
		dicomElem{0x0100, dicomUS(dicom.CFindRQ)},
		dicomElem{0x0110, dicomUS(1)},
		dicomElem{0x0700, dicomUS(0)},
		dicomElem{0x0800, dicomUS(0)},
	))
	// QueryRetrieveLevel=STUDY, PatientName=MIL*, StudyInstanceUID return key (Explicit VR LE)
	identifier, _ := hex.DecodeString("080052004353060053545544592010001000504e04004d494c2a20000d0055490000")
	findData := dicom.BuildPData(1, false, true, identifier)
	pending := dicomRoundTrip(t, client, findCmd, findData)
	cmd, pdvs := dicomReadCommand(t, pending)
	require.Equal(t, dicom.StatusPending, cmd.Status)
	require.Equal(t, uint16(1), cmd.RespondedTo)
	require.Len(t, pdvs, 2)
	elems, err := dicom.ParseDataSet(pdvs[1].Data, dicom.ExplicitVRLittleEndian)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"QueryRetrieveLevel": "STUDY",
		"PatientName":        "MILLER^ANNA",
		"StudyInstanceUID":   "1.2.276.0.7230010.3.1.2.2831156423.4120.1726558452.215",
	}, dicom.QueryMap(elems))

	final, err := dicom.ReadPDU(client)
	require.NoError(t, err)
	cmd, _ = dicomReadCommand(t, final)
	require.Equal(t, dicom.StatusSuccess, cmd.Status)
	require.False(t, cmd.HasDataSet())

	moveCmd := dicom.BuildPData(3, true, true, dicomCommand(
		dicomElem{0x0002, dicomUI(studyRootMove)},
		dicomElem{0x0100, dicomUS(dicom.CMoveRQ)},
		dicomElem{0x0110, dicomUS(2)},
		dicomElem{0x0600, []byte("EVIL            ")},
		dicomElem{0x0700, dicomUS(0)},
		dicomElem{0x0800, dicomUS(0)},
	))
	// QueryRetrieveLevel=STUDY, StudyInstanceUID=1.2.3.4
	moveIdent, _ := hex.DecodeString("0800520043530600535455445920" + "20000d0055490800312e322e332e3400")
	moveData := dicom.BuildPData(3, false, true, moveIdent)
	moveRsp := dicomRoundTrip(t, client, moveCmd, moveData)
	cmd, _ = dicomReadCommand(t, moveRsp)
	require.Equal(t, uint16(0x8021), cmd.Field)
	require.Equal(t, dicom.StatusMoveDestinationUnknown, cmd.Status)

	abort := dicom.BuildAbort(0, 0)
	_, err = client.Write(abort)
	require.NoError(t, err)

	ev := waitDICOM(t, hp, done)
	frames := ev.decoded.([]parsedDICOM)
	require.Len(t, frames, 8)
	require.Equal(t, "PACS", frames[0].CalledAE)
	require.Equal(t, parsedDICOM{
		Direction:   "read",
		Command:     "C-FIND-RQ",
		PDUType:     "P-DATA-TF",
		MessageID:   1,
		SOPClassUID: dicom.StudyRootFind,
		Query:       map[string]string{"QueryRetrieveLevel": "STUDY", "PatientName": "MIL*", "StudyInstanceUID": ""},
		Payload:     append(append([]byte{}, findCmd...), findData...),
	}, frames[2])
	require.Equal(t, parsedDICOM{Direction: "write", Command: "C-FIND-RSP", PDUType: "P-DATA-TF", Status: "Pending", MessageID: 1, SOPClassUID: dicom.StudyRootFind, Payload: pending}, frames[3])
	require.Equal(t, parsedDICOM{Direction: "write", Command: "C-FIND-RSP", PDUType: "P-DATA-TF", Status: "Success", MessageID: 1, SOPClassUID: dicom.StudyRootFind, Payload: final}, frames[4])
	require.Equal(t, parsedDICOM{
		Direction:       "read",
		Command:         "C-MOVE-RQ",
		PDUType:         "P-DATA-TF",
		MessageID:       2,
		SOPClassUID:     studyRootMove,
		MoveDestination: "EVIL",
		Query:           map[string]string{"QueryRetrieveLevel": "STUDY", "StudyInstanceUID": "1.2.3.4"},
		Payload:         append(append([]byte{}, moveCmd...), moveData...),
	}, frames[5])
	require.Equal(t, parsedDICOM{Direction: "write", Command: "C-MOVE-RSP", PDUType: "P-DATA-TF", Status: "MoveDestinationUnknown", MessageID: 2, SOPClassUID: studyRootMove, Payload: moveRsp}, frames[6])
	require.Equal(t, "A-ABORT", frames[7].Command)
}
