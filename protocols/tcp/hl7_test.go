package tcp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/hl7"
	"github.com/stretchr/testify/require"
)

// synthetic messages in the HL7 v2 shape; no traffic was captured and the
// patient data is made up
const (
	hl7ADTA01 = "MSH|^~\\&|REGADT|GOODHOSP|LAB|LABFAC|20261017093000||ADT^A01^ADT_A01|MSG00042|P|2.5\r" +
		"EVN|A01|20261017093000\r" +
		"PID|1||100234^^^GOODHOSP^MR||DOE^JANE||19800101|F\r" +
		"PV1|1|I|WARD1^101^A\r"
	hl7QRYA19 = "MSH|^~\\&|SCAN|X|||20261017093005||QRY^A19|Q7|P|2.3\rQRD|20261017|R|I|Q7|||10^RD|*|DEM\r"
	// medpot's scripts/send.sh pipes the message through nc: no MLLP, LF line ends
	hl7RawADT = "MSH|^~\\&|ADT1|MCM|LABADT|MCM|20261017112600|SECURITY|ADT^A01|MSG00001-|P|2.6\nEVN|A01|20261017112300\nPID|||PATID1234^5^M11||ROE^RICHARD\n"
)

func stubHL7(t *testing.T) {
	t.Helper()
	prevNow, prevID := hl7Now, hl7ControlID
	ids := []string{"5001", "5002", "5003"}
	hl7Now = func() time.Time { return time.Date(2026, 10, 17, 9, 30, 1, 0, time.UTC) }
	hl7ControlID = func() string {
		id := ids[0]
		ids = ids[1:]
		return id
	}
	t.Cleanup(func() { hl7Now, hl7ControlID = prevNow, prevID })
}

func startHL7(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	stubHL7(t)
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHL7(context.Background(), serverConn, connection.Metadata{TargetPort: 2575}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func readHL7Reply(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	return buf[:n]
}

func waitHL7(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "hl7", produced.protocol)
	return produced, err
}

func TestHandleHL7MLLPSession(t *testing.T) {
	client, hp, done := startHL7(t)

	first := hl7.Frame([]byte(hl7ADTA01))
	_, err := client.Write(first)
	require.NoError(t, err)
	ack1 := readHL7Reply(t, client)
	require.Equal(t, "\x0bMSH|^~\\&|LAB|LABFAC|REGADT|GOODHOSP|20261017093001.000+0000||ACK^A01^ACK|5001|P|2.5\rMSA|AA|MSG00042\r\x1c\r", string(ack1))

	second := hl7.Frame([]byte(hl7QRYA19))
	_, err = client.Write(second)
	require.NoError(t, err)
	ack2 := readHL7Reply(t, client)
	require.Equal(t, "\x0bMSH|^~\\&|||SCAN|X|20261017093001.000+0000||ACK^A19|5002|P|2.3\rMSA|AA|Q7\r\x1c\r", string(ack2))

	require.NoError(t, client.Close())
	produced, err := waitHL7(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, first, produced.payload)
	require.Equal(t, []parsedHL7{
		{Direction: "read", Command: "ADT^A01", ControlID: "MSG00042", Version: "2.5", SendingApplication: "REGADT", SendingFacility: "GOODHOSP", ReceivingApplication: "LAB", ReceivingFacility: "LABFAC", Segments: []string{"MSH", "EVN", "PID", "PV1"}, Framing: "mllp", Payload: first},
		{Direction: "write", Command: "ACK^A01", ControlID: "5001", Version: "2.5", SendingApplication: "LAB", SendingFacility: "LABFAC", ReceivingApplication: "REGADT", ReceivingFacility: "GOODHOSP", Framing: "mllp", Status: "AA", Payload: ack1},
		{Direction: "read", Command: "QRY^A19", ControlID: "Q7", Version: "2.3", SendingApplication: "SCAN", SendingFacility: "X", Segments: []string{"MSH", "QRD"}, Framing: "mllp", Payload: second},
		{Direction: "write", Command: "ACK^A19", ControlID: "5002", Version: "2.3", ReceivingApplication: "SCAN", ReceivingFacility: "X", Framing: "mllp", Status: "AA", Payload: ack2},
	}, produced.decoded)
}

func TestHandleHL7RawRecordsSecurity(t *testing.T) {
	client, hp, done := startHL7(t)

	_, err := client.Write([]byte(hl7RawADT))
	require.NoError(t, err)
	ack := readHL7Reply(t, client)
	// unframed in, unframed out
	require.Equal(t, "MSH|^~\\&|LABADT|MCM|ADT1|MCM|20261017093001.000+0000||ACK^A01^ACK|5001|P|2.6\rMSA|AA|MSG00001-\r", string(ack))

	require.NoError(t, client.Close())
	produced, err := waitHL7(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedHL7{
		{Direction: "read", Command: "ADT^A01", ControlID: "MSG00001-", Version: "2.6", SendingApplication: "ADT1", SendingFacility: "MCM", ReceivingApplication: "LABADT", ReceivingFacility: "MCM", Security: "SECURITY", Segments: []string{"MSH", "EVN", "PID"}, Framing: "raw", Payload: []byte(hl7RawADT)},
		{Direction: "write", Command: "ACK^A01", ControlID: "5001", Version: "2.6", SendingApplication: "LABADT", SendingFacility: "MCM", ReceivingApplication: "ADT1", ReceivingFacility: "MCM", Framing: "raw", Status: "AA", Payload: ack},
	}, produced.decoded)
}

func TestHandleHL7Rejects(t *testing.T) {
	client, hp, done := startHL7(t)

	// MSH without a message type or control ID: AE
	missing := hl7.Frame([]byte("MSH|^~\\&|A|B|C|D|20261017||||P|2.5\r"))
	_, err := client.Write(missing)
	require.NoError(t, err)
	ae := readHL7Reply(t, client)
	require.Equal(t, "\x0bMSH|^~\\&|C|D|A|B|20261017093001.000+0000||ACK|5001|P|2.5\rMSA|AE|\rERR|||101^Required field missing^HL70357|E\r\x1c\r", string(ae))

	// framed, but no MSH: AR
	noMSH := hl7.Frame([]byte("PID|1||X\r"))
	_, err = client.Write(noMSH)
	require.NoError(t, err)
	ar := readHL7Reply(t, client)
	require.Equal(t, "\x0bMSH|^~\\&|||||20261017093001.000+0000||ACK|5002|P|2.5\rMSA|AR|\rERR|||100^Segment sequence error^HL70357|E\r\x1c\r", string(ar))

	require.NoError(t, client.Close())
	produced, err := waitHL7(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedHL7{
		{Direction: "read", Version: "2.5", SendingApplication: "A", SendingFacility: "B", ReceivingApplication: "C", ReceivingFacility: "D", Segments: []string{"MSH"}, Framing: "mllp", Payload: missing},
		{Direction: "write", Command: "ACK", ControlID: "5001", Version: "2.5", SendingApplication: "C", SendingFacility: "D", ReceivingApplication: "A", ReceivingFacility: "B", Framing: "mllp", Status: "AE", Payload: ae},
		{Direction: "read", Segments: []string{"PID"}, Framing: "mllp", Payload: noMSH},
		{Direction: "write", Command: "ACK", ControlID: "5002", Version: "2.5", Framing: "mllp", Status: "AR", Payload: ar},
	}, produced.decoded)
}

func TestHandleHL7Oversize(t *testing.T) {
	client, hp, done := startHL7(t)

	body := append([]byte("MSH|^~\\&|A|B|C|D|20261017||ORU^R01|BIG|P|2.5\rOBX|1|ED|"), bytes.Repeat([]byte("A"), hl7MaxMessage)...)
	go func() {
		// the handler stops reading at the cap and closes the connection
		_, _ = client.Write(hl7.Frame(body))
	}()

	produced, err := waitHL7(t, hp, done)
	require.ErrorIs(t, err, hl7.ErrTooLarge)
	require.Equal(t, connection.EndReadError, produced.endReason)
	frames := produced.decoded.([]parsedHL7)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
	require.Equal(t, "ORU^R01", frames[0].Command)
	require.Len(t, frames[0].Payload, hl7MaxMessage+1)
	require.Equal(t, append([]byte{hl7.StartBlock}, body[:hl7MaxMessage]...), frames[0].Payload)
}

func TestHandleHL7EarlyDisconnect(t *testing.T) {
	client, hp, done := startHL7(t)
	require.NoError(t, client.Close())
	produced, err := waitHL7(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Empty(t, produced.payload)
	require.Equal(t, []parsedHL7{}, produced.decoded)
}

func TestHandleHL7PartialFrame(t *testing.T) {
	client, hp, done := startHL7(t)

	partial := []byte("\x0bMSH|^~\\&|A|B|C|D|20261017||ADT^A04|P1|P|2.5\rPID|1")
	_, err := client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitHL7(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedHL7{
		{Direction: "read", Command: "ADT^A04", ControlID: "P1", Version: "2.5", SendingApplication: "A", SendingFacility: "B", ReceivingApplication: "C", ReceivingFacility: "D", Segments: []string{"MSH", "PID"}, Framing: "mllp", Payload: partial},
	}, produced.decoded)
}
