package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
	"github.com/xiegeo/modbusone"
)

func waitModbusEvent(t *testing.T, hp *fakeHoneypot) producedTCP {
	t.Helper()
	select {
	case ev := <-hp.produced:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced Modbus event")
		return producedTCP{}
	}
}

func readModbusADU(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	hdr := make([]byte, modbusone.TCPHeaderLength)
	_, err := io.ReadFull(conn, hdr)
	require.NoError(t, err)
	l := int(binary.BigEndian.Uint16(hdr[4:6]))
	require.Greater(t, l, 2)
	body := make([]byte, l)
	_, err = io.ReadFull(conn, body)
	require.NoError(t, err)
	return append(hdr, body...)
}

func modbusADU(txid uint16, unitID byte, pdu []byte) []byte {
	l := len(pdu) + 1
	adu := make([]byte, modbusone.TCPHeaderLength+l)
	binary.BigEndian.PutUint16(adu[0:2], txid)
	binary.BigEndian.PutUint16(adu[4:6], uint16(l))
	adu[6] = unitID
	copy(adu[7:], pdu)
	return adu
}

func startModbus(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleModbus(context.Background(), serverConn, connection.Metadata{TargetPort: 502}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func TestHandleModbusReads(t *testing.T) {
	clientConn, hp, done := startModbus(t)

	client := modbusone.NewTCPClient(clientConn, 1)
	go client.Serve(&modbusone.SimpleHandler{
		WriteCoils:            func(uint16, []bool) error { return nil },
		WriteDiscreteInputs:   func(uint16, []bool) error { return nil },
		WriteHoldingRegisters: func(uint16, []uint16) error { return nil },
		WriteInputRegisters:   func(uint16, []uint16) error { return nil },
	})
	defer client.Close()

	for _, fc := range []modbusone.FunctionCode{
		modbusone.FcReadCoils,
		modbusone.FcReadDiscreteInputs,
		modbusone.FcReadHoldingRegisters,
		modbusone.FcReadInputRegisters,
	} {
		pdu, err := fc.MakeRequestHeader(0, 1)
		require.NoError(t, err)
		require.NoError(t, client.DoTransaction(pdu))
	}

	require.NoError(t, clientConn.Close())
	require.NoError(t, <-done)

	ev := waitModbusEvent(t, hp)
	require.Equal(t, "modbus", ev.protocol)
	events, ok := ev.decoded.([]parsedModbus)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 8)

	reads := map[string]int{}
	writes := 0
	for _, e := range events {
		if e.Direction == "read" {
			reads[e.FunctionCode]++
			require.NotEmpty(t, e.Payload)
		}
		if e.Direction == "write" {
			writes++
			require.GreaterOrEqual(t, len(e.Payload), modbusone.MBAPHeaderLength)
		}
	}
	require.Equal(t, 1, reads["ReadCoils"])
	require.Equal(t, 1, reads["ReadDiscreteInputs"])
	require.Equal(t, 1, reads["ReadHoldingRegisters"])
	require.Equal(t, 1, reads["ReadInputRegisters"])
	require.Equal(t, 4, writes)
}

func TestHandleModbusMBAPEchoAndWriteRoundTrip(t *testing.T) {
	client, hp, done := startModbus(t)

	writePDU := []byte{byte(modbusone.FcWriteSingleRegister), 0x00, 0x0a, 0xab, 0xcd}
	writeADU := modbusADU(0x1234, 0x11, writePDU)
	_, err := client.Write(writeADU)
	require.NoError(t, err)
	writeReply := readModbusADU(t, client)
	require.Equal(t, []byte{0x12, 0x34}, writeReply[0:2])
	require.Equal(t, byte(0x11), writeReply[6])
	require.Equal(t, writePDU, writeReply[7:])

	readPDU := []byte{byte(modbusone.FcReadHoldingRegisters), 0x00, 0x0a, 0x00, 0x01}
	readADU := modbusADU(0x1235, 0x11, readPDU)
	_, err = client.Write(readADU)
	require.NoError(t, err)
	readReply := readModbusADU(t, client)
	require.Equal(t, []byte{0x12, 0x35}, readReply[0:2])
	require.Equal(t, byte(0x11), readReply[6])
	require.Equal(t, byte(modbusone.FcReadHoldingRegisters), readReply[7])
	require.Equal(t, byte(2), readReply[8])
	require.Equal(t, []byte{0xab, 0xcd}, readReply[9:11])

	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	ev := waitModbusEvent(t, hp)
	events, ok := ev.decoded.([]parsedModbus)
	require.True(t, ok)
	require.Len(t, events, 4)
	require.Equal(t, "WriteSingleRegister", events[0].FunctionCode)
	require.Equal(t, uint8(0x11), events[0].UnitID)
	require.Equal(t, uint16(10), events[0].Address)
	require.Equal(t, uint16(1), events[0].Quantity)
	require.Equal(t, writeADU, events[0].Payload)
	require.Equal(t, writeReply, events[1].Payload)
	require.Equal(t, "ReadHoldingRegisters", events[2].FunctionCode)
	require.Equal(t, readReply, events[3].Payload)
}

func TestHandleModbusUnsupportedFunction(t *testing.T) {
	client, hp, done := startModbus(t)

	req := modbusADU(0x0007, 0x01, []byte{0x11, 0x00, 0x00, 0x00, 0x01})
	_, err := client.Write(req)
	require.NoError(t, err)
	reply := readModbusADU(t, client)
	require.Equal(t, []byte{0x00, 0x07}, reply[0:2])
	require.Equal(t, byte(0x01), reply[6])
	require.Equal(t, byte(0x11|0x80), reply[7])
	require.Equal(t, byte(modbusone.EcIllegalFunction), reply[8])

	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	ev := waitModbusEvent(t, hp)
	events, ok := ev.decoded.([]parsedModbus)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "UNKNOWN", events[0].FunctionCode)
	require.Equal(t, "UNKNOWN", events[0].Command)
	require.Equal(t, "Exception", events[1].FunctionCode)
	require.Equal(t, "Exception", events[1].Command)
	require.Equal(t, "Exception", events[1].Status)
	require.Equal(t, uint16(0), events[1].Address)
}

// Captured on tcp/504: MBAP txid 0x1337, unit 0, FC 0x2B MEI 0x0E, basic
// stream access from object 0 (Read Device Identification discovery probe).
var modbusReadDeviceIDProbe = []byte{0x13, 0x37, 0x00, 0x00, 0x00, 0x05, 0x00, 0x2b, 0x0e, 0x01, 0x00}

func TestHandleModbusReadDeviceIdentification(t *testing.T) {
	client, hp, done := startModbus(t)

	_, err := client.Write(modbusReadDeviceIDProbe)
	require.NoError(t, err)
	reply := readModbusADU(t, client)

	want := []byte{0x13, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2b, 0x0e, 0x01, 0x82, 0x00, 0x00, 0x03,
		0x00, 18}
	want = append(want, "Schneider Electric"...)
	want = append(want, 0x01, 12)
	want = append(want, "BMX P34 2020"...)
	want = append(want, 0x02, 5)
	want = append(want, "v2.70"...)
	binary.BigEndian.PutUint16(want[4:6], uint16(len(want)-6))
	require.Equal(t, want, reply)

	// Individual access to an unknown object is an illegal data address.
	bad := modbusADU(0x1338, 0x00, []byte{0x2b, 0x0e, 0x04, 0x42})
	_, err = client.Write(bad)
	require.NoError(t, err)
	excReply := readModbusADU(t, client)
	require.Equal(t, []byte{0x13, 0x38, 0x00, 0x00, 0x00, 0x03, 0x00, 0xab, 0x02}, excReply)

	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	ev := waitModbusEvent(t, hp)
	require.Equal(t, "modbus", ev.protocol)
	events, ok := ev.decoded.([]parsedModbus)
	require.True(t, ok)
	require.Equal(t, []parsedModbus{
		{Direction: "read", Command: "ReadDeviceIdentification", FunctionCode: "EncapsulatedInterfaceTransport", DeviceIDCode: 1, Payload: modbusReadDeviceIDProbe},
		{Direction: "write", Command: "ReadDeviceIdentification", FunctionCode: "EncapsulatedInterfaceTransport", DeviceIDCode: 1, Payload: reply},
		{Direction: "read", Command: "ReadDeviceIdentification", FunctionCode: "EncapsulatedInterfaceTransport", DeviceIDCode: 4, ObjectID: 0x42, Payload: bad},
		{Direction: "write", Command: "Exception", FunctionCode: "Exception", Status: "Exception", DeviceIDCode: 4, ObjectID: 0x42, Payload: excReply},
	}, events)
}

func TestHandleModbusEarlyDisconnect(t *testing.T) {
	client, hp, done := startModbus(t)
	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitModbusEvent(t, hp)
	require.Equal(t, "modbus", ev.protocol)
	events, ok := ev.decoded.([]parsedModbus)
	require.True(t, ok)
	require.Empty(t, events)
}

func TestHandleModbusMalformedMBAP(t *testing.T) {
	client, hp, done := startModbus(t)
	_, _ = client.Write([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x06})
	_ = client.Close()
	require.NoError(t, <-done)
	ev := waitModbusEvent(t, hp)
	require.Equal(t, "modbus", ev.protocol)
	events, ok := ev.decoded.([]parsedModbus)
	require.True(t, ok)
	require.Empty(t, events)
}
