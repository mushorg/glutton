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
)

func mqttConnectPacket(clientID, username string) []byte {
	body := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04}
	flags := byte(0x02) // clean session
	if username != "" {
		flags |= 0x80
	}
	body = append(body, flags, 0x00, 0x3c)
	idLen := make([]byte, 2)
	binary.BigEndian.PutUint16(idLen, uint16(len(clientID)))
	body = append(body, idLen...)
	body = append(body, []byte(clientID)...)
	if username != "" {
		uLen := make([]byte, 2)
		binary.BigEndian.PutUint16(uLen, uint16(len(username)))
		body = append(body, uLen...)
		body = append(body, []byte(username)...)
	}
	return encodeMQTT(mqttCONNECT, 0, body)
}

func mqttPingreq() []byte {
	return encodeMQTT(mqttPINGREQ, 0, nil)
}

func mqttSubscribePacket(id uint16, topic string, qos uint8) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, id)
	tLen := make([]byte, 2)
	binary.BigEndian.PutUint16(tLen, uint16(len(topic)))
	body = append(body, tLen...)
	body = append(body, []byte(topic)...)
	body = append(body, qos)
	return encodeMQTT(mqttSUBSCRIBE, 0x02, body)
}

func mqttPublishQoS1(id uint16, topic string, payload []byte) []byte {
	tLen := make([]byte, 2)
	binary.BigEndian.PutUint16(tLen, uint16(len(topic)))
	body := append(tLen, []byte(topic)...)
	idBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(idBytes, id)
	body = append(body, idBytes...)
	body = append(body, payload...)
	return encodeMQTT(mqttPUBLISH, 0x02, body) // QoS 1
}

func mqttPublishLargeQoS0(topic string, payload []byte) []byte {
	tLen := make([]byte, 2)
	binary.BigEndian.PutUint16(tLen, uint16(len(topic)))
	body := append(tLen, []byte(topic)...)
	body = append(body, payload...)
	return encodeMQTT(mqttPUBLISH, 0, body)
}

func readMQTTPacket(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	first := make([]byte, 1)
	_, err := io.ReadFull(conn, first)
	require.NoError(t, err)
	remaining, lenBytes, err := readRemainingLength(conn)
	require.NoError(t, err)
	body := make([]byte, remaining)
	if remaining > 0 {
		_, err = io.ReadFull(conn, body)
		require.NoError(t, err)
	}
	out := append(first, lenBytes...)
	return append(out, body...)
}

func TestHandleMQTTConnectPing(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMQTT(context.Background(), serverConn, connection.Metadata{TargetPort: 1883}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(mqttConnectPacket("sensor-1", "user"))
	require.NoError(t, err)
	connack := readMQTTPacket(t, client)
	require.Equal(t, byte(mqttCONNACK<<4), connack[0])
	require.Equal(t, []byte{0x20, 0x02, 0x00, 0x00}, connack)

	_, err = client.Write(mqttPingreq())
	require.NoError(t, err)
	pingresp := readMQTTPacket(t, client)
	require.Equal(t, []byte{0xd0, 0x00}, pingresp)

	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	select {
	case ev := <-hp.produced:
		require.Equal(t, "mqtt", ev.protocol)
		events, ok := ev.decoded.([]parsedMQTT)
		require.True(t, ok)
		require.GreaterOrEqual(t, len(events), 4)
		require.Equal(t, "CONNECT", events[0].Packet)
		require.Equal(t, "CONNECT", events[0].Command)
		require.Equal(t, "sensor-1", events[0].ClientID)
		require.Equal(t, "user", events[0].Username)
		require.Equal(t, "CONNACK", events[1].Packet)
		require.Equal(t, "PINGREQ", events[2].Packet)
		require.Equal(t, "PINGRESP", events[3].Packet)
		var writes int
		for _, e := range events {
			if e.Direction == "write" {
				writes++
			}
		}
		require.Equal(t, 2, writes)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced MQTT event")
	}
}

func TestHandleMQTTSubscribeAndQoS1Publish(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMQTT(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(mqttConnectPacket("c1", ""))
	require.NoError(t, err)
	_ = readMQTTPacket(t, client)

	_, err = client.Write(mqttSubscribePacket(7, "sensors/temp", 1))
	require.NoError(t, err)
	suback := readMQTTPacket(t, client)
	require.Equal(t, byte(mqttSUBACK<<4), suback[0])
	require.Equal(t, uint16(7), binary.BigEndian.Uint16(suback[2:4]))
	require.Equal(t, byte(1), suback[4])

	_, err = client.Write(mqttPublishQoS1(9, "sensors/temp", []byte("22")))
	require.NoError(t, err)
	puback := readMQTTPacket(t, client)
	require.Equal(t, byte(mqttPUBACK<<4), puback[0])
	require.Equal(t, uint16(9), binary.BigEndian.Uint16(puback[2:4]))

	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	ev := <-hp.produced
	require.Equal(t, "mqtt", ev.protocol)
	events := ev.decoded.([]parsedMQTT)
	var sawSub, sawPub bool
	for _, e := range events {
		if e.Packet == "SUBSCRIBE" {
			sawSub = true
			require.Equal(t, []string{"sensors/temp"}, e.Topics)
		}
		if e.Packet == "PUBLISH" && e.Direction == "read" {
			sawPub = true
			require.Equal(t, "sensors/temp", e.Topic)
			require.Equal(t, uint8(1), e.QoS)
		}
	}
	require.True(t, sawSub)
	require.True(t, sawPub)
}

func TestHandleMQTTEarlyCloseProduces(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMQTT(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	select {
	case ev := <-hp.produced:
		require.Equal(t, "mqtt", ev.protocol)
		events, ok := ev.decoded.([]parsedMQTT)
		require.True(t, ok)
		require.Empty(t, events)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced MQTT event")
	}
}

func TestHandleMQTTMultiByteRemainingLength(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleMQTT(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(mqttConnectPacket("c1", ""))
	require.NoError(t, err)
	_ = readMQTTPacket(t, client)

	payload := make([]byte, 130)
	for i := range payload {
		payload[i] = 0x61
	}
	pub := mqttPublishLargeQoS0("a", payload)
	require.Greater(t, len(pub), 130)
	require.Equal(t, byte(0x80), pub[1]&0x80) // remaining length uses more than one byte

	_, err = client.Write(pub)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	ev := <-hp.produced
	events := ev.decoded.([]parsedMQTT)
	var saw bool
	for _, e := range events {
		if e.Packet == "PUBLISH" && e.Direction == "read" {
			saw = true
			require.Equal(t, "a", e.Topic)
			require.Equal(t, uint8(0), e.QoS)
		}
	}
	require.True(t, saw)
}

func TestEncodeRemainingLength(t *testing.T) {
	require.Equal(t, []byte{0x00}, encodeRemainingLength(0))
	require.Equal(t, []byte{0x7f}, encodeRemainingLength(127))
	require.Equal(t, []byte{0x80, 0x01}, encodeRemainingLength(128))
}
