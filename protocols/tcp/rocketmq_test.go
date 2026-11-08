package tcp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/rocketmq"
	"github.com/stretchr/testify/require"
)

// Captured probe on tcp/10911 and tcp/13911 (run-1794154414-1.jsonl events 3 and 5).
var rocketMQCapturedRuntimeInfo = append([]byte{0, 0, 0, 0x64, 0, 0, 0, 0x60},
	`{"code":28,"flag":0,"language":"JAVA","opaque":0,"serializeTypeCurrentRPC":"JSON","version":433}`...)

func startRocketMQ(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	orig := newRocketMQBroker
	newRocketMQBroker = func() *rocketmq.Broker {
		b := rocketmq.NewBroker()
		now := time.Date(2026, 11, 8, 16, 0, 0, 0, time.UTC)
		b.Now = func() time.Time { return now }
		return b
	}
	t.Cleanup(func() { newRocketMQBroker = orig })
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRocketMQ(context.Background(), serverConn, connection.Metadata{TargetPort: 10911}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitRocketMQEvent(t *testing.T, hp *fakeHoneypot, done chan error) ([]parsedRocketMQ, producedTCP) {
	t.Helper()
	require.NoError(t, <-done)
	select {
	case ev := <-hp.produced:
		require.Equal(t, "rocketmq", ev.protocol)
		frames, ok := ev.decoded.([]parsedRocketMQ)
		require.True(t, ok)
		if len(frames) > 0 {
			require.Equal(t, frames[0].Payload, ev.payload)
		}
		select {
		case <-hp.produced:
			t.Fatal("expected exactly one produced event")
		default:
		}
		return frames, ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced RocketMQ event")
		return nil, producedTCP{}
	}
}

func readRocketMQReply(t *testing.T, c net.Conn) rocketmq.Frame {
	t.Helper()
	f, err := rocketmq.ReadFrame(c)
	require.NoError(t, err)
	return f
}

func TestHandleRocketMQCapturedRuntimeInfo(t *testing.T) {
	client, hp, done := startRocketMQ(t)
	_, err := client.Write(rocketMQCapturedRuntimeInfo)
	require.NoError(t, err)
	reply := readRocketMQReply(t, client)
	require.Equal(t, rocketmq.CodeSuccess, reply.Header.Code)
	require.Equal(t, rocketmq.FlagResponse, reply.Header.Flag)
	require.Contains(t, string(reply.Body), `"brokerVersionDesc":"V4_9_4"`)
	require.NoError(t, client.Close())

	frames, ev := waitRocketMQEvent(t, hp, done)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedRocketMQ{
		{Direction: "read", Command: "GET_BROKER_RUNTIME_INFO", Code: 28, Language: "JAVA", Version: 433, Payload: rocketMQCapturedRuntimeInfo},
		{Direction: "write", Command: "GET_BROKER_RUNTIME_INFO", Code: 0, Flag: 1, Status: "SUCCESS", Payload: reply.Raw},
	}, frames)
}

func TestHandleRocketMQUpdateConfigAndUnsupported(t *testing.T) {
	client, hp, done := startRocketMQ(t)
	update := rocketmq.Encode(rocketmq.Header{Code: 25, Language: "JAVA", Opaque: 3, SerializeTypeCurrentRPC: "JSON", Version: 433},
		[]byte("filterServerNums=1\nrocketmqHome=-c id\n"))
	_, err := client.Write(update)
	require.NoError(t, err)
	r1 := readRocketMQReply(t, client)
	require.Equal(t, int32(3), r1.Header.Opaque)
	require.Equal(t, rocketmq.CodeSuccess, r1.Header.Code)

	other := rocketmq.Encode(rocketmq.Header{Code: 4242, Language: "JAVA", Opaque: 4, SerializeTypeCurrentRPC: "JSON", Version: 433}, nil)
	_, err = client.Write(other)
	require.NoError(t, err)
	r2 := readRocketMQReply(t, client)
	require.Equal(t, rocketmq.CodeNotSupported, r2.Header.Code)
	require.Equal(t, int32(4), r2.Header.Opaque)
	require.NoError(t, client.Close())

	frames, _ := waitRocketMQEvent(t, hp, done)
	require.Len(t, frames, 4)
	require.Equal(t, "UPDATE_BROKER_CONFIG", frames[0].Command)
	require.Equal(t, map[string]string{"filterServerNums": "1", "rocketmqHome": "-c id"}, frames[0].Config)
	require.Equal(t, update, frames[0].Payload)
	require.Equal(t, "SUCCESS", frames[1].Status)
	require.Equal(t, "CODE_4242", frames[2].Command)
	require.Equal(t, "REQUEST_CODE_NOT_SUPPORTED", frames[3].Status)
	require.Equal(t, int32(4), frames[3].Opaque)
}

func TestHandleRocketMQOversize(t *testing.T) {
	client, hp, done := startRocketMQ(t)
	hdr := []byte{0x7f, 0xff, 0xff, 0xff}
	_, err := client.Write(hdr)
	require.NoError(t, err)
	_, err = io.ReadAll(client)
	require.NoError(t, err)

	frames, ev := waitRocketMQEvent(t, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, []parsedRocketMQ{{Direction: "read", Payload: hdr, Truncated: true}}, frames)
}

func TestHandleRocketMQEarlyDisconnect(t *testing.T) {
	client, hp, done := startRocketMQ(t)
	_, err := client.Write(rocketMQCapturedRuntimeInfo[:20])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	frames, _ := waitRocketMQEvent(t, hp, done)
	require.Equal(t, []parsedRocketMQ{{Direction: "read", Payload: rocketMQCapturedRuntimeInfo[:20], Truncated: true}}, frames)
}
