package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/nvms9000"
	"github.com/stretchr/testify/require"
)

// The request mirrors the capture on tcp/8888 (Ochi event
// 8c21d002-4069-4f48-a464-ac3eb5742229); replies are synthetic.

const nvmsXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"/>\n"

var nvmsTestIdentity = nvms9000.Identity{Name: "NVR", Model: "M1", Firmware: "1.0", Serial: "SER1", MAC: "00:11:22:33:44:55"}

func nvmsPad(s string) []byte {
	return append([]byte(s), make([]byte, 64-len(s))...)
}

func nvmsRequest(user, op, xml string) []byte {
	body := append(nvmsPad(user), nvmsPad(op)...)
	body = append(body, xml...)
	return nvms9000.Build(nvms9000.Header{Version: 0x01000004, Command: 0x091b, Unknown: 0x0102}, body)
}

func runNVMS(t *testing.T, client func(c net.Conn)) producedTCP {
	t.Helper()
	prev := nvmsIdentity
	nvmsIdentity = func() nvms9000.Identity { return nvmsTestIdentity }
	t.Cleanup(func() { nvmsIdentity = prev })

	pipe, cli := net.Pipe()
	h := newFakeHoneypot()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = HandleNVMS9000(context.Background(), pipe, connection.Metadata{TargetPort: 6036}, &recordingLogger{}, h)
	}()
	require.NoError(t, cli.SetDeadline(time.Now().Add(2*time.Second)))
	client(cli)
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
	require.Len(t, h.produced, 1)
	ev := <-h.produced
	require.Equal(t, "nvms9000", ev.protocol)
	return ev
}

func TestNVMS9000QueryBasicCfg(t *testing.T) {
	req := nvmsRequest("admin", "queryBasicCfg", nvmsXML)
	require.Len(t, req, 256)
	var reply []byte
	ev := runNVMS(t, func(c net.Conn) {
		_, err := c.Write(req)
		require.NoError(t, err)
		frame, raw, err := nvms9000.ReadFrame(c)
		require.NoError(t, err)
		reply = raw
		require.Equal(t, uint32(0x091b), frame.Header.Command)
		require.Equal(t, nvms9000.BasicCfgXML(nvmsTestIdentity), string(frame.Body))
	})

	require.Equal(t, req, ev.payload)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedNVMS{
		{Direction: "read", Command: "queryBasicCfg", CommandID: 0x091b, Username: "admin", Payload: req},
		{Direction: "write", Command: "queryBasicCfg", CommandID: 0x091b, Status: "success", Payload: reply},
	}, ev.decoded)
}

func TestNVMS9000LoginRecordsCredentialsAndFails(t *testing.T) {
	xml := `<?xml version="1.0"?><request version="1.0" systemType="NVMS-9000" clientType="WEB"><content><userName><![CDATA[root]]></userName><password><![CDATA[xc3511]]></password></content></request>`
	req := nvmsRequest("", "doLogin", xml)
	ev := runNVMS(t, func(c net.Conn) {
		_, err := c.Write(req)
		require.NoError(t, err)
		frame, _, err := nvms9000.ReadFrame(c)
		require.NoError(t, err)
		require.Contains(t, string(frame.Body), `status="fail"`)
	})
	frames := ev.decoded.([]parsedNVMS)
	require.Len(t, frames, 2)
	require.Equal(t, "doLogin", frames[0].Command)
	require.Equal(t, "root", frames[0].Username)
	require.Equal(t, "xc3511", frames[0].Password)
	require.Equal(t, "fail", frames[1].Status)
}

func TestNVMS9000MultipleRequestsOneEvent(t *testing.T) {
	ev := runNVMS(t, func(c net.Conn) {
		for _, op := range []string{"queryBasicCfg", "queryDevInfo"} {
			_, err := c.Write(nvmsRequest("admin", op, nvmsXML))
			require.NoError(t, err)
			_, _, err = nvms9000.ReadFrame(c)
			require.NoError(t, err)
		}
	})
	frames := ev.decoded.([]parsedNVMS)
	require.Len(t, frames, 4)
	require.Equal(t, "success", frames[1].Status)
	require.Equal(t, "fail", frames[3].Status)
}

func TestNVMS9000BadMagicEndsSession(t *testing.T) {
	ev := runNVMS(t, func(c net.Conn) {
		// the handler reads one 8-byte prefix, then closes
		_, err := c.Write([]byte("GET / HT"))
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndReadError, ev.endReason)
	require.Equal(t, []parsedNVMS{{Direction: "read", Payload: []byte("GET / HT")}}, ev.decoded)
}

func TestNVMS9000OversizeFrame(t *testing.T) {
	ev := runNVMS(t, func(c net.Conn) {
		_, err := c.Write([]byte("1111\xff\xff\xff\x00"))
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndReadError, ev.endReason)
	require.Equal(t, []parsedNVMS{{Direction: "read", Payload: []byte("1111\xff\xff\xff\x00"), Truncated: true}}, ev.decoded)
}

func TestNVMS9000EarlyDisconnect(t *testing.T) {
	req := nvmsRequest("admin", "queryBasicCfg", nvmsXML)
	ev := runNVMS(t, func(c net.Conn) {
		_, err := c.Write(req[:100])
		require.NoError(t, err)
	})
	frames := ev.decoded.([]parsedNVMS)
	require.Len(t, frames, 1)
	require.Equal(t, req[:100], frames[0].Payload)
	require.Equal(t, connection.EndClientClose, ev.endReason)
}

func TestNVMS9000NoDataStillProduces(t *testing.T) {
	ev := runNVMS(t, func(net.Conn) {})
	require.Empty(t, ev.decoded)
	require.Empty(t, ev.payload)
}
