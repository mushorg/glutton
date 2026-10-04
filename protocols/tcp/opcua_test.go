package tcp

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/opcua"
	"github.com/stretchr/testify/require"
)

func waitOpcuaEvent(t *testing.T, hp *fakeHoneypot) producedTCP {
	t.Helper()
	select {
	case ev := <-hp.produced:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced OPC UA event")
		return producedTCP{}
	}
}

func startOPCUA(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleOPCUA(context.Background(), serverConn, connection.Metadata{TargetPort: 4840}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func readOpcua(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	msg, err := opcua.ReadMessage(conn)
	require.NoError(t, err)
	return msg
}

func requestHeader() *ua.RequestHeader {
	return &ua.RequestHeader{
		AuthenticationToken: ua.NewTwoByteNodeID(0),
		Timestamp:           time.Now().UTC(),
		RequestHandle:       1,
		AdditionalHeader:    ua.NewExtensionObject(nil),
	}
}

func encodeOPN(t *testing.T, policy string, mode ua.MessageSecurityMode) []byte {
	t.Helper()
	m := &uasc.Message{
		MessageHeader: &uasc.MessageHeader{
			Header: &uasc.Header{MessageType: "OPN", ChunkType: uasc.ChunkTypeFinal},
			AsymmetricSecurityHeader: &uasc.AsymmetricSecurityHeader{
				SecurityPolicyURI: policy,
			},
			SequenceHeader: &uasc.SequenceHeader{SequenceNumber: 1, RequestID: 1},
		},
		TypeID: ua.NewFourByteExpandedNodeID(0, id.OpenSecureChannelRequest_Encoding_DefaultBinary),
		Service: &ua.OpenSecureChannelRequest{
			RequestHeader:     requestHeader(),
			RequestType:       ua.SecurityTokenRequestTypeIssue,
			SecurityMode:      mode,
			RequestedLifetime: 600000,
		},
	}
	b, err := m.Encode()
	require.NoError(t, err)
	return b
}

func encodeMSG(t *testing.T, typeID uint16, svc interface{}, reqID uint32) []byte {
	t.Helper()
	m := &uasc.Message{
		MessageHeader: &uasc.MessageHeader{
			Header:                  &uasc.Header{MessageType: "MSG", ChunkType: uasc.ChunkTypeFinal, SecureChannelID: 1},
			SymmetricSecurityHeader: &uasc.SymmetricSecurityHeader{TokenID: 1},
			SequenceHeader:          &uasc.SequenceHeader{SequenceNumber: reqID, RequestID: reqID},
		},
		TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
		Service: svc,
	}
	b, err := m.Encode()
	require.NoError(t, err)
	return b
}

func TestHandleOPCUAHelloACK(t *testing.T) {
	client, hp, done := startOPCUA(t)

	hel, err := opcua.EncodeHello("opc.tcp://203.0.113.10:4840")
	require.NoError(t, err)
	_, err = client.Write(hel)
	require.NoError(t, err)

	ack := readOpcua(t, client)
	frame := opcua.Parse(ack)
	require.Equal(t, "ACK", frame.MessageType)
	require.Equal(t, "Acknowledge", frame.Service)

	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitOpcuaEvent(t, hp)
	require.Equal(t, "opcua", ev.protocol)
	frames, ok := ev.decoded.([]parsedOPCUA)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(frames), 2)
	require.Equal(t, "read", frames[0].Direction)
	require.Equal(t, "HEL", frames[0].MessageType)
	require.Equal(t, "opc.tcp://203.0.113.10:4840", frames[0].EndpointURL)
	require.Equal(t, "write", frames[1].Direction)
	require.Equal(t, "ACK", frames[1].MessageType)
}

func TestHandleOPCUAGetEndpoints(t *testing.T) {
	client, hp, done := startOPCUA(t)

	hel, err := opcua.EncodeHello("opc.tcp://1.2.3.4:4840")
	require.NoError(t, err)
	_, err = client.Write(hel)
	require.NoError(t, err)
	_ = readOpcua(t, client)

	_, err = client.Write(encodeOPN(t, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone))
	require.NoError(t, err)
	opn := opcua.Parse(readOpcua(t, client))
	require.Equal(t, "OPN", opn.MessageType)
	require.Equal(t, "OpenSecureChannel", opn.Service)
	require.Equal(t, ua.SecurityPolicyURINone, opn.SecurityPolicy)

	get := encodeMSG(t, id.GetEndpointsRequest_Encoding_DefaultBinary, &ua.GetEndpointsRequest{
		RequestHeader: requestHeader(),
		EndpointURL:   "opc.tcp://1.2.3.4:4840",
	}, 2)
	_, err = client.Write(get)
	require.NoError(t, err)
	respBytes := readOpcua(t, client)
	resp := new(uasc.Message)
	_, err = resp.Decode(respBytes)
	require.NoError(t, err)
	gep, ok := resp.Service.(*ua.GetEndpointsResponse)
	require.True(t, ok)
	require.NotEmpty(t, gep.Endpoints)
	require.Equal(t, ua.SecurityPolicyURINone, gep.Endpoints[0].SecurityPolicyURI)
	require.Equal(t, ua.MessageSecurityModeNone, gep.Endpoints[0].SecurityMode)

	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitOpcuaEvent(t, hp)
	require.Equal(t, "opcua", ev.protocol)
	frames := ev.decoded.([]parsedOPCUA)
	var sawGet bool
	for _, f := range frames {
		if f.Direction == "write" && f.Service == "GetEndpoints" {
			sawGet = true
		}
	}
	require.True(t, sawGet)
}

func TestHandleOPCUAReverseHelloNoDial(t *testing.T) {
	client, hp, done := startOPCUA(t)

	rhe, err := opcua.EncodeReverseHello("opc.tcp://203.0.113.99:1", "opc.tcp://1.2.3.4:4840")
	require.NoError(t, err)
	_, err = client.Write(rhe)
	require.NoError(t, err)
	errf := opcua.Parse(readOpcua(t, client))
	require.Equal(t, "ERR", errf.MessageType)

	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitOpcuaEvent(t, hp)
	require.Equal(t, "opcua", ev.protocol)
	frames := ev.decoded.([]parsedOPCUA)
	require.Equal(t, "read", frames[0].Direction)
	require.Equal(t, "RHE", frames[0].MessageType)
}

func TestHandleOPCUAEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done := startOPCUA(t)
	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitOpcuaEvent(t, hp)
	require.Equal(t, "opcua", ev.protocol)
	frames, ok := ev.decoded.([]parsedOPCUA)
	require.True(t, ok)
	require.Empty(t, frames)
}

func TestHandleOPCUAOversizeDoesNotUnboundedRead(t *testing.T) {
	client, hp, done := startOPCUA(t)
	hdr := make([]byte, 8)
	copy(hdr, []byte("HELF"))
	binary.LittleEndian.PutUint32(hdr[4:8], opcua.MaxMessageSize+1)
	_, err := client.Write(hdr)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitOpcuaEvent(t, hp)
	require.Equal(t, "opcua", ev.protocol)
}

func TestHandleOPCUAActivateSessionOmitsPassword(t *testing.T) {
	client, hp, done := startOPCUA(t)

	hel, err := opcua.EncodeHello("opc.tcp://1.2.3.4:4840")
	require.NoError(t, err)
	_, err = client.Write(hel)
	require.NoError(t, err)
	_ = readOpcua(t, client)
	_, err = client.Write(encodeOPN(t, ua.SecurityPolicyURINone, ua.MessageSecurityModeNone))
	require.NoError(t, err)
	_ = readOpcua(t, client)

	create := encodeMSG(t, id.CreateSessionRequest_Encoding_DefaultBinary, &ua.CreateSessionRequest{
		RequestHeader: requestHeader(),
		ClientDescription: &ua.ApplicationDescription{
			ApplicationURI:  "urn:scanner",
			ApplicationName: ua.NewLocalizedText("nmap"),
			ApplicationType: ua.ApplicationTypeClient,
		},
		EndpointURL: "opc.tcp://1.2.3.4:4840",
	}, 2)
	_, err = client.Write(create)
	require.NoError(t, err)
	_ = readOpcua(t, client)

	activate := encodeMSG(t, id.ActivateSessionRequest_Encoding_DefaultBinary, &ua.ActivateSessionRequest{
		RequestHeader:      requestHeader(),
		ClientSignature:    &ua.SignatureData{},
		UserTokenSignature: &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
			PolicyID: "username",
			UserName: "admin",
			Password: []byte("secret-password"),
		}),
	}, 3)
	_, err = client.Write(activate)
	require.NoError(t, err)
	_ = readOpcua(t, client)

	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitOpcuaEvent(t, hp)
	frames := ev.decoded.([]parsedOPCUA)
	var sawUser bool
	for _, f := range frames {
		if f.Direction == "read" && f.Service == "ActivateSession" {
			require.Equal(t, "admin", f.Username)
			sawUser = true
		}
		if f.Service == "CreateSession" && f.Direction == "read" {
			require.Equal(t, "urn:scanner", f.ApplicationURI)
			require.Equal(t, "nmap", f.ApplicationName)
		}
	}
	require.True(t, sawUser)
}

func TestHandleOPCUATruncatedHeaderProduces(t *testing.T) {
	client, hp, done := startOPCUA(t)
	_, err := client.Write([]byte{'H', 'E'})
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NoError(t, <-done)
	ev := waitOpcuaEvent(t, hp)
	require.Equal(t, "opcua", ev.protocol)
}
