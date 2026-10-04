package opcua

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
	"github.com/stretchr/testify/require"
)

func encodeTestMSG(t *testing.T, typeID uint16, svc interface{}) []byte {
	t.Helper()
	m := &uasc.Message{
		MessageHeader: &uasc.MessageHeader{
			Header:                  &uasc.Header{MessageType: "MSG", ChunkType: uasc.ChunkTypeFinal, SecureChannelID: 1},
			SymmetricSecurityHeader: &uasc.SymmetricSecurityHeader{TokenID: 1},
			SequenceHeader:          &uasc.SequenceHeader{SequenceNumber: 2, RequestID: 2},
		},
		TypeID:  ua.NewFourByteExpandedNodeID(0, typeID),
		Service: svc,
	}
	b, err := m.Encode()
	require.NoError(t, err)
	return b
}

func TestSessionActivateSession(t *testing.T) {
	s := NewSession("opc.tcp://1.2.3.4:4840")
	hel, err := EncodeHello("opc.tcp://1.2.3.4:4840")
	require.NoError(t, err)
	_, err = s.Reply(hel)
	require.NoError(t, err)

	opn := &uasc.Message{
		MessageHeader: &uasc.MessageHeader{
			Header: &uasc.Header{MessageType: "OPN", ChunkType: uasc.ChunkTypeFinal},
			AsymmetricSecurityHeader: &uasc.AsymmetricSecurityHeader{
				SecurityPolicyURI: ua.SecurityPolicyURINone,
			},
			SequenceHeader: &uasc.SequenceHeader{SequenceNumber: 1, RequestID: 1},
		},
		TypeID: ua.NewFourByteExpandedNodeID(0, id.OpenSecureChannelRequest_Encoding_DefaultBinary),
		Service: &ua.OpenSecureChannelRequest{
			RequestHeader: &ua.RequestHeader{
				AuthenticationToken: ua.NewTwoByteNodeID(0),
				Timestamp:           time.Now().UTC(),
				RequestHandle:       1,
				AdditionalHeader:    ua.NewExtensionObject(nil),
			},
			RequestType:       ua.SecurityTokenRequestTypeIssue,
			SecurityMode:      ua.MessageSecurityModeNone,
			RequestedLifetime: 600000,
		},
	}
	opnBytes, err := opn.Encode()
	require.NoError(t, err)
	_, err = s.Reply(opnBytes)
	require.NoError(t, err)

	create := encodeTestMSG(t, id.CreateSessionRequest_Encoding_DefaultBinary, &ua.CreateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			AuthenticationToken: ua.NewTwoByteNodeID(0),
			Timestamp:           time.Now().UTC(),
			RequestHandle:       1,
			AdditionalHeader:    ua.NewExtensionObject(nil),
		},
		ClientDescription: &ua.ApplicationDescription{
			ApplicationURI:  "urn:scanner",
			ApplicationName: ua.NewLocalizedText("nmap"),
			ApplicationType: ua.ApplicationTypeClient,
		},
		EndpointURL: "opc.tcp://1.2.3.4:4840",
	})
	createReply, err := s.Reply(create)
	require.NoError(t, err)
	require.NotEmpty(t, createReply)
	require.Equal(t, "CreateSession", Parse(createReply).Service)

	activate := encodeTestMSG(t, id.ActivateSessionRequest_Encoding_DefaultBinary, &ua.ActivateSessionRequest{
		RequestHeader: &ua.RequestHeader{
			AuthenticationToken: ua.NewTwoByteNodeID(0),
			Timestamp:           time.Now().UTC(),
			RequestHandle:       1,
			AdditionalHeader:    ua.NewExtensionObject(nil),
		},
		ClientSignature:    &ua.SignatureData{},
		UserTokenSignature: &ua.SignatureData{},
		UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
			PolicyID: "username",
			UserName: "admin",
			Password: []byte("secret-password"),
		}),
	})
	f := Parse(activate)
	actReply, err := s.Reply(activate)
	require.NoError(t, err)
	require.NotEmpty(t, actReply, "expected ActivateSession response")
	require.Equal(t, "ActivateSession", Parse(actReply).Service)
	require.Equal(t, "admin", f.Username)
}
