package opcua

import (
	"encoding/hex"
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
	require.Equal(t, "secret-password", f.Password)
}

func TestParseBrowseNamed(t *testing.T) {
	payload := encodeTestMSG(t, id.BrowseRequest_Encoding_DefaultBinary, &ua.BrowseRequest{
		RequestHeader: &ua.RequestHeader{
			AuthenticationToken: ua.NewTwoByteNodeID(0),
			Timestamp:           time.Now().UTC(),
			RequestHandle:       4,
			AdditionalHeader:    ua.NewExtensionObject(nil),
		},
		View:          &ua.ViewDescription{ViewID: ua.NewTwoByteNodeID(0)},
		NodesToBrowse: []*ua.BrowseDescription{{NodeID: ua.NewNumericNodeID(0, nodeObjectsFolder), BrowseDirection: ua.BrowseDirectionForward, ReferenceTypeID: ua.NewNumericNodeID(0, nodeOrganizes), IncludeSubtypes: true}},
	})
	require.Equal(t, "Browse", Parse(payload).Service)

	s := NewSession("opc.tcp://1.2.3.4:4840")
	reply, err := s.Reply(payload)
	require.NoError(t, err)
	require.Equal(t, "Browse", Parse(reply).Service)

	m := new(uasc.Message)
	_, err = m.Decode(reply)
	require.NoError(t, err)
	resp, ok := m.Service.(*ua.BrowseResponse)
	require.True(t, ok)
	require.Len(t, resp.Results, 1)
	require.Equal(t, ua.StatusGood, resp.Results[0].StatusCode)
	require.Len(t, resp.Results[0].References, 2)
	require.Equal(t, uint32(4), resp.ResponseHeader.RequestHandle)
}

func TestBrowseUnknownNode(t *testing.T) {
	r := browseNode(&ua.BrowseDescription{NodeID: ua.NewNumericNodeID(0, 9999)})
	require.Equal(t, ua.StatusBadNodeIDUnknown, r.StatusCode)
	require.Empty(t, r.References)
}

func TestBrowseCapturedWire(t *testing.T) {
	// BrowseRequest (TypeId 527) from Ochi event 7b5c582d-5b3d-4df1-8c5d-c625fe3cf054.
	payload, err := hex.DecodeString("4d5347466a0000000100000001000000040000000400000001000f020201000200000006a3f715d16bdd010400000000000000ffffffffe8030000000000000000000000000000000000000000000000010000000200005400000000000000002101000000003f000000")
	require.NoError(t, err)
	require.Equal(t, "Browse", Parse(payload).Service)
	reply, err := NewSession("opc.tcp://1.2.3.4:4840").Reply(payload)
	require.NoError(t, err)
	require.Equal(t, "Browse", Parse(reply).Service)
}

func TestSessionNoncePerSession(t *testing.T) {
	a, b := NewSession(""), NewSession("")
	require.Len(t, a.nonce, 32)
	require.NotEqual(t, a.nonce, b.nonce)
}
