package opcua

import (
	"crypto/rand"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

const (
	fakeChannelID = 1
	fakeTokenID   = 1
)

const (
	nodeObjectsFolder = 85
	nodeServer        = 2253
	nodeOrganizes     = 35
	nodeFolderType    = 61
	nodeServerType    = 2004
)

// randRead fills the server nonce; tests swap it for determinism.
var randRead = rand.Read

func newNonce() []byte {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		for i := range b {
			b[i] = byte(i + 1)
		}
	}
	return b
}

// Session holds per-connection secure-channel state for None-security replies.
type Session struct {
	endpointURL string
	channelID   uint32
	tokenID     uint32
	sequence    uint32
	nonce       []byte
}

func NewSession(endpointURL string) *Session {
	if endpointURL == "" {
		endpointURL = "opc.tcp://1.2.3.4:4840"
	}
	return &Session{
		endpointURL: endpointURL,
		channelID:   fakeChannelID,
		tokenID:     fakeTokenID,
		nonce:       newNonce(),
	}
}

func (s *Session) nextSequence() uint32 {
	s.sequence++
	return s.sequence
}

// Reply builds a honeypot response for a full UACP payload. A nil reply means
// the frame was stored but not answered (unknown type, intermediate chunk).
func (s *Session) Reply(payload []byte) ([]byte, error) {
	if len(payload) < HeaderLen {
		return nil, nil
	}
	var h uacp.Header
	if _, err := h.Decode(payload[:HeaderLen]); err != nil {
		return nil, nil
	}
	if h.ChunkType != uacp.ChunkTypeFinal {
		return nil, nil
	}

	switch h.MessageType {
	case uacp.MessageTypeHello:
		return encodeACK()
	case uacp.MessageTypeReverseHello:
		return encodeERR(ua.StatusBadTCPInternalError)
	case uasc.MessageTypeOpenSecureChannel:
		return s.replyOpen(payload)
	case uasc.MessageTypeCloseSecureChannel:
		return s.replyService(payload, uasc.MessageTypeCloseSecureChannel, id.CloseSecureChannelResponse_Encoding_DefaultBinary, &ua.CloseSecureChannelResponse{})
	case uasc.MessageTypeMessage:
		return s.replyMSG(payload)
	default:
		return nil, nil
	}
}

func (s *Session) replyOpen(payload []byte) ([]byte, error) {
	m := new(uasc.Message)
	if _, err := m.Decode(payload); err != nil {
		return encodeERR(ua.StatusBadTCPInternalError)
	}
	if m.AsymmetricSecurityHeader == nil || m.AsymmetricSecurityHeader.SecurityPolicyURI != ua.SecurityPolicyURINone {
		return encodeERR(ua.StatusBadSecurityPolicyRejected)
	}
	req, ok := m.Service.(*ua.OpenSecureChannelRequest)
	if !ok || req == nil {
		return encodeERR(ua.StatusBadTCPInternalError)
	}
	if req.SecurityMode != ua.MessageSecurityModeInvalid && req.SecurityMode != ua.MessageSecurityModeNone {
		return encodeERR(ua.StatusBadSecurityPolicyRejected)
	}

	s.channelID = fakeChannelID
	s.tokenID = fakeTokenID
	lifetime := req.RequestedLifetime
	if lifetime == 0 {
		lifetime = 600000
	}
	resp := &ua.OpenSecureChannelResponse{
		ResponseHeader:        responseHeader(req),
		ServerProtocolVersion: 0,
		SecurityToken: &ua.ChannelSecurityToken{
			ChannelID:       s.channelID,
			TokenID:         s.tokenID,
			CreatedAt:       time.Now().UTC(),
			RevisedLifetime: lifetime,
		},
	}
	return s.encodeUASC(uasc.MessageTypeOpenSecureChannel, requestID(m), id.OpenSecureChannelResponse_Encoding_DefaultBinary, resp)
}

func (s *Session) replyMSG(payload []byte) ([]byte, error) {
	m := new(uasc.Message)
	if _, err := m.Decode(payload); err != nil {
		if m.SequenceHeader != nil {
			return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.ServiceFault_Encoding_DefaultBinary, &ua.ServiceFault{
				ResponseHeader: responseHeaderFromAny(m.Service, ua.StatusBadServiceUnsupported),
			})
		}
		return nil, nil
	}
	if m.Header != nil && m.Header.SecureChannelID != 0 {
		s.channelID = m.Header.SecureChannelID
	}
	if m.SymmetricSecurityHeader != nil && m.SymmetricSecurityHeader.TokenID != 0 {
		s.tokenID = m.SymmetricSecurityHeader.TokenID
	}

	switch req := m.Service.(type) {
	case *ua.GetEndpointsRequest:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.GetEndpointsResponse_Encoding_DefaultBinary, &ua.GetEndpointsResponse{
			ResponseHeader: responseHeader(req),
			Endpoints:      []*ua.EndpointDescription{s.endpoint()},
		})
	case *ua.FindServersRequest:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.FindServersResponse_Encoding_DefaultBinary, &ua.FindServersResponse{
			ResponseHeader: responseHeader(req),
			Servers:        []*ua.ApplicationDescription{s.application()},
		})
	case *ua.CreateSessionRequest:
		timeout := req.RequestedSessionTimeout
		if timeout == 0 {
			timeout = 60000
		}
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.CreateSessionResponse_Encoding_DefaultBinary, &ua.CreateSessionResponse{
			ResponseHeader:        responseHeader(req),
			SessionID:             ua.NewNumericNodeID(1, 1),
			AuthenticationToken:   ua.NewNumericNodeID(1, 2),
			RevisedSessionTimeout: timeout,
			ServerNonce:           s.nonce,
			ServerEndpoints:       []*ua.EndpointDescription{s.endpoint()},
			ServerSignature:       &ua.SignatureData{},
			MaxRequestMessageSize: MaxMessageSize,
		})
	case *ua.ActivateSessionRequest:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.ActivateSessionResponse_Encoding_DefaultBinary, &ua.ActivateSessionResponse{
			ResponseHeader: responseHeader(req),
			ServerNonce:    s.nonce,
		})
	case *ua.CloseSessionRequest:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.CloseSessionResponse_Encoding_DefaultBinary, &ua.CloseSessionResponse{
			ResponseHeader: responseHeader(req),
		})
	case *ua.BrowseRequest:
		results := make([]*ua.BrowseResult, 0, len(req.NodesToBrowse))
		for _, n := range req.NodesToBrowse {
			results = append(results, browseNode(n))
		}
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.BrowseResponse_Encoding_DefaultBinary, &ua.BrowseResponse{
			ResponseHeader: responseHeader(req),
			Results:        results,
		})
	default:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.ServiceFault_Encoding_DefaultBinary, &ua.ServiceFault{
			ResponseHeader: responseHeaderFromAny(m.Service, ua.StatusBadServiceUnsupported),
		})
	}
}

func ref(idn uint32, name string, class ua.NodeClass, typeDef uint32) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, nodeOrganizes),
		IsForward:       true,
		NodeID:          ua.NewExpandedNodeID(ua.NewNumericNodeID(0, idn), "", 0),
		BrowseName:      &ua.QualifiedName{NamespaceIndex: 0, Name: name},
		DisplayName:     ua.NewLocalizedText(name),
		NodeClass:       class,
		TypeDefinition:  ua.NewExpandedNodeID(ua.NewNumericNodeID(0, typeDef), "", 0),
	}
}

// browseNode answers one BrowseDescription. Only the Objects folder has
// children; every other node is reported as unknown.
func browseNode(d *ua.BrowseDescription) *ua.BrowseResult {
	if d == nil || d.NodeID == nil || d.NodeID.Namespace() != 0 || d.NodeID.IntID() != nodeObjectsFolder {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}
	if d.BrowseDirection == ua.BrowseDirectionInverse {
		return &ua.BrowseResult{StatusCode: ua.StatusGood}
	}
	return &ua.BrowseResult{
		StatusCode: ua.StatusGood,
		References: []*ua.ReferenceDescription{
			ref(nodeServer, "Server", ua.NodeClassObject, nodeServerType),
			ref(1000, "PLC", ua.NodeClassObject, nodeFolderType),
		},
	}
}

func (s *Session) replyService(payload []byte, msgType string, typeID uint16, resp headeredResponse) ([]byte, error) {
	m := new(uasc.Message)
	if _, err := m.Decode(payload); err != nil {
		return nil, nil
	}
	resp.SetHeader(responseHeaderFromAny(m.Service, ua.StatusGood))
	return s.encodeUASC(msgType, requestID(m), typeID, resp)
}

type headeredResponse interface {
	SetHeader(*ua.ResponseHeader)
}

func (s *Session) encodeUASC(msgType string, reqID uint32, typeID uint16, service interface{}) ([]byte, error) {
	mh := &uasc.MessageHeader{
		Header: &uasc.Header{
			MessageType:     msgType,
			ChunkType:       uasc.ChunkTypeFinal,
			SecureChannelID: s.channelID,
		},
		SequenceHeader: &uasc.SequenceHeader{
			SequenceNumber: s.nextSequence(),
			RequestID:      reqID,
		},
	}
	if msgType == uasc.MessageTypeOpenSecureChannel {
		mh.AsymmetricSecurityHeader = &uasc.AsymmetricSecurityHeader{
			SecurityPolicyURI: ua.SecurityPolicyURINone,
		}
	} else {
		mh.SymmetricSecurityHeader = &uasc.SymmetricSecurityHeader{TokenID: s.tokenID}
	}
	m := &uasc.Message{
		MessageHeader: mh,
		TypeID:        ua.NewFourByteExpandedNodeID(0, typeID),
		Service:       service,
	}
	return m.Encode()
}

func (s *Session) application() *ua.ApplicationDescription {
	return &ua.ApplicationDescription{
		ApplicationURI:  applicationURI,
		ProductURI:      productURI,
		ApplicationName: ua.NewLocalizedText(applicationName),
		ApplicationType: ua.ApplicationTypeServer,
		DiscoveryURLs:   []string{s.endpointURL},
	}
}

func (s *Session) endpoint() *ua.EndpointDescription {
	return &ua.EndpointDescription{
		EndpointURL:       s.endpointURL,
		Server:            s.application(),
		SecurityMode:      ua.MessageSecurityModeNone,
		SecurityPolicyURI: ua.SecurityPolicyURINone,
		UserIdentityTokens: []*ua.UserTokenPolicy{
			{PolicyID: "anonymous", TokenType: ua.UserTokenTypeAnonymous, SecurityPolicyURI: ua.SecurityPolicyURINone},
			{PolicyID: "username", TokenType: ua.UserTokenTypeUserName, SecurityPolicyURI: ua.SecurityPolicyURINone},
		},
		TransportProfileURI: transportURI,
		SecurityLevel:       0,
	}
}

type requestHeadered interface {
	Header() *ua.RequestHeader
}

func requestID(m *uasc.Message) uint32 {
	if m != nil && m.SequenceHeader != nil {
		return m.SequenceHeader.RequestID
	}
	return 0
}

func responseHeader(req requestHeadered) *ua.ResponseHeader {
	return responseHeaderFromAny(req, ua.StatusGood)
}

func responseHeaderFromAny(svc interface{}, result ua.StatusCode) *ua.ResponseHeader {
	var handle uint32
	if req, ok := svc.(requestHeadered); ok && req != nil && req.Header() != nil {
		handle = req.Header().RequestHandle
	}
	return &ua.ResponseHeader{
		Timestamp:          time.Now().UTC(),
		RequestHandle:      handle,
		ServiceResult:      result,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}
