package opcua

import (
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

var sessionNonce = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// Session holds per-connection secure-channel state for None-security replies.
type Session struct {
	endpointURL string
	channelID   uint32
	tokenID     uint32
	sequence    uint32
}

func NewSession(endpointURL string) *Session {
	if endpointURL == "" {
		endpointURL = "opc.tcp://1.2.3.4:4840"
	}
	return &Session{
		endpointURL: endpointURL,
		channelID:   fakeChannelID,
		tokenID:     fakeTokenID,
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
			ServerNonce:           sessionNonce,
			ServerEndpoints:       []*ua.EndpointDescription{s.endpoint()},
			ServerSignature:       &ua.SignatureData{},
			MaxRequestMessageSize: MaxMessageSize,
		})
	case *ua.ActivateSessionRequest:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.ActivateSessionResponse_Encoding_DefaultBinary, &ua.ActivateSessionResponse{
			ResponseHeader: responseHeader(req),
			ServerNonce:    sessionNonce,
		})
	case *ua.CloseSessionRequest:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.CloseSessionResponse_Encoding_DefaultBinary, &ua.CloseSessionResponse{
			ResponseHeader: responseHeader(req),
		})
	default:
		return s.encodeUASC(uasc.MessageTypeMessage, requestID(m), id.ServiceFault_Encoding_DefaultBinary, &ua.ServiceFault{
			ResponseHeader: responseHeaderFromAny(m.Service, ua.StatusBadServiceUnsupported),
		})
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
