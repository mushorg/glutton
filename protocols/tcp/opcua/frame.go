package opcua

import (
	"fmt"
	"io"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

const (
	HeaderLen      = 8
	MaxMessageSize = 64 * 1024

	applicationURI  = "urn:opcua:server"
	productURI      = "urn:opcua:product"
	applicationName = "PLC"
	transportURI    = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
)

var DefaultACK = uacp.Acknowledge{
	Version:        0,
	ReceiveBufSize: MaxMessageSize,
	SendBufSize:    MaxMessageSize,
	MaxMessageSize: MaxMessageSize,
	MaxChunkCount:  1,
}

// Frame is one decoded UACP message.
type Frame struct {
	MessageType     string
	ChunkType       byte
	Service         string
	EndpointURL     string
	SecurityPolicy  string
	ApplicationURI  string
	ApplicationName string
	Username        string
	Payload         []byte
}

// ReadMessage reads one length-prefixed UACP message. It rejects claimed
// sizes outside [HeaderLen, MaxMessageSize] without reading the body.
func ReadMessage(r io.Reader) ([]byte, error) {
	hdr := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	var h uacp.Header
	if _, err := h.Decode(hdr); err != nil {
		return nil, err
	}
	if h.MessageSize < HeaderLen || h.MessageSize > MaxMessageSize {
		return nil, fmt.Errorf("invalid uacp message size: %d", h.MessageSize)
	}
	buf := make([]byte, h.MessageSize)
	copy(buf, hdr)
	if h.MessageSize == HeaderLen {
		return buf, nil
	}
	if _, err := io.ReadFull(r, buf[HeaderLen:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// Parse extracts fields from a full UACP message. Unknown or truncated
// payloads still return a frame with Payload set.
func Parse(payload []byte) Frame {
	f := Frame{Payload: payload}
	if len(payload) < HeaderLen {
		f.Service = "UNKNOWN"
		return f
	}
	var h uacp.Header
	if _, err := h.Decode(payload[:HeaderLen]); err != nil {
		f.Service = "UNKNOWN"
		return f
	}
	f.MessageType = h.MessageType
	f.ChunkType = h.ChunkType
	body := payload[HeaderLen:]

	switch h.MessageType {
	case uacp.MessageTypeHello:
		f.Service = "Hello"
		hel := new(uacp.Hello)
		if _, err := hel.Decode(body); err == nil {
			f.EndpointURL = hel.EndpointURL
		}
	case uacp.MessageTypeAcknowledge:
		f.Service = "Acknowledge"
	case uacp.MessageTypeError:
		f.Service = "Error"
	case uacp.MessageTypeReverseHello:
		f.Service = "ReverseHello"
		rhe := new(uacp.ReverseHello)
		if _, err := rhe.Decode(body); err == nil {
			f.EndpointURL = rhe.EndpointURL
		}
	case uasc.MessageTypeOpenSecureChannel, uasc.MessageTypeMessage, uasc.MessageTypeCloseSecureChannel:
		mh := new(uasc.MessageHeader)
		if _, err := mh.Decode(payload); err == nil && mh.AsymmetricSecurityHeader != nil {
			f.SecurityPolicy = mh.AsymmetricSecurityHeader.SecurityPolicyURI
		}
		m := new(uasc.Message)
		if _, err := m.Decode(payload); err != nil {
			if f.Service == "" {
				f.Service = "UNKNOWN"
			}
			return f
		}
		if m.AsymmetricSecurityHeader != nil {
			f.SecurityPolicy = m.AsymmetricSecurityHeader.SecurityPolicyURI
		}
		fillFromService(&f, m.Service)
	default:
		f.Service = "UNKNOWN"
	}
	return f
}

func fillFromService(f *Frame, svc interface{}) {
	switch t := svc.(type) {
	case *ua.OpenSecureChannelRequest, *ua.OpenSecureChannelResponse:
		f.Service = "OpenSecureChannel"
	case *ua.CloseSecureChannelRequest, *ua.CloseSecureChannelResponse:
		f.Service = "CloseSecureChannel"
	case *ua.GetEndpointsRequest:
		f.Service = "GetEndpoints"
		if t != nil {
			f.EndpointURL = t.EndpointURL
		}
	case *ua.GetEndpointsResponse:
		f.Service = "GetEndpoints"
	case *ua.FindServersRequest:
		f.Service = "FindServers"
		if t != nil {
			f.EndpointURL = t.EndpointURL
		}
	case *ua.FindServersResponse:
		f.Service = "FindServers"
	case *ua.CreateSessionRequest:
		f.Service = "CreateSession"
		if t != nil {
			f.EndpointURL = t.EndpointURL
			if t.ClientDescription != nil {
				f.ApplicationURI = t.ClientDescription.ApplicationURI
				if t.ClientDescription.ApplicationName != nil {
					f.ApplicationName = t.ClientDescription.ApplicationName.Text
				}
			}
		}
	case *ua.CreateSessionResponse:
		f.Service = "CreateSession"
	case *ua.ActivateSessionRequest:
		f.Service = "ActivateSession"
		if t != nil && t.UserIdentityToken != nil {
			if tok, ok := t.UserIdentityToken.Value.(*ua.UserNameIdentityToken); ok && tok != nil {
				f.Username = tok.UserName
			}
		}
	case *ua.ActivateSessionResponse:
		f.Service = "ActivateSession"
	case *ua.CloseSessionRequest, *ua.CloseSessionResponse:
		f.Service = "CloseSession"
	case *ua.ServiceFault:
		f.Service = "ServiceFault"
	default:
		if f.Service == "" {
			f.Service = "UNKNOWN"
		}
	}
}

// EncodeUACP wraps a body in an 8-byte UACP header.
func EncodeUACP(msgType string, chunkType byte, body []byte) ([]byte, error) {
	h := uacp.Header{
		MessageType: msgType,
		ChunkType:   chunkType,
		MessageSize: uint32(HeaderLen + len(body)),
	}
	hdr, err := h.Encode()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hdr)+len(body))
	out = append(out, hdr...)
	out = append(out, body...)
	return out, nil
}

// EncodeHello builds a client Hello used by tests and callers.
func EncodeHello(endpointURL string) ([]byte, error) {
	hel := uacp.Hello{
		Version:        0,
		ReceiveBufSize: MaxMessageSize,
		SendBufSize:    MaxMessageSize,
		MaxMessageSize: MaxMessageSize,
		MaxChunkCount:  1,
		EndpointURL:    endpointURL,
	}
	body, err := hel.Encode()
	if err != nil {
		return nil, err
	}
	return EncodeUACP(uacp.MessageTypeHello, uacp.ChunkTypeFinal, body)
}

func encodeACK() ([]byte, error) {
	body, err := DefaultACK.Encode()
	if err != nil {
		return nil, err
	}
	return EncodeUACP(uacp.MessageTypeAcknowledge, uacp.ChunkTypeFinal, body)
}

func encodeERR(code ua.StatusCode) ([]byte, error) {
	body, err := (&uacp.Error{ErrorCode: uint32(code)}).Encode()
	if err != nil {
		return nil, err
	}
	return EncodeUACP(uacp.MessageTypeError, uacp.ChunkTypeFinal, body)
}

// EncodeReverseHello builds a ReverseHello used by tests. The handler never dials.
func EncodeReverseHello(serverURI, endpointURL string) ([]byte, error) {
	body, err := (&uacp.ReverseHello{ServerURI: serverURI, EndpointURL: endpointURL}).Encode()
	if err != nil {
		return nil, err
	}
	return EncodeUACP(uacp.MessageTypeReverseHello, uacp.ChunkTypeFinal, body)
}
