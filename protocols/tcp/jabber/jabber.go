// Package jabber holds XMPP (RFC 6120) stream framing, stanza parsing and
// response construction for the jabber TCP handler.
package jabber

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	NSClient   = "jabber:client"
	NSStream   = "http://etherx.jabber.org/streams"
	NSSASL     = "urn:ietf:params:xml:ns:xmpp-sasl"
	NSTLS      = "urn:ietf:params:xml:ns:xmpp-tls"
	NSStreams  = "urn:ietf:params:xml:ns:xmpp-streams"
	NSStanzas  = "urn:ietf:params:xml:ns:xmpp-stanzas"
	NSIQAuth   = "jabber:iq:auth"
	NSIQAuthFt = "http://jabber.org/features/iq-auth"

	// CmdStreamEnd is the command recorded for a closing </stream:stream>.
	CmdStreamEnd = "stream-end"

	maxHostLen = 255
)

// ErrMalformed is returned by NextFrame when the buffered bytes are not
// well-formed XML.
var ErrMalformed = errors.New("jabber: malformed XML")

// NextFrame splits the first complete top-level unit off buf. A unit is a
// stream header (<stream:stream ...>, optionally preceded by an XML
// declaration), a stream close (</stream:stream>), or a complete stanza
// (<auth>...</auth>, <iq/>, ...). Leading whitespace is kept with the unit so
// payloads reproduce the wire bytes. ok is false when more data is needed.
func NextFrame(buf []byte) (frame, rest []byte, ok bool, err error) {
	d := xml.NewDecoder(bytes.NewReader(buf))
	d.Strict = true
	var open []xml.Name
	for {
		tok, err := d.RawToken()
		if err != nil {
			if isIncomplete(err) {
				return nil, buf, false, nil
			}
			return nil, buf, false, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(open) == 0 && t.Name.Local == "stream" {
				// The stream header is never closed until the session ends.
				off := d.InputOffset()
				return buf[:off], buf[off:], true, nil
			}
			open = append(open, t.Name)
		case xml.EndElement:
			if len(open) == 0 {
				if t.Name.Local != "stream" {
					return nil, buf, false, fmt.Errorf("%w: unexpected </%s>", ErrMalformed, t.Name.Local)
				}
				off := d.InputOffset()
				return buf[:off], buf[off:], true, nil
			}
			if open[len(open)-1] != t.Name {
				return nil, buf, false, fmt.Errorf("%w: </%s> does not match <%s>", ErrMalformed, t.Name.Local, open[len(open)-1].Local)
			}
			open = open[:len(open)-1]
			if len(open) == 0 {
				off := d.InputOffset()
				return buf[:off], buf[off:], true, nil
			}
		case xml.CharData:
			if len(open) == 0 && len(bytes.TrimSpace(t)) > 0 {
				return nil, buf, false, fmt.Errorf("%w: text outside of element", ErrMalformed)
			}
		}
	}
}

func isIncomplete(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var se *xml.SyntaxError
	return errors.As(err, &se) && se.Msg == "unexpected EOF"
}

// Stanza is the parsed form of one frame returned by NextFrame.
type Stanza struct {
	Name      string // local name of the top-level element, or CmdStreamEnd
	Space     string // namespace (xmlns attribute) of the top-level element
	To        string
	ID        string
	Type      string
	Mechanism string
	Text      string // character data directly inside the top-level element
	QueryNS   string // namespace of a <query> child (iq stanzas)
	Username  string // <username> descendant (jabber:iq:auth)
	Password  string // <password> descendant (jabber:iq:auth)
	Resource  string
}

// ParseStanza parses a frame returned by NextFrame.
func ParseStanza(frame []byte) (Stanza, error) {
	var s Stanza
	d := xml.NewDecoder(bytes.NewReader(frame))
	depth := 0
	var current string
	for {
		tok, err := d.RawToken()
		if err != nil {
			if s.Name != "" {
				return s, nil
			}
			return s, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				s.Name = t.Name.Local
				for _, a := range t.Attr {
					switch {
					case a.Name.Space == "" && a.Name.Local == "xmlns":
						s.Space = a.Value
					case a.Name.Local == "to":
						s.To = a.Value
					case a.Name.Local == "id":
						s.ID = a.Value
					case a.Name.Local == "type":
						s.Type = a.Value
					case a.Name.Local == "mechanism":
						s.Mechanism = a.Value
					}
				}
				if s.Name == "stream" {
					return s, nil
				}
			} else if t.Name.Local == "query" {
				for _, a := range t.Attr {
					if a.Name.Space == "" && a.Name.Local == "xmlns" {
						s.QueryNS = a.Value
					}
				}
			}
			current = t.Name.Local
			depth++
		case xml.EndElement:
			if depth == 0 {
				s.Name = CmdStreamEnd
				return s, nil
			}
			depth--
			current = ""
			if depth == 0 {
				return s, nil
			}
		case xml.CharData:
			text := string(t)
			switch {
			case depth == 1:
				s.Text += text
			case current == "username":
				s.Username += text
			case current == "password":
				s.Password += text
			case current == "resource":
				s.Resource += text
			}
		}
	}
}

// DecodePlain decodes a SASL PLAIN initial response (RFC 4616):
// base64(authzid NUL authcid NUL passwd).
func DecodePlain(text string) (authzid, username, password string, err error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return "", "", "", err
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 {
		return "", "", "", errors.New("jabber: invalid PLAIN message")
	}
	return parts[0], parts[1], parts[2], nil
}

func escapeAttr(s string) string {
	if len(s) > maxHostLen {
		s = s[:maxHostLen]
	}
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// StreamHeader builds the server's response stream header.
func StreamHeader(id, from string) []byte {
	return []byte(fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='%s' id='%s' from='%s' version='1.0' xml:lang='en'>",
		NSClient, NSStream, escapeAttr(id), escapeAttr(from)))
}

// Features builds the pre-authentication <stream:features>. STARTTLS is
// offered only when the stream is not already encrypted.
func Features(offerTLS bool) []byte {
	var b strings.Builder
	b.WriteString("<stream:features>")
	if offerTLS {
		fmt.Fprintf(&b, "<starttls xmlns='%s'/>", NSTLS)
	}
	fmt.Fprintf(&b, "<mechanisms xmlns='%s'><mechanism>PLAIN</mechanism></mechanisms>", NSSASL)
	fmt.Fprintf(&b, "<auth xmlns='%s'/>", NSIQAuthFt)
	b.WriteString("</stream:features>")
	return []byte(b.String())
}

// Proceed tells the client to start the TLS handshake.
func Proceed() []byte {
	return []byte(fmt.Sprintf("<proceed xmlns='%s'/>", NSTLS))
}

// SASLFailure builds a SASL <failure/> with the given condition.
func SASLFailure(condition string) []byte {
	return []byte(fmt.Sprintf("<failure xmlns='%s'><%s/></failure>", NSSASL, condition))
}

// StreamError builds a stream error followed by the stream close tag.
func StreamError(condition string) []byte {
	return []byte(fmt.Sprintf("<stream:error><%s xmlns='%s'/></stream:error></stream:stream>", condition, NSStreams))
}

// StreamEnd closes the server stream.
func StreamEnd() []byte {
	return []byte("</stream:stream>")
}

// IQAuthFields answers a jabber:iq:auth get (XEP-0078) with the plaintext
// fields so legacy clients continue to the set request.
func IQAuthFields(id string) []byte {
	return []byte(fmt.Sprintf(
		"<iq type='result' id='%s'><query xmlns='%s'><username/><password/><resource/></query></iq>",
		escapeAttr(id), NSIQAuth))
}

// IQError builds an iq error reply with an RFC 6120 stanza error condition.
func IQError(id, errType, condition string) []byte {
	return []byte(fmt.Sprintf(
		"<iq type='error' id='%s'><error type='%s'><%s xmlns='%s'/></error></iq>",
		escapeAttr(id), errType, condition, NSStanzas))
}
