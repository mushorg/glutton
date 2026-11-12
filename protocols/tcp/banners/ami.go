package banners

import (
	"bytes"
	"math/rand/v2"
	"strconv"
	"strings"
)

// Asterisk Manager Interface (tcp/5038) is server-first: manager.c greets
// with "Asterisk Call Manager/<AMI_VERSION>\r\n" on connect, then reads
// messages of "Key: Value" lines ended by a blank line. nmap match:
// asterisk p/Asterisk Call Manager/ v/$1/. The persona is Asterisk 18 LTS;
// its AMI version string is from memory and unverified.
var amiBanner = []byte("Asterisk Call Manager/7.0.3\r\n")

// amiChallenge is the MD5 login challenge (manager.c: "%ld" of ast_random()),
// replaced in tests.
var amiChallenge = func() int64 { return rand.Int64N(1 << 31) }

// amiMessage is one parsed AMI message: its headers by lower-cased key, with
// the first occurrence winning as in __astman_get_header.
type amiMessage map[string]string

func (m amiMessage) get(key string) string { return m[key] }

// amiResponse renders astman_send_response_full: the response line, the
// echoed ActionID, then the message (or a bare blank line).
func amiResponse(m amiMessage, resp, msg string) []byte {
	var b bytes.Buffer
	b.WriteString("Response: " + resp + "\r\n")
	if id := m.get("actionid"); id != "" {
		b.WriteString("ActionID: " + id + "\r\n")
	}
	if msg != "" {
		b.WriteString("Message: " + msg + "\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// AMIFollowUp answers client messages after the AMI greeting the way an
// unauthenticated manager session does (manager.c process_message). Every
// complete message (ended by a blank line, so a bare "\r\n" counts) is
// answered: no Action gets "Missing action in request", any action other than
// Login, Logoff or Challenge gets "Permission denied", Login fails with
// "Authentication failed" and Logoff says goodbye, after which the server
// hangs up. A trailing message without its blank line is not answered yet.
// The Login's Username and Secret are recorded as credential guesses.
func AMIFollowUp(data []byte) (Response, bool) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	// the element after the final "\n" is an unterminated line still being
	// read; drop it
	lines = lines[:len(lines)-1]

	out := Response{Name: "ami", NoReply: true}
	var reply bytes.Buffer
	msg := amiMessage{}
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line != "" {
			if key, value, ok := strings.Cut(line, ":"); ok {
				key = strings.ToLower(strings.TrimSpace(key))
				if _, seen := msg[key]; !seen {
					msg[key] = strings.TrimLeft(value, " \t")
				}
			}
			continue
		}

		action := strings.ToLower(msg.get("action"))
		switch action {
		case "":
			out.Name = "ami-error"
			reply.Write(amiResponse(msg, "Error", "Missing action in request"))
		case "login":
			out.Name = "ami-auth-failed"
			out.Username = msg.get("username")
			out.Password = msg.get("secret")
			out.Close = true
			reply.Write(amiResponse(msg, "Error", "Authentication failed"))
		case "logoff":
			out.Name = "ami-goodbye"
			out.Close = true
			reply.Write(amiResponse(msg, "Goodbye", "Thanks for all the fish."))
		case "challenge":
			if !strings.EqualFold(msg.get("authtype"), "md5") {
				out.Name = "ami-error"
				reply.Write(amiResponse(msg, "Error", "Must specify AuthType"))
				break
			}
			out.Name = "ami-challenge"
			ack := amiResponse(msg, "Success", "")
			reply.Write(ack[:len(ack)-2])
			reply.WriteString("Challenge: " + strconv.FormatInt(amiChallenge(), 10) + "\r\n\r\n")
		default:
			out.Name = "ami-error"
			reply.Write(amiResponse(msg, "Error", "Permission denied"))
		}
		if out.Close {
			break
		}
		msg = amiMessage{}
	}
	if reply.Len() > 0 {
		out.NoReply = false
		out.Data = reply.Bytes()
	}
	return out, true
}
