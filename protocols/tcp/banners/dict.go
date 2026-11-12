package banners

import (
	"bytes"
	"math/rand/v2"
	"strconv"
	"strings"
)

// DICT (RFC 2229, tcp/2628) is server-first: dictd greets with
// "220 <host> <server info> <capabilities> <msg-id>" on connect, then reads
// CRLF-terminated command lines. nmap match:
// dict m|^220 ([-.\w]+) dictd ([-.\w/]+) on ([-.+ \w]+) <auth\.mime>|
// p/dictd/ v/$2/ o/$3/ h/$1/. The persona is the dictd 1.12.1 package of
// Ubuntu 22.04, matching the OpenSSH and Dovecot personas; the msg-id is
// dictd's "<pid.forks.time@host>" stamp. The reply texts are from memory of
// dictd's daemon.c and unverified.
const dictHost = "ubuntu"

// dictPID is the dictd child pid in the msg-id, replaced in tests.
var dictPID = func() int { return 1000 + rand.IntN(30000) }

func dictGreeting() []byte {
	return []byte("220 " + dictHost + " dictd 1.12.1/rf on Linux 5.15.0-91-generic <auth.mime> <" +
		strconv.Itoa(dictPID()) + ".0." + strconv.FormatInt(now().Unix(), 10) + "@" + dictHost + ">\r\n")
}

const (
	dictUnknown = "500 unknown command\r\n"
	dictBye     = "221 bye [d/m/c = 0/0/0; 0.000r 0.000u 0.000s]\r\n"
	dictOK      = "250 ok\r\n"
)

// DICTFollowUp answers command lines after the DICT greeting. Every complete
// line is answered, so a scanner's bare "\r\n\r\n" gets two "500 unknown
// command" replies; CLIENT is acknowledged and QUIT says goodbye, after which
// the server hangs up. A trailing line without its newline is not answered
// yet.
func DICTFollowUp(data []byte) (Response, bool) {
	lines := strings.Split(string(data), "\n")
	// the element after the final "\n" is an unterminated line; drop it
	lines = lines[:len(lines)-1]

	out := Response{Name: "dict", NoReply: true}
	var reply bytes.Buffer
	for _, line := range lines {
		verb, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch strings.ToLower(verb) {
		case "quit":
			out.Name = "dict-bye"
			out.Close = true
			reply.WriteString(dictBye)
		case "client":
			out.Name = "dict-ok"
			reply.WriteString(dictOK)
		default:
			out.Name = "dict-unknown"
			reply.WriteString(dictUnknown)
		}
		if out.Close {
			break
		}
	}
	if reply.Len() > 0 {
		out.NoReply = false
		out.Data = reply.Bytes()
	}
	return out, true
}
