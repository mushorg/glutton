// Package banners holds canned service responses for the catch-all TCP
// handler, so connections to ports without a dedicated handler get a reply
// shaped like the real service instead of random bytes. The per-port
// responses come from honeytrap (github.com/armedpot/honeytrap/etc/responses,
// mushorg/glutton#53); a few payload signatures cover client-first protocols
// that show up on any port. The package does no I/O.
package banners

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"
)

// Response is a canned reply.
type Response struct {
	Name        string // recorded as the write frame status
	Data        []byte
	ServerFirst bool // sent on connect, before reading
	// GreetWhenIdle sends the response on connect only if the client stays
	// silent for a short wait, so ports shared with client-first protocols
	// (HTTP on 4444) still route those clients by their first bytes.
	GreetWhenIdle bool
	// Silent means the client's bytes get no reply, as a real service does
	// with input it cannot parse.
	Silent bool
}

// now is replaced in tests for a stable HTTP Date header.
var now = time.Now

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	sshBanner  = []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
	pop3Banner = []byte("+OK Dovecot (Ubuntu) ready.\r\n")
	rfbBanner  = []byte("RFB 003.008\n")

	// cmd.exe prompt of a Windows Server 2003 bind shell, matching the IIS 6.0
	// persona on port 80. Adapted from honeytrap 4444_tcp (an XP prompt with
	// bare LFs that nmap does not recognize); CRLF line endings make nmap -sV
	// report bindshell "Microsoft Windows cmd.exe".
	cmdShellBanner = []byte("Microsoft Windows [Version 5.2.3790]\r\n" +
		"(C) Copyright 1985-2003 Microsoft Corp.\r\n\r\n" +
		"C:\\WINDOWS\\system32>")

	// DCE/RPC bind_ack (honeytrap 135_tcp).
	dcerpcBindAck = mustHex(
		"05000c03100000003c00000001000000d016d016acd80000040031333500c501" +
			"0100000000000000045d888aeb1cc9119fe808002b10486002000000")
	// NetBIOS positive session response (honeytrap 139_tcp).
	netbiosSession = []byte{0x82, 0x00, 0x00, 0x00}
	// TDS pre-login response (honeytrap 1433_tcp).
	mssqlPrelogin = mustHex(
		"0401002500000100000015000601001b000102001c000103001d0000ff080001" +
			"3700000200")
	// Radmin handshake reply (honeytrap 4899_tcp).
	radminReply = mustHex(
		"0100000025000000100800000008000000000000000000000000000000000000" +
			"0000000000000000000000000000")
	// AJP13 SEND_HEADERS 404 + body + END_RESPONSE from Tomcat (honeytrap 8009_tcp).
	ajp404 = mustHex(
		"414200360401940003343034000003a0010017746578742f68746d6c3b636861" +
			"727365743d7574662d3800a0020002656e00a003000337313300414202cd0302" +
			"c93c21646f63747970652068746d6c3e3c68746d6c206c616e673d22656e223e" +
			"3c686561643e3c7469746c653e48545450205374617475732034303420e28093" +
			"204e6f7420466f756e643c2f7469746c653e3c7374796c6520747970653d2274" +
			"6578742f637373223e626f6479207b666f6e742d66616d696c793a5461686f6d" +
			"612c417269616c2c73616e732d73657269663b7d2068312c2068322c2068332c" +
			"2062207b636f6c6f723a77686974653b6261636b67726f756e642d636f6c6f72" +
			"3a233532354437363b7d206831207b666f6e742d73697a653a323270783b7d20" +
			"6832207b666f6e742d73697a653a313670783b7d206833207b666f6e742d7369" +
			"7a653a313470783b7d2070207b666f6e742d73697a653a313270783b7d206120" +
			"7b636f6c6f723a626c61636b3b7d202e6c696e65207b6865696768743a317078" +
			"3b6261636b67726f756e642d636f6c6f723a233532354437363b626f72646572" +
			"3a6e6f6e653b7d3c2f7374796c653e3c2f686561643e3c626f64793e3c68313e" +
			"48545450205374617475732034303420e28093204e6f7420466f756e643c2f68" +
			"313e3c687220636c6173733d226c696e6522202f3e3c703e3c623e547970653c" +
			"2f623e20537461747573205265706f72743c2f703e3c703e3c623e4d65737361" +
			"67653c2f623e204e6f7420666f756e643c2f703e3c703e3c623e446573637269" +
			"7074696f6e3c2f623e20546865206f726967696e207365727665722064696420" +
			"6e6f742066696e6420612063757272656e7420726570726573656e746174696f" +
			"6e20666f722074686520746172676574207265736f75726365206f7220697320" +
			"6e6f742077696c6c696e6720746f20646973636c6f73652074686174206f6e65" +
			"206578697374732e3c2f703e3c687220636c6173733d226c696e6522202f3e3c" +
			"68333e41706163686520546f6d6361742f392e302e33303c2f68333e3c2f626f" +
			"64793e3c2f68746d6c3e00414200020501")

	// TLS fatal handshake_failure alert.
	tlsAlert = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

	// HTTP/2 client connection preface (RFC 9113 §3.4), sent first by h2c
	// prior-knowledge clients.
	h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	// nginx-style HTTP/2 server reply, all on stream 0:
	//   SETTINGS       MAX_CONCURRENT_STREAMS=128, INITIAL_WINDOW_SIZE=65536,
	//                  MAX_FRAME_SIZE=16777215
	//   WINDOW_UPDATE  connection window +2147418112
	//   SETTINGS ACK   for the client's SETTINGS
	//   GOAWAY         last stream 0, NO_ERROR (the catch-all closes after one write)
	h2Reply = mustHex(
		"000012040000000000" + "000300000080" + "000400010000" + "000500ffffff" +
			"000004080000000000" + "7fff0000" +
			"000000040100000000" +
			"000008070000000000" + "0000000000000000")
)

// x11Reason is Xorg's refusal for a client without authorization; nmap
// reports it as "X11 (access denied)".
const x11Reason = "No protocol specified\n"

// isX11Setup reports whether data starts with an X11 connection setup
// request: byte order 'l' (little-endian) or 'B' (big-endian), an unused zero
// byte and protocol major version 11. It returns the client's byte order.
func isX11Setup(data []byte) (binary.ByteOrder, bool) {
	if len(data) < 12 || data[1] != 0 {
		return nil, false
	}
	var order binary.ByteOrder
	switch data[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return nil, false
	}
	if order.Uint16(data[2:4]) != 11 {
		return nil, false
	}
	return order, true
}

// x11Failed builds an X11 connection setup Failed reply in the client's byte
// order: status 0, reason length, protocol 11.0, additional length in 4-byte
// units, then the reason padded to a multiple of four.
func x11Failed(order binary.ByteOrder, reason string) []byte {
	padded := (len(reason) + 3) &^ 3
	b := make([]byte, 8+padded)
	b[1] = byte(len(reason))
	order.PutUint16(b[2:4], 11)
	order.PutUint16(b[6:8], uint16(padded/4))
	copy(b[8:], reason)
	return b
}

// httpResponse is honeytrap's IIS 6.0 reply (80_tcp) with CRLF line endings,
// a current Date and a Content-Length matching the body.
func httpResponse() []byte {
	body := "<HTML>\r\n<BODY>\r\n</BODY>\r\n</HTML>\r\n"
	return []byte("HTTP/1.1 200 OK\r\n" +
		"Connection: close\r\n" +
		"Date: " + now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\r\n" +
		"Server: Microsoft-IIS/6.0\r\n" +
		"X-Powered-By: ASP.NET\r\n" +
		"X-AspNet-Version: 2.0.50727\r\n" +
		"Accept-Ranges: bytes\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Cache-Control: private\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" + body)
}

// statsdStart is when the fake statsd management console came up; uptime and
// graphite.last_exception count from it, so they differ per sensor run.
var statsdStart = now().Add(-(37*time.Hour + 12*time.Minute))

// statsdStats is the Etsy statsd management console (mgmt_port 8126) reply to
// "stats": uptime, the base message stats and the graphite backend status, with
// last_* values as seconds since the event, terminated by "END\n\n".
func statsdStats() []byte {
	t := now()
	uptime := int64(t.Sub(statsdStart).Seconds())
	s := t.Unix()
	return []byte("uptime: " + strconv.FormatInt(uptime, 10) + "\n" +
		"messages.last_msg_seen: " + strconv.FormatInt(s%7, 10) + "\n" +
		"messages.bad_lines_seen: 0\n" +
		"graphite.last_flush: " + strconv.FormatInt(s%10, 10) + "\n" +
		"graphite.last_exception: " + strconv.FormatInt(uptime, 10) + "\n" +
		"graphite.flush_time: " + strconv.FormatInt(s%4, 10) + "\n" +
		"graphite.flush_length: " + strconv.FormatInt(1400+s%300, 10) + "\n" +
		"END\n\n")
}

// ForPort returns the canned response for a destination port.
func ForPort(port uint16) (Response, bool) {
	switch port {
	case 22, 2222:
		return Response{Name: "ssh", Data: sshBanner, ServerFirst: true}, true
	case 110:
		return Response{Name: "pop3", Data: pop3Banner, ServerFirst: true}, true
	case 5900:
		return Response{Name: "rfb", Data: rfbBanner, ServerFirst: true}, true
	case 80:
		return Response{Name: "http", Data: httpResponse()}, true
	case 135:
		return Response{Name: "dcerpc-bind-ack", Data: dcerpcBindAck}, true
	case 139:
		return Response{Name: "netbios-session", Data: netbiosSession}, true
	case 1433:
		return Response{Name: "mssql-prelogin", Data: mssqlPrelogin}, true
	case 4899:
		return Response{Name: "radmin", Data: radminReply}, true
	case 8009:
		return Response{Name: "ajp-404", Data: ajp404}, true
	case 8126:
		return Response{Name: "statsd-stats", Data: statsdStats()}, true
	case 4444:
		return Response{Name: "cmd-shell", Data: cmdShellBanner, GreetWhenIdle: true}, true
	case 389:
		// LDAP servers drop input that is not an LDAPMessage they answer
		return Response{Name: "ldap", Silent: true}, true
	}
	return Response{}, false
}

// ForPayload matches the first client bytes against protocol signatures; it
// takes precedence over the port response.
func ForPayload(data []byte) (Response, bool) {
	switch {
	case bytes.HasPrefix(data, []byte("SSH-")):
		return Response{Name: "ssh", Data: sshBanner}, true
	case len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04:
		return Response{Name: "tls-alert", Data: tlsAlert}, true
	case bytes.HasPrefix(data, h2Preface):
		return Response{Name: "http2-settings", Data: h2Reply}, true
	case mglnddProbe.Match(data):
		return Response{Name: "mglndd", Silent: true}, true
	}
	if msgID, ok := ldapRootDSEQuery(data); ok {
		return Response{Name: "ldap-rootdse", Data: ldapRootDSEReply(msgID)}, true
	}
	if order, ok := isX11Setup(data); ok {
		return Response{Name: "x11-denied", Data: x11Failed(order, x11Reason)}, true
	}
	return Response{}, false
}
