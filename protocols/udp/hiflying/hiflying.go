// Package hiflying parses the UDP configuration protocol of Hi-Flying
// (HF-A11, HF-LPB100, HF-LPT; also USR-WIFI232 clones) Wi-Fi serial modules
// on udp/48899 and builds a module's replies. A client broadcasts the assist
// password, the module answers with "<ip>,<mac>,<module id>", the client sends
// "+ok" to enter command mode and then "AT+<CMD>[=args]\r" commands answered
// with "+ok[=value]\r\n\r\n" or "+ERR=<code>\r\n\r\n". Nothing here acts on a
// command: set, reset and OTA commands are only acknowledged.
package hiflying

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
)

const (
	// DiscoveryPassword is the factory "assist" password (AT+ASWD) that
	// clients broadcast to find modules.
	DiscoveryPassword = "HF-A11ASSISTHREAD"
	// ModuleID is the module type announced in the discovery reply.
	ModuleID = "HF-LPB100"

	enterAT    = "+ok"
	atPrefix   = "AT+"
	maxVerbLen = 16
	maskedArg  = "***"

	// StatusDiscoverReply, StatusOK and StatusErr are the decoded `status` of writes.
	StatusDiscoverReply = "DISCOVER_REPLY"
	StatusOK            = "OK"
	StatusErr           = "ERR"
)

// Kind classifies a datagram.
type Kind int

const (
	KindUnknown Kind = iota
	KindDiscover
	KindEnterAT
	KindAT
)

// Request is a parsed datagram. Verb is the upper-cased command without the
// "AT+" prefix (e.g. "WSKEY"), Args the text after '=' with any key or
// password replaced by "***". Masked is the datagram with the same
// replacement, or nil when nothing was masked.
type Request struct {
	Kind    Kind
	Verb    string
	Args    string
	HasArgs bool
	Masked  []byte
}

// Command returns the decoded `command`: DISCOVER, ENTER_AT, AT+<VERB> or UNKNOWN.
func (r Request) Command() string {
	switch r.Kind {
	case KindDiscover:
		return "DISCOVER"
	case KindEnterAT:
		return "ENTER_AT"
	case KindAT:
		return atPrefix + r.Verb
	}
	return "UNKNOWN"
}

// firstLine returns b up to its first CR or LF.
func firstLine(b []byte) []byte {
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		return b[:i]
	}
	return b
}

// LooksLikeDiscovery reports whether b is the factory discovery password,
// optionally followed by a line ending.
func LooksLikeDiscovery(b []byte) bool {
	return len(b) <= len(DiscoveryPassword)+2 && string(firstLine(b)) == DiscoveryPassword
}

// LooksLikeCommand reports whether b is "+ok" or a well-formed AT command.
func LooksLikeCommand(b []byte) bool {
	k := Parse(b).Kind
	return k == KindEnterAT || k == KindAT
}

// Parse classifies one datagram. Only its first line is considered.
func Parse(b []byte) Request {
	line := firstLine(b)
	switch {
	case string(line) == DiscoveryPassword:
		return Request{Kind: KindDiscover}
	case string(line) == enterAT:
		return Request{Kind: KindEnterAT}
	case len(line) <= len(atPrefix) || !strings.EqualFold(string(line[:len(atPrefix)]), atPrefix):
		return Request{}
	}
	rest := string(line[len(atPrefix):])
	verb, args, hasArgs := strings.Cut(rest, "=")
	if len(verb) > maxVerbLen || !isVerb(verb) {
		return Request{}
	}
	r := Request{Kind: KindAT, Verb: strings.ToUpper(verb), Args: args, HasArgs: hasArgs}
	if masked, ok := maskArgs(r.Verb, args); hasArgs && ok {
		r.Args = masked
		start := len(atPrefix) + len(verb) + 1
		r.Masked = append(append(append([]byte{}, b[:start]...), masked...), b[len(line):]...)
	}
	return r
}

func isVerb(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// maskArgs hides keys and passwords a client sets: the key field of
// WSKEY/WAKEY ("auth,encry,key"), the ASWD assist password and the WEBU
// password ("user,password").
func maskArgs(verb, args string) (string, bool) {
	maskField := func(n int) (string, bool) {
		f := strings.SplitN(args, ",", n+1)
		if len(f) <= n || f[n] == "" {
			return args, false
		}
		f[n] = maskedArg
		return strings.Join(f, ","), true
	}
	switch verb {
	case "WSKEY", "WAKEY":
		return maskField(2)
	case "WEBU":
		return maskField(1)
	case "ASWD":
		if args == "" {
			return args, false
		}
		return maskedArg, true
	}
	return args, false
}

// Module is the stable identity a sensor presents.
type Module struct {
	IP      net.IP
	Gateway net.IP
	MAC     [6]byte
	APMAC   [6]byte
	SSID    string
	Key     string
}

// ModuleFor derives a stable module identity from seed (the sensor address).
// The module sits on a private LAN behind the router that forwards the port,
// as a real exposed module does; the MAC uses the Hi-Flying AC:CF:23 OUI.
func ModuleFor(seed []byte) Module {
	sum := sha256.Sum256(append([]byte("hiflying:"), seed...))
	return Module{
		IP:      net.IPv4(192, 168, 1, 100+sum[0]%100).To4(),
		Gateway: net.IPv4(192, 168, 1, 1).To4(),
		MAC:     [6]byte{0xac, 0xcf, 0x23, sum[1], sum[2], sum[3]},
		APMAC:   [6]byte{sum[4] & 0xfc, sum[5], sum[6], sum[7], sum[8], sum[9]},
		SSID:    fmt.Sprintf("TP-Link_%02X%02X", sum[10], sum[11]),
		Key:     fmt.Sprintf("%x", sum[12:17]),
	}
}

func hexMAC(m [6]byte) string { return fmt.Sprintf("%X", m[:]) }

// BuildDiscoveryReply is the module's answer to the discovery password.
func BuildDiscoveryReply(m Module) []byte {
	return []byte(fmt.Sprintf("%s,%s,%s", m.IP, hexMAC(m.MAC), ModuleID))
}

func ok(v string) []byte {
	if v == "" {
		return []byte("+ok\r\n\r\n")
	}
	return []byte("+ok=" + v + "\r\n\r\n")
}

// errInvalidCommand is "+ERR=-2" (invalid command code).
var errInvalidCommand = []byte("+ERR=-2\r\n\r\n")

// queries are the values a module reports for read commands.
func queries(m Module) map[string]string {
	return map[string]string{
		"VER":    "1.0.06a-14 (2015-09-08 10:20 1M)",
		"MID":    ModuleID,
		"WMODE":  "STA",
		"WSSSID": m.SSID,
		"WSKEY":  "WPA2PSK,AES," + m.Key,
		"WSLK":   fmt.Sprintf("%s(%s)", m.SSID, hexMAC(m.APMAC)),
		"WSMAC":  hexMAC(m.MAC),
		"WANN":   fmt.Sprintf("DHCP,%s,255.255.255.0,%s", m.IP, m.Gateway),
		"WAP":    "11BGN," + ModuleID + ",CH1",
		"NETP":   "TCP,Server,8899,10.10.100.254",
		"UART":   "115200,8,1,None,NFC",
	}
}

// actions are acknowledged without a value and never carried out.
var actions = map[string]string{
	"Q":    "",
	"Z":    "",
	"ENTM": "",
	"RELD": "rebooting...",
}

// settable are commands that accept "=args" (acknowledged, not applied).
var settable = map[string]bool{
	"WMODE": true, "WSSSID": true, "WSKEY": true, "WANN": true, "WAP": true,
	"NETP": true, "UART": true, "WAKEY": true, "ASWD": true, "WEBU": true,
	"MID": true, "UPURL": true, "WSMAC": true,
}

// BuildATReply answers an AT command and returns the decoded `status`.
func BuildATReply(m Module, r Request) ([]byte, string) {
	if r.Kind != KindAT {
		return errInvalidCommand, StatusErr
	}
	if r.HasArgs {
		if settable[r.Verb] {
			return ok(""), StatusOK
		}
		return errInvalidCommand, StatusErr
	}
	if v, found := actions[r.Verb]; found {
		return ok(v), StatusOK
	}
	if v, found := queries(m)[r.Verb]; found {
		return ok(v), StatusOK
	}
	return errInvalidCommand, StatusErr
}
