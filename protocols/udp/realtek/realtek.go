// Package realtek parses datagrams sent to the Realtek Jungle SDK "MP Daemon"
// (UDPServer, udp/9034). The daemon passes commands that start with "orf" to
// system(), so "orf;<shell>" runs arbitrary commands (CVE-2021-35394); Mirai
// family loaders use it to download and run their droppers.
package realtek

import (
	"bytes"
	"strings"
)

// Prefix is the command prefix the vulnerable daemon checks for.
const Prefix = "orf"

// maxURLs caps the URLs kept from one datagram.
const maxURLs = 16

// downloaders are the commands whose URL arguments are recorded.
var downloaders = []string{"wget", "curl", "tftp", "ftpget"}

// urlSchemes are the URL schemes recorded after a downloader.
var urlSchemes = []string{"http://", "https://", "ftp://", "tftp://"}

// Request is one parsed MP daemon datagram.
type Request struct {
	// Shell is the injected command: the text after "orf" and its
	// separator, without a trailing "#" comment.
	Shell string
	// URLs lists, in order and without duplicates, the URLs passed to
	// wget/curl/tftp/ftpget in Shell.
	URLs []string
}

// LooksLikeRealtekMP matches an "orf" command followed by a shell separator
// (";", "|", "&", "$(", "`" or a line break) or nothing at all.
func LooksLikeRealtekMP(data []byte) bool {
	if !bytes.HasPrefix(data, []byte(Prefix)) {
		return false
	}
	rest := data[len(Prefix):]
	if len(rest) == 0 {
		return true
	}
	switch rest[0] {
	case ';', '|', '&', '`', '\n', '\r', 0:
		return true
	case '$':
		return len(rest) > 1 && rest[1] == '('
	}
	return false
}

// Parse extracts the injected shell command and its download URLs. It accepts
// any input; a datagram cut by a capture cap yields what is left.
func Parse(data []byte) Request {
	s := strings.TrimPrefix(string(data), Prefix)
	s = strings.TrimLeft(s, ";|& \t\r\n")
	s = strings.TrimRight(s, " \t\r\n\x00")
	s = trimComment(s)
	return Request{Shell: s, URLs: downloadURLs(s)}
}

// trimComment drops a trailing "#" comment (the "; #" exploits append to
// neutralize what the daemon adds after the command) and the separators
// before it. A "#" inside a word, as in a URL fragment, is kept.
func trimComment(s string) string {
	idx := strings.LastIndexByte(s, '#')
	if idx < 0 || strings.ContainsAny(s[idx:], "\n\r") {
		return s
	}
	if idx > 0 && !strings.ContainsRune(" \t;", rune(s[idx-1])) {
		return s
	}
	return strings.TrimRight(s[:idx], " \t;")
}

// downloadURLs returns the URLs in the shell segments that run a downloader.
func downloadURLs(shell string) []string {
	var urls []string
	seen := map[string]bool{}
	segments := strings.FieldsFunc(shell, func(r rune) bool {
		return strings.ContainsRune(";|&\n\r`()", r)
	})
	for _, seg := range segments {
		fields := strings.FieldsFunc(seg, func(r rune) bool {
			return strings.ContainsRune(" \t\"'\x00", r)
		})
		if !runsDownloader(fields) {
			continue
		}
		for _, f := range fields {
			if !hasURLScheme(f) || seen[f] {
				continue
			}
			seen[f] = true
			urls = append(urls, f)
			if len(urls) == maxURLs {
				return urls
			}
		}
	}
	return urls
}

// runsDownloader reports whether a word of the segment names a downloader,
// bare or as a path ("/bin/busybox wget", "/usr/bin/curl").
func runsDownloader(fields []string) bool {
	for _, f := range fields {
		if strings.Contains(f, "://") {
			continue
		}
		name := f[strings.LastIndexByte(f, '/')+1:]
		for _, d := range downloaders {
			if strings.EqualFold(name, d) {
				return true
			}
		}
	}
	return false
}

func hasURLScheme(f string) bool {
	lower := strings.ToLower(f)
	for _, scheme := range urlSchemes {
		if strings.HasPrefix(lower, scheme) && len(f) > len(scheme) {
			return true
		}
	}
	return false
}
