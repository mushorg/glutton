package banners

import "bytes"

// dnsQueryProbe is a malformed request line Shodan sends (tcp/444,
// 143.110.239.2, srcPtr buffet.census.shodan.io): the version before the
// method, a "/dns?" path with no query, and a trailing NUL instead of CRLF.
// The service it looks for is unidentified (no nmap match), so the catch-all
// stays silent instead of answering with random bytes no real service sends.
var dnsQueryProbe = []byte("HTTP/1.1 GET /dns?")

// isDNSQueryProbe reports whether data is exactly the probe, with or without
// its trailing NUL.
func isDNSQueryProbe(data []byte) bool {
	rest, ok := bytes.CutPrefix(data, dnsQueryProbe)
	return ok && (len(rest) == 0 || (len(rest) == 1 && rest[0] == 0))
}
