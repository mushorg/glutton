package banners

import "bytes"

// iperf3 (default tcp/5201) is client-first: the client opens the control
// connection with a 37-byte cookie (COOKIE_SIZE in iperf_api.h; the real
// client sends 36 characters of [a-z2-7] plus a NUL), and the server answers
// with the one-byte test state PARAM_EXCHANGE (9) before reading the
// length-prefixed JSON parameters. nmap's iperf3 probe (seen from Shodan on
// tcp/5201, 2026-11-12) sends 37 ASCII '0's followed by a zero parameter
// length (00 00 00 00). nmap match: iperf3 m|^\t$|.

const iperf3CookieSize = 37

// iperf3ParamExchange is the PARAM_EXCHANGE state byte.
var iperf3ParamExchange = []byte{0x09}

// isIperf3Cookie reports whether data is an iperf3 control cookie, optionally
// followed by the 4-byte big-endian parameter length when that is zero (as
// nmap sends it).
func isIperf3Cookie(data []byte) bool {
	switch len(data) {
	case iperf3CookieSize:
	case iperf3CookieSize + 4:
		if !bytes.Equal(data[iperf3CookieSize:], []byte{0, 0, 0, 0}) {
			return false
		}
	default:
		return false
	}
	for _, c := range data[:iperf3CookieSize-1] {
		if !isAlnum(c) {
			return false
		}
	}
	last := data[iperf3CookieSize-1]
	return last == 0 || isAlnum(last)
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// iperf3Reply answers the cookie with PARAM_EXCHANGE.
func iperf3Reply(data []byte) (Response, bool) {
	if !isIperf3Cookie(data) {
		return Response{}, false
	}
	return Response{Name: "iperf3-param-exchange", Data: iperf3ParamExchange}, true
}
