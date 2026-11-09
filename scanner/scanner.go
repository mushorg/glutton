package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	scannerSubnet = map[string][]string{
		"censys": {
			"162.142.125.0/24",
			"167.94.138.0/24",
			"167.94.145.0/24",
			"167.94.146.0/24",
			"167.248.133.0/24",
		},
		"shadowserver": {
			"64.62.202.96/27",
			"66.220.23.112/29",
			"74.82.47.0/26",
			"184.105.139.64/26",
			"184.105.143.128/26",
			"184.105.247.192/26",
			"216.218.206.64/26",
			"141.212.0.0/16",
		},
		"PAN Expanse": {
			"144.86.173.0/24",
		},
		"rwth": {
			"137.226.113.0/26",
		},
		"ruhr-uni-bochum.de": {
			"195.37.190.64/27",
		},
		"driftnet.io": {
			"87.236.176.0/24",
			"185.247.137.0/24",
			"193.163.125.0/24",
			"195.96.139.0/24",
			"45.55.151.3/32",
			"45.55.153.86/32",
			"45.55.158.168/32",
			"45.55.185.224/32",
			"45.55.186.92/32",
			"64.227.99.138/32",
			"64.227.108.146/32",
			"64.227.109.89/32",
			"64.227.110.161/32",
			"107.170.65.169/32",
			"128.199.8.140/32",
			"157.245.243.118/32",
			"157.245.245.246/32",
			"159.65.216.50/32",
			"159.65.219.252/32",
			"162.243.114.171/32",
			"162.243.116.182/32",
			"162.243.208.127/32",
			"167.99.234.119/32",
			"192.241.179.235/32",
			"2a06:4880::/29",
			"2604:a880:0:202a::b41:8000/124",
			"2604:a880:0:202a::b41:a000/124",
			"2604:a880:0:202a::b41:b000/124",
			"2604:a880:0:202a::b42:d000/124",
			"2604:a880:0:202a::b42:e000/124",
			"2604:a880:4:1d0::2fa6:a000/124",
			"2604:a880:4:1d0::2fa6:b000/124",
			"2604:a880:4:1d0::2fa6:c000/124",
			"2604:a880:4:1d0::2fa6:d000/124",
			"2604:a880:4:1d0::2fa6:e000/124",
			"2604:a880:400:d1::91e4:a000/124",
			"2604:a880:400:d1::91e4:b000/124",
			"2604:a880:400:d1::91e4:c000/124",
			"2604:a880:400:d1::91e4:d000/124",
			"2604:a880:400:d1::91e4:e000/124",
			"2604:a880:800:14::5633:8000/124",
			"2604:a880:800:14::5633:9000/124",
			"2604:a880:800:14::5633:a000/124",
			"2604:a880:800:14::5633:b000/124",
			"2604:a880:800:14::5633:c000/124",
		},
		// SHODAN-01, allocated directly to Shodan, LLC; its hosts do not
		// always carry a *.shodan.io PTR, so the PTR check alone misses them
		"shodan": {
			"207.90.244.0/24",
		},
	}
)

// Classify reports a known scanner label (if any) and the first PTR name.
// CIDR matches do not trigger DNS. PTR lookup runs only when the IP is not
// in a known scanner prefix, matching IsScanner.
func Classify(ip net.IP) (scannerName, srcPtr string, err error) {
	if ip == nil {
		return "", "", nil
	}
	for scanner, subnets := range scannerSubnet {
		for _, subnet := range subnets {
			_, network, err := net.ParseCIDR(subnet)
			if err != nil {
				return "", "", err
			}
			if network.Contains(ip) {
				return scanner, "", nil
			}
		}
	}
	names := lookupPTR(ip.String())
	if len(names) > 0 {
		srcPtr = strings.TrimSuffix(names[0], ".")
	}
	for _, name := range names {
		if strings.HasSuffix(name, "shodan.io.") {
			return "shodan", srcPtr, nil
		}
		if strings.HasSuffix(name, "binaryedge.ninja.") {
			return "binaryedge", srcPtr, nil
		}
		if strings.HasSuffix(name, "rwth-aachen.de.") {
			return "rwth", srcPtr, nil
		}
		if strings.HasSuffix(name, "shadowserver.io.") {
			return "shadowserver", srcPtr, nil
		}
		if strings.HasSuffix(name, "censys.io.") || strings.HasSuffix(name, "censys-scanner.com.") {
			return "censys", srcPtr, nil
		}
		if strings.HasSuffix(name, "infrawat.ch.") {
			return "infrawatch", srcPtr, nil
		}
		if strings.HasSuffix(name, "onyphe.net.") {
			return "onyphe", srcPtr, nil
		}
		if strings.HasSuffix(name, "criminalip.com.") {
			return "criminalip", srcPtr, nil
		}
		if strings.HasSuffix(name, "internet-census.org.") {
			return "internet-census", srcPtr, nil
		}
	}
	return "", srcPtr, nil
}

const (
	// ptrTimeout bounds one PTR lookup, which runs while the handler still
	// holds the attacker's connection.
	ptrTimeout = 2 * time.Second
	// ptrTTL keeps answers so a flood from one source costs one lookup;
	// ptrFailTTL is shorter so a resolver outage is retried soon.
	ptrTTL     = 10 * time.Minute
	ptrFailTTL = time.Minute
	ptrMax     = 65536
)

// lookupAddr is the PTR resolver; a var so tests do not touch DNS.
var lookupAddr = net.DefaultResolver.LookupAddr

type ptrEntry struct {
	names   []string
	expires time.Time     // zero while the lookup runs
	done    chan struct{} // closed when names and expires are set
}

var ptrCache = struct {
	sync.Mutex
	entries map[string]*ptrEntry
}{entries: map[string]*ptrEntry{}}

// lookupPTR returns the PTR names for ip, cached. Concurrent calls for the
// same ip share one lookup; failures cache as no names.
func lookupPTR(ip string) []string {
	now := time.Now()
	ptrCache.Lock()
	if e, ok := ptrCache.entries[ip]; ok && (e.expires.IsZero() || now.Before(e.expires)) {
		ptrCache.Unlock()
		<-e.done
		return e.names
	}
	if len(ptrCache.entries) >= ptrMax {
		for k, e := range ptrCache.entries {
			if !e.expires.IsZero() && now.After(e.expires) {
				delete(ptrCache.entries, k)
			}
		}
		if len(ptrCache.entries) >= ptrMax {
			ptrCache.entries = map[string]*ptrEntry{}
		}
	}
	e := &ptrEntry{done: make(chan struct{})}
	ptrCache.entries[ip] = e
	ptrCache.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), ptrTimeout)
	names, err := lookupAddr(ctx, ip)
	cancel()
	ttl := ptrTTL
	if err != nil {
		names, ttl = nil, ptrFailTTL
	}
	ptrCache.Lock()
	e.names = names
	e.expires = time.Now().Add(ttl)
	ptrCache.Unlock()
	close(e.done)
	return names
}

func IsScanner(ip net.IP) (bool, string, error) {
	name, _, err := Classify(ip)
	if err != nil {
		return false, "", err
	}
	return name != "", name, nil
}

// payloadFleets labels scanner fleets that are recognized by what they send
// rather than where they come from, keyed by handler and the SHA-256 of the
// event's top-level payload. These are behavioral labels, not attributions.
var payloadFleets = map[string]map[string]string{
	// X.224 CR without cookie, requesting TLS|CredSSP|EarlyAuth, followed by an
	// SPNEGO NTLM login for Administrator (Ochi 9f62fb02, f28ba1c0).
	"rdp": {
		"0003c8efa0acdc0c6540f4bdb920f6bcabdd01d0ed98e0f21938144c44e121a5": "rdp-nla-prober",
	},
	// SOCKS4 CONNECT to 167.235.123.162:24001, then a pipelined flood of one
	// absolute-URI GET with a Chrome/3.0.196.2 user agent (Ochi f87615a7).
	// The hash covers the CONNECT request, so it matches only this target.
	"socks": {
		"b211715c04660f10841bbd1315b6ca7a4f4c755d1127f5c59d7122ae51a6eb13": "socks-http-flood",
	},
}

// ClassifyPayload returns the fleet label for a handler and payload hash, or "".
func ClassifyPayload(handler, payloadHash string) string {
	return payloadFleets[handler][payloadHash]
}

// tlsFleets labels scanner fleets by the JA4 of the ClientHello the sensor
// terminated, keyed by handler, for fleets whose payload varies per target.
// JA4 sorts ciphers and extensions, so it survives the reordering that breaks
// JA3. These are behavioral labels, not attributions.
var tlsFleets = map[string]map[string]string{
	// SOCKS4 CONNECT to Cloudflare edge IPs on 443 from 149.86.227.0/24, then
	// TLS 1.2 (SNI just-play1.top, www.detikindonesia.co.id) carrying one
	// GET /qwe or bodiless POST /xmlrpc.php per connection with randomized
	// user agent and sec-ch-ua (Ochi stream 2026-10-24, 133 sessions in 26s).
	"socks": {
		"t12d320800_a6df2e0e78d0_36cef8aed422": "socks-https-flood",
	},
	// X.224 Connection Request with Cookie: mstshash=rdp-async offering
	// TLS|CredSSP|EarlyAuth, then this TLS 1.2 ClientHello (no SNI) and a reset
	// after the handshake. Four sources on tcp/23389 (2026-11-08) and again on
	// 2026-11-09, all with the same CR payload hash c880c8cb.
	"rdp": {
		"t12i210600_76e208dd3e22_f28add8e7af0": "rdp-async-cookie-fleet",
		// X.224 Connection Request with Cookie: mstshash=test (or hello), then
		// this TLS 1.3 ClientHello (no SNI, no ALPN) and an NTLMSSP Negotiate,
		// closing or resetting within ~60-300 ms. Same CR payload hash df88d953
		// on tcp/3369, 3379, 3384, 9898, 9989, 23389 and 33896-33899 from
		// several sources (2026-11-09).
		"t13i251000_b78ed14e2fd0_ab7e3b40a677": "rdp-tls-sweep",
	},
}

// ClassifyTLS returns the fleet label for a handler and JA4 fingerprint, or "".
func ClassifyTLS(handler, ja4 string) string {
	return tlsFleets[handler][ja4]
}
