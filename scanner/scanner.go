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
}

// ClassifyTLS returns the fleet label for a handler and JA4 fingerprint, or "".
func ClassifyTLS(handler, ja4 string) string {
	return tlsFleets[handler][ja4]
}
