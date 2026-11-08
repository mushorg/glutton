package helpers

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// MaxSampleBytes caps the bytes kept from one fetched sample.
const MaxSampleBytes = 10 << 20

// SampleFetchSlots bounds sample downloads in flight across all handlers
// (each may buffer MaxSampleBytes). Acquire a slot with a non-blocking send
// and skip the download when the channel is full.
var SampleFetchSlots = make(chan struct{}, 32)

// ErrSampleAddress is returned when a sample URL resolves to an address that
// is not a public unicast address (loopback, private, link-local, ...).
var ErrSampleAddress = errors.New("sample host is not a public address")

// DownloadURL extracts the first http(s) URL from a wget/curl shell line.
func DownloadURL(line string) (string, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "wget") && !strings.Contains(lower, "curl") {
		return "", false
	}
	idx := strings.Index(lower, "http://")
	if idx < 0 {
		idx = strings.Index(lower, "https://")
	}
	if idx < 0 {
		return "", false
	}
	url := line[idx:]
	if end := strings.IndexAny(url, " \t\r\n;|&\"'`)"); end >= 0 {
		url = url[:end]
	}
	if url == "" {
		return "", false
	}
	return url, true
}

// FetchSample downloads url with client, keeps at most MaxSampleBytes, stores
// the body under samples/ and returns its SHA-256.
func FetchSample(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch sample: " + resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxSampleBytes))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("empty response body")
	}
	hash, err := Store(data, "samples")
	if err != nil {
		return "", err
	}
	if hash == "" {
		hash = SHA256Hex(data)
	}
	return hash, nil
}

// PublicSampleClient returns an HTTP client for fetching samples named by
// unauthenticated (spoofable) traffic: it only connects to public unicast
// addresses, checked after DNS resolution and on every redirect, so a forged
// request cannot point the sensor at loopback, its LAN or cloud metadata.
func PublicSampleClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !PublicAddr(addr) {
				return fmt.Errorf("%w: %s", ErrSampleAddress, addr)
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// PublicAddr reports whether addr is a globally routable unicast address.
func PublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddrSpace.Contains(addr)
}

// sharedAddrSpace is RFC 6598 carrier-grade NAT space, which IsPrivate omits.
var sharedAddrSpace = netip.MustParsePrefix("100.64.0.0/10")
