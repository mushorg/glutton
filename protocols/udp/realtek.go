package udp

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/realtek"
)

const (
	maxRealtekPayload = 1024
	// maxRealtekFetches caps sample downloads per datagram.
	maxRealtekFetches = 2
	// realtekFetchTTL is how long a fetched (or attempted) URL is not fetched
	// again, so a flood of forged datagrams costs one download per URL.
	realtekFetchTTL     = time.Hour
	maxRealtekFetchURLs = 4096
	realtekFetchTimeout = 5 * time.Second
)

type parsedRealtek struct {
	Direction string   `json:"direction,omitempty"`
	Command   string   `json:"command,omitempty"` // "orf" for an MP daemon command
	Shell     string   `json:"shell,omitempty"`   // injected shell command
	Path      string   `json:"path,omitempty"`    // first download URL
	URLs      []string `json:"urls,omitempty"`    // every download URL in Shell
	// SampleHashes maps a fetched URL to the SHA-256 of the sample stored
	// under samples/ (only with realtek.fetch_samples).
	SampleHashes map[string]string `json:"sample_hashes,omitempty"`
	PayloadHash  string            `json:"payload_hash,omitempty"`
	Payload      []byte            `json:"payload,omitempty"`
	Truncated    bool              `json:"truncated,omitempty"`
}

// realtekFetch downloads and stores one sample; tests replace it.
var realtekFetch = func() func(string) (string, error) {
	client := helpers.PublicSampleClient(realtekFetchTimeout)
	return func(u string) (string, error) { return helpers.FetchSample(client, u) }
}()

// realtekNow is the dedupe clock; tests replace it.
var realtekNow = time.Now

// realtekFetchCache remembers recently fetched URLs and their sample hashes.
type realtekFetchCache struct {
	mu sync.Mutex
	m  map[string]realtekFetchEntry
}

type realtekFetchEntry struct {
	at   time.Time
	hash string // empty while in flight or when the fetch failed
}

var realtekFetched = &realtekFetchCache{m: map[string]realtekFetchEntry{}}

// claim reports whether u should be fetched now and, if not, the hash of an
// earlier fetch. A claimed URL counts as fetched until its TTL ends.
func (c *realtekFetchCache) claim(u string, now time.Time) (fetch bool, hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[u]; ok && now.Sub(e.at) < realtekFetchTTL {
		return false, e.hash
	}
	if len(c.m) >= maxRealtekFetchURLs {
		for k, e := range c.m {
			if now.Sub(e.at) >= realtekFetchTTL {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxRealtekFetchURLs {
			return false, ""
		}
	}
	c.m[u] = realtekFetchEntry{at: now}
	return true, ""
}

func (c *realtekFetchCache) done(u, hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[u]; ok {
		e.hash = hash
		c.m[u] = e
	}
}

// release forgets a claimed URL that was not fetched, so a later datagram
// may fetch it.
func (c *realtekFetchCache) release(u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, u)
}

// fetchableSample reports whether u is an http(s) URL the handler may fetch.
func fetchableSample(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

// fetchRealtekSamples downloads up to maxRealtekFetches http(s) URLs and
// returns url -> sample hash. It runs synchronously in the datagram's
// goroutine (bounded by realtekFetchTimeout per URL), so the hashes land in
// the event; URLs fetched within realtekFetchTTL reuse the earlier hash.
func fetchRealtekSamples(urls []string, src string, logger interfaces.Logger) map[string]string {
	hashes := map[string]string{}
	fetches := 0
	for _, u := range urls {
		if !fetchableSample(u) {
			continue
		}
		fetch, hash := realtekFetched.claim(u, realtekNow())
		if !fetch {
			if hash != "" {
				hashes[u] = hash
			}
			continue
		}
		if fetches >= maxRealtekFetches {
			realtekFetched.release(u)
			continue
		}
		select {
		case helpers.SampleFetchSlots <- struct{}{}:
		default:
			realtekFetched.release(u)
			logger.Debug("Skipping sample fetch, too many in flight", slog.String("protocol", "realtek"), slog.String("source", u))
			continue
		}
		fetches++
		hash, err := realtekFetch(u)
		<-helpers.SampleFetchSlots
		realtekFetched.done(u, hash)
		if err != nil {
			logger.Debug("Failed to get sample", slog.String("protocol", "realtek"), slog.String("source", u), producer.ErrAttr(err))
			continue
		}
		hashes[u] = hash
		logger.Info("New sample fetched",
			slog.String("handler", "realtek"),
			slog.String("src_ip", src),
			slog.String("sample_hash", hash),
			slog.String("source", u),
		)
	}
	if len(hashes) == 0 {
		return nil
	}
	return hashes
}

// HandleRealtek records Realtek Jungle SDK MP daemon (UDPServer, udp/9034)
// commands, the "orf;<shell>" injection of CVE-2021-35394. It never replies.
// With realtek.fetch_samples it downloads the http(s) URLs the injected
// command fetches into samples/.
func HandleRealtek(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxRealtekPayload))
	copy(payload, data[:len(payload)])

	events := []parsedRealtek{}
	defer func() {
		md.EndReason = connection.EndHandlerClose
		if err := h.ProduceUDP("realtek", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedRealtek](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "realtek"), producer.ErrAttr(err))
		}
	}()

	frame := parsedRealtek{
		Direction: "read",
		Payload:   payload,
		Truncated: len(data) > maxRealtekPayload,
	}
	if len(payload) > 0 {
		frame.PayloadHash = helpers.SHA256Hex(payload)
	}
	if realtek.LooksLikeRealtekMP(payload) {
		req := realtek.Parse(payload)
		frame.Command = realtek.Prefix
		frame.Shell = req.Shell
		frame.URLs = req.URLs
		if len(req.URLs) > 0 {
			frame.Path = req.URLs[0]
		}
	}

	logger.Info("Realtek MP daemon command received",
		slog.String("handler", "realtek"),
		slog.String("protocol", "realtek"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("path", frame.Path),
	)

	if len(frame.URLs) > 0 && viper.GetBool("realtek.fetch_samples") {
		frame.SampleHashes = fetchRealtekSamples(frame.URLs, srcAddr.IP.String(), logger)
	}
	events = append(events, frame)
	return nil
}
