package producer

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mushorg/glutton/connection"

	"github.com/d1str0/hpfeeds"
	"github.com/spf13/viper"
)

const (
	httpTimeout = 10 * time.Second
	tlsTimeout  = 5 * time.Second
)

// Producer for the producer
type Producer struct {
	sensorID      string
	sensorVersion string
	httpClient    *http.Client
	hpfClient     hpfeeds.Client
	hpfChannel    chan []byte
}

// Event is a struct for glutton events
type Event struct {
	Timestamp     time.Time   `json:"timestamp,omitempty"`
	StartedAt     time.Time   `json:"startedAt,omitempty"`
	DurationMs    int64       `json:"durationMs,omitempty"`
	Transport     string      `json:"transport,omitempty"`
	SrcHost       string      `json:"srcHost,omitempty"`
	SrcPort       string      `json:"srcPort,omitempty"`
	SrcPtr        string      `json:"srcPtr,omitempty"`
	DstHost       string      `json:"dstHost,omitempty"`
	DstPort       uint16      `json:"dstPort,omitempty"`
	SensorID      string      `json:"sensorID,omitempty"`
	SensorVersion string      `json:"sensorVersion,omitempty"`
	Rule          string      `json:"rule,omitempty"`
	RuleName      string      `json:"ruleName,omitempty"`
	Handler       string      `json:"handler,omitempty"`
	Payload       string      `json:"payload,omitempty"`
	PayloadHash   string      `json:"payloadHash,omitempty"`
	FrameCount    int         `json:"frameCount,omitempty"`
	EndReason     string      `json:"endReason,omitempty"`
	Scanner       string      `json:"scanner,omitempty"`
	Decoded       interface{} `json:"decoded,omitempty"`
	TLS           *TLSInfo    `json:"tls,omitempty"`
}

// TLSInfo is set when the sensor terminated TLS before the handler ran.
type TLSInfo struct {
	ServerName  string   `json:"serverName,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Version     string   `json:"version,omitempty"`
	Cipher      string   `json:"cipher,omitempty"`
	ClientHello string   `json:"clientHello,omitempty"` // base64 of the raw ClientHello records
	Truncated   bool     `json:"truncated,omitempty"`
}

// New initializes the producers
func New(sensorID, sensorVersion string) (*Producer, error) {
	producer := &Producer{
		sensorID:      sensorID,
		sensorVersion: sensorVersion,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSHandshakeTimeout: tlsTimeout,
			},
			Timeout: httpTimeout,
		},
	}
	if viper.GetBool("producers.hpfeeds.enabled") {
		producer.hpfClient = hpfeeds.NewClient(
			viper.GetString("producers.hpfeeds.host"),
			viper.GetInt("producers.hpfeeds.port"),
			viper.GetString("producers.hpfeeds.ident"),
			viper.GetString("producers.hpfeeds.auth"),
		)
		if err := producer.hpfClient.Connect(); err != nil {
			return producer, err
		}
		producer.hpfChannel = make(chan []byte)
		producer.hpfClient.Publish(viper.GetString("producers.hpfeeds.channel"), producer.hpfChannel)
	}
	return producer, nil
}

// LogTCP is a meta caller for all producers
func (p *Producer) LogTCP(handler string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error {
	event, err := p.makeEventTCP(handler, conn, md, payload, decoded)
	if err != nil {
		return err
	}
	if viper.GetBool("producers.hpfeeds.enabled") {
		if err := p.logHPFeeds(event); err != nil {
			return err
		}
	}
	if viper.GetBool("producers.http.enabled") {
		if err := p.logHTTP(event); err != nil {
			return err
		}
	}
	return nil
}

// LogUDP is a meta caller for all producers
func (p *Producer) LogUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	event, err := p.makeEventUDP(handler, srcAddr, dstAddr, md, payload, decoded)
	if err != nil {
		return err
	}
	if viper.GetBool("producers.hpfeeds.enabled") {
		if err := p.logHPFeeds(event); err != nil {
			return err
		}
	}
	if viper.GetBool("producers.http.enabled") {
		if err := p.logHTTP(event); err != nil {
			return err
		}
	}
	return nil
}

// logHPFeeds logs an event to a hpfeeds broker
func (p *Producer) logHPFeeds(event *Event) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		return err
	}
	p.hpfChannel <- buf.Bytes()
	return nil
}

// Check if a ip is private.
func isPrivateIP(ip string) bool {
	ipAddress := net.ParseIP(ip)
	return ipAddress.IsPrivate()
}

// logHTTP send logs to HTTP endpoint
func (p *Producer) logHTTP(event *Event) error {
	if isPrivateIP(event.SrcHost) {
		return nil
	}
	url, err := url.Parse(viper.GetString("producers.http.remote"))
	if err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url.Scheme+"://"+url.Host+url.Path, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.URL.RawQuery = url.RawQuery
	if password, ok := url.User.Password(); ok {
		req.SetBasicAuth(url.User.Username(), password)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return redactURLError(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("http producer: %s %s: %s", req.Method, redactURL(req.URL), resp.Status)
	}
	return nil
}

// redactURL renders u without userinfo and with every query value replaced,
// so tokens in producers.http.remote never reach the logs.
func redactURL(u *url.URL) string {
	r := *u
	r.User = nil
	if q := r.Query(); len(q) > 0 {
		for k := range q {
			q[k] = []string{"REDACTED"}
		}
		r.RawQuery = q.Encode()
	}
	return r.String()
}

// redactURLError strips credentials from the URL that net/http embeds in
// *url.Error messages.
func redactURLError(err error) error {
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		return err
	}
	redacted := *uerr
	if u, perr := url.Parse(uerr.URL); perr == nil {
		redacted.URL = redactURL(u)
	} else {
		redacted.URL = "<redacted>"
	}
	return &redacted
}
