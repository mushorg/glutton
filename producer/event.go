package producer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/scanner"
)

func payloadHash(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func sliceLen(v interface{}) int {
	if v == nil {
		return 0
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return 0
	}
	return rv.Len()
}

func dstHostFromConn(conn net.Conn, md connection.Metadata) string {
	if md.TargetIP != "" {
		return md.TargetIP
	}
	if conn == nil || conn.LocalAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func durationMs(added time.Time) int64 {
	if added.IsZero() {
		return 0
	}
	ms := time.Since(added).Milliseconds()
	if ms < 0 {
		return 0
	}
	return ms
}

func fillEnvelope(event *Event, md connection.Metadata, payload []byte, decoded interface{}, sensorVersion string) {
	event.SensorVersion = sensorVersion
	event.EndReason = md.EndReason
	event.PayloadHash = payloadHash(payload)
	if n := sliceLen(decoded); n > 0 {
		event.FrameCount = n
	}
	if !md.Added.IsZero() {
		event.StartedAt = md.Added.UTC()
		event.DurationMs = durationMs(md.Added)
	}
	if md.Rule != nil {
		event.Rule = md.Rule.String()
		event.RuleName = md.Rule.Name
	}
	if t := md.TLS; t != nil {
		event.TLS = &TLSInfo{
			ServerName:  t.ServerName,
			ALPN:        t.ALPN,
			Version:     t.Version,
			Cipher:      t.Cipher,
			ClientHello: base64.StdEncoding.EncodeToString(t.Hello),
			Truncated:   t.Truncated,
			JA3:         t.JA3,
			JA3N:        t.JA3N,
			JA4:         t.JA4,
			JA4R:        t.JA4R,
		}
	}
}

func (p *Producer) makeEventTCP(handler string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) (*Event, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	scannerName, srcPtr, err := scanner.Classify(net.ParseIP(host))
	if err != nil {
		return nil, err
	}

	event := Event{
		Timestamp: time.Now().UTC(),
		Transport: "tcp",
		SrcHost:   host,
		SrcPort:   port,
		SrcPtr:    srcPtr,
		DstHost:   dstHostFromConn(conn, md),
		DstPort:   uint16(md.TargetPort),
		SensorID:  p.sensorID,
		Handler:   handler,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Scanner:   scannerName,
		Decoded:   decoded,
	}
	fillEnvelope(&event, md, payload, decoded, p.sensorVersion)
	return &event, nil
}

func (p *Producer) makeEventUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) (*Event, error) {
	srcIP := srcAddr.IP.String()
	scannerName, srcPtr, err := scanner.Classify(net.ParseIP(srcIP))
	if err != nil {
		return nil, err
	}

	dstHost := md.TargetIP
	if dstHost == "" && dstAddr != nil {
		dstHost = dstAddr.IP.String()
	}

	event := Event{
		Timestamp: time.Now().UTC(),
		Transport: "udp",
		SrcHost:   srcIP,
		SrcPort:   strconv.Itoa(int(srcAddr.AddrPort().Port())),
		SrcPtr:    srcPtr,
		DstHost:   dstHost,
		DstPort:   uint16(md.TargetPort),
		SensorID:  p.sensorID,
		Handler:   handler,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Scanner:   scannerName,
		Decoded:   decoded,
	}
	fillEnvelope(&event, md, payload, decoded, p.sensorVersion)
	return &event, nil
}
