package udp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	maxRequestCount = 3
	throttleSeconds = int64(60)
)

type throttleState struct {
	count int
	last  int64
}

var throttle = map[string]throttleState{}

func cleanupThrottle() {
	for ip, state := range throttle {
		if state.last+throttleSeconds < time.Now().Unix() {
			delete(throttle, ip)
		}
	}
}

func shouldThrottle(ip string) bool {
	defer func() { go cleanupThrottle() }()
	if _, ok := throttle[ip]; ok {
		if throttle[ip].count > maxRequestCount {
			if throttle[ip].last+throttleSeconds > time.Now().Unix() {
				return true
			}
			throttle[ip] = throttleState{count: 1, last: time.Now().Unix()}
			return false
		}
		throttle[ip] = throttleState{count: throttle[ip].count + 1, last: time.Now().Unix()}
		return false
	}
	throttle[ip] = throttleState{count: 1, last: time.Now().Unix()}
	return false
}

// HandleDNS handles DNS packets
func HandleDNS(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) ([]byte, error) {
	if shouldThrottle(srcAddr.IP.String()) {
		return nil, fmt.Errorf("throttling DNS requests")
	}
	var p dnsmessage.Parser
	if _, err := p.Start(data); err != nil {
		return nil, fmt.Errorf("failed to parse DNS query: %w", err)
	}

	questions, err := p.AllQuestions()
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS questions: %w", err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
	}

	for _, q := range questions {
		msg.Questions = append(msg.Questions, q)
		name, err := dnsmessage.NewName(q.Name.String())
		if err != nil {
			return nil, err
		}

		answer := dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  q.Type,
				Class: q.Class,
				TTL:   453,
			},
		}

		switch q.Type {
		case dnsmessage.TypeA:
			answer.Body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
		case dnsmessage.TypeAAAA:
			answer.Body = &dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}}
		case dnsmessage.TypeCNAME:
			answer.Body = &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("localhost")}
		case dnsmessage.TypeNS:
			answer.Body = &dnsmessage.NSResource{NS: dnsmessage.MustNewName("localhost")}
		case dnsmessage.TypePTR:
			answer.Body = &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("localhost")}
		case dnsmessage.TypeTXT:
			answer.Body = &dnsmessage.TXTResource{TXT: []string{"localhost"}}
		}
		msg.Answers = append(msg.Answers, answer)
	}

	buf, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS response: %w", err)
	}

	if err := h.ProduceUDP("dns", srcAddr, dstAddr, md, data[:len(data)%1024], nil); err != nil {
		log.Error("failed to produce DNS payload", producer.ErrAttr(err))
		return nil, err
	}
	return buf, nil
}
