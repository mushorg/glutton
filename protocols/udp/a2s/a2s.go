// Package a2s parses Valve Source Engine server queries (A2S) and builds the
// S2C_CHALLENGE reply. It never builds A2S_INFO/PLAYER/RULES data responses:
// those are larger than the request and turn a server into a UDP amplifier.
package a2s

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// HeaderLen is the simple (unsplit) packet header plus the request type byte.
const HeaderLen = 5

// ChallengeLen is the size of a challenge number on the wire.
const ChallengeLen = 4

// Request and response type bytes that follow the 0xFFFFFFFF header.
const (
	TypeInfo         byte = 0x54 // 'T' A2S_INFO
	TypePlayer       byte = 0x55 // 'U' A2S_PLAYER
	TypeRules        byte = 0x56 // 'V' A2S_RULES
	TypeGetChallenge byte = 0x57 // 'W' A2S_SERVERQUERY_GETCHALLENGE (deprecated)
	TypePing         byte = 0x69 // 'i' A2A_PING (deprecated)
	TypeChallenge    byte = 0x41 // 'A' S2C_CHALLENGE
)

// InfoQuery is the fixed A2S_INFO payload string.
const InfoQuery = "Source Engine Query"

var simpleHeader = []byte{0xff, 0xff, 0xff, 0xff}

var typeNames = map[byte]string{
	TypeInfo:         "A2S_INFO",
	TypePlayer:       "A2S_PLAYER",
	TypeRules:        "A2S_RULES",
	TypeGetChallenge: "A2S_SERVERQUERY_GETCHALLENGE",
	TypePing:         "A2A_PING",
	TypeChallenge:    "S2C_CHALLENGE",
}

// Name returns the request/response name for a type byte, or UNKNOWN.
func Name(t byte) string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return "UNKNOWN"
}

// LooksLikeA2S reports whether data starts with the simple header followed by
// a known client request type.
func LooksLikeA2S(data []byte) bool {
	if len(data) < HeaderLen || !bytes.HasPrefix(data, simpleHeader) {
		return false
	}
	switch data[4] {
	case TypeInfo, TypePlayer, TypeRules, TypeGetChallenge, TypePing:
		return true
	}
	return false
}

// Request is a parsed client query.
type Request struct {
	Type      byte
	Query     string // A2S_INFO payload string
	Challenge []byte // raw wire bytes; nil when the client sent none
}

// ChallengeHex returns the challenge as hex of its wire bytes, or "".
func (r Request) ChallengeHex() string {
	if r.Challenge == nil {
		return ""
	}
	return hex.EncodeToString(r.Challenge)
}

// WantsChallenge reports whether a real server would answer this request with
// S2C_CHALLENGE: A2S_INFO without a challenge, PLAYER/RULES with -1, and the
// deprecated GETCHALLENGE.
func (r Request) WantsChallenge() bool {
	switch r.Type {
	case TypeInfo:
		return r.Query == InfoQuery && r.Challenge == nil
	case TypePlayer, TypeRules:
		return bytes.Equal(r.Challenge, simpleHeader)
	case TypeGetChallenge:
		return true
	}
	return false
}

// Parse decodes a client query. On error the returned Request still carries
// whatever was decoded (the type byte once the header is present).
func Parse(data []byte) (Request, error) {
	if len(data) < HeaderLen {
		return Request{}, fmt.Errorf("shorter than A2S header: %d bytes", len(data))
	}
	if !bytes.HasPrefix(data, simpleHeader) {
		return Request{}, errors.New("missing simple packet header")
	}
	req := Request{Type: data[4]}
	body := data[HeaderLen:]
	switch req.Type {
	case TypeInfo:
		end := bytes.IndexByte(body, 0)
		if end < 0 {
			req.Query = string(body)
			return req, errors.New("unterminated A2S_INFO query string")
		}
		req.Query = string(body[:end])
		if rest := body[end+1:]; len(rest) >= ChallengeLen {
			req.Challenge = append([]byte{}, rest[:ChallengeLen]...)
		}
	case TypePlayer, TypeRules:
		if len(body) < ChallengeLen {
			return req, fmt.Errorf("truncated %s challenge", Name(req.Type))
		}
		req.Challenge = append([]byte{}, body[:ChallengeLen]...)
	case TypeGetChallenge, TypePing:
	default:
		return req, fmt.Errorf("unknown A2S request type 0x%02x", req.Type)
	}
	return req, nil
}

// BuildChallenge builds an S2C_CHALLENGE reply (9 bytes). The challenge is
// encoded little-endian, as Source servers do.
func BuildChallenge(challenge uint32) []byte {
	out := make([]byte, HeaderLen+ChallengeLen)
	copy(out, simpleHeader)
	out[4] = TypeChallenge
	binary.LittleEndian.PutUint32(out[HeaderLen:], challenge)
	return out
}
