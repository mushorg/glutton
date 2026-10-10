package spicy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// package level regex to match conlen header in HTTP requests
var contentLenRE = regexp.MustCompile(`(?i)Content-Length:\s*(\d+)`)

// MaxHTTPBody is the abuse cap on Content-Length for Spicy HTTP reads.
const MaxHTTPBody = 1 << 20 // 1 MiB

// ReadHTTPMessage reads one HTTP request (headers + Content-Length body) from r.
// Partial bytes are returned alongside any error so the caller can still capture them.
func ReadHTTPMessage(r *bufio.Reader, maxBody int) ([]byte, error) {
	raw := make([]byte, 0, 4096)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			raw = append(raw, line...)
		}
		if err != nil {
			if len(raw) > 0 {
				return raw, err
			}
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}

	clen := 0
	if m := contentLenRE.FindSubmatch(raw); m != nil {
		clen, _ = strconv.Atoi(string(m[1]))
	}
	if clen < 0 || clen > maxBody {
		return raw, fmt.Errorf("Content-Length %d exceeds maximum %d", clen, maxBody)
	}
	if clen > 0 {
		body := make([]byte, clen)
		if _, err := io.ReadFull(r, body); err != nil {
			return raw, err
		}
		raw = append(raw, body...)
	}
	return raw, nil
}

// reads protocol-specific initial data from a network connection and
// returns the complete protocol message as a byte slice.
func ReadInitialBytes(protocol string, conn net.Conn) ([]byte, error) {
	switch protocol {

	case "http":
		return ReadHTTPMessage(bufio.NewReader(conn), MaxHTTPBody)

	case "dns":
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		l := int(binary.BigEndian.Uint16(lenBuf[:]))
		if l == 0 || l > 64*1024 {
			return nil, errors.New("suspicious DNS length")
		}
		p := make([]byte, l)
		_, err := io.ReadFull(conn, p)
		return p, err

	default:
		buf := make([]byte, 8192)
		n, err := conn.Read(buf)
		return buf[:n], err
	}
}

// converts a flat map with dot notation keys into a nested map structure.
// created initially as a Spicy helper to handle nested data structures
// currently unused, kept for potential future use
func NestedFromFlat(flat map[string]interface{}) map[string]interface{} {
	root := map[string]interface{}{}

	for k, v := range flat {
		cur := root
		parts := strings.Split(k, ".")

		for i, p := range parts {
			if b := strings.Index(p, "["); b != -1 {
				base := p[:b]
				e := strings.Index(p[b:], "]")
				idx, _ := strconv.Atoi(p[b+1 : b+e])

				slice, ok := cur[base].([]interface{})
				if !ok {
					slice = make([]interface{}, idx+1)
					cur[base] = slice
				} else if idx >= len(slice) {
					slice = append(slice, make([]interface{}, idx+1-len(slice))...)
					cur[base] = slice
				}

				if i == len(parts)-1 {
					slice[idx] = v
				} else {
					if slice[idx] == nil {
						slice[idx] = map[string]interface{}{}
					}
					cur, ok = slice[idx].(map[string]interface{})
					if !ok {
						return nil
					}
				}
			} else {
				if i == len(parts)-1 {
					cur[p] = v
				} else {
					if _, ok := cur[p]; !ok {
						cur[p] = map[string]interface{}{}
					}
					m, ok := cur[p].(map[string]interface{})
					if !ok {
						return nil
					}
					cur = m
				}
			}
		}
	}
	return root
}

// retrieves a string value from a nested map using a path with dot notation
// currently unused, kept for potential future use
func GetDeepStr(m map[string]interface{}, path ...string) string {
	for _, p := range path {
		parts := strings.Split(p, ".")
		cur := m
		for i, seg := range parts {
			v, ok := cur[seg]
			if !ok {
				break
			}
			if i == len(parts)-1 {
				if s, ok := v.(string); ok {
					return s
				}
			} else {
				if nxt, ok := v.(map[string]interface{}); ok {
					cur = nxt
				} else {
					break
				}
			}
		}
	}
	return ""
}
