package spicy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func ReadInitialBytes(protocol string, conn net.Conn) ([]byte, error) {
	switch protocol {

	case "http":
		r := bufio.NewReader(conn)
		raw := make([]byte, 0, 4096)

		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return nil, err
			}
			raw = append(raw, line...)
			if bytes.Equal(line, []byte("\r\n")) {
				break
			}
		}

		var clen int
		if m := regexp.MustCompile(`(?i)content-length:\s*(\d+)`).FindSubmatch(raw); m != nil {
			clen, _ = strconv.Atoi(string(m[1]))
		}

		if clen > 0 {
			body := make([]byte, clen)
			if _, err := io.ReadFull(r, body); err != nil {
				return nil, err
			}
			raw = append(raw, body...)
		}
		return raw, nil

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
					cur = slice[idx].(map[string]interface{})
				}
			} else {
				if i == len(parts)-1 {
					cur[p] = v
				} else {
					if _, ok := cur[p]; !ok {
						cur[p] = map[string]interface{}{}
					}
					cur = cur[p].(map[string]interface{})
				}
			}
		}
	}
	return root
}

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
