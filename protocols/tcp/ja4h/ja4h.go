// Package ja4h computes the FoxIO JA4H fingerprint of an HTTP request from
// its raw bytes. net/http drops header order, casing and cookie order, which
// the fingerprint depends on, so it works on the wire form.
package ja4h

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const empty = "000000000000"

// Fingerprint returns "a_b_c_d" for a raw HTTP request, or "" when raw does
// not start with a request line.
func Fingerprint(raw []byte) string {
	head := raw
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head = raw[:i]
	} else if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		head = raw[:i]
	}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	reqLine := strings.Fields(lines[0])
	if len(reqLine) < 2 {
		return ""
	}

	var names, cookies []string
	var cookieSet, referer bool
	var lang string
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(name) {
		case "cookie":
			cookieSet = true
			for _, c := range strings.Split(value, ";") {
				if c = strings.TrimSpace(c); c != "" {
					cookies = append(cookies, c)
				}
			}
			continue
		case "referer":
			referer = true
			continue
		case "accept-language":
			if lang == "" {
				lang = value
			}
		}
		names = append(names, name)
	}

	a := fmt.Sprintf("%s%s%s%s%02d%s", method(reqLine[0]), version(reqLine), flag(cookieSet, "c"), flag(referer, "r"), min(len(names), 99), language(lang))
	b := hash(strings.Join(names, ","), len(names) == 0)

	fields := make([]string, len(cookies))
	pairs := make([]string, len(cookies))
	for i, c := range cookies {
		fields[i], _, _ = strings.Cut(c, "=")
		pairs[i] = c
	}
	sort.Strings(fields)
	sort.Strings(pairs)
	return a + "_" + b + "_" + hash(strings.Join(fields, ","), len(cookies) == 0) + "_" + hash(strings.Join(pairs, ","), len(cookies) == 0)
}

func method(m string) string {
	m = strings.ToLower(m)
	if len(m) < 2 {
		return m + strings.Repeat("0", 2-len(m))
	}
	return m[:2]
}

func version(reqLine []string) string {
	if len(reqLine) >= 3 {
		switch strings.ToUpper(reqLine[len(reqLine)-1]) {
		case "HTTP/1.0":
			return "10"
		case "HTTP/1.1":
			return "11"
		case "HTTP/2", "HTTP/2.0":
			return "20"
		case "HTTP/3", "HTTP/3.0":
			return "30"
		}
	}
	return "00"
}

func flag(set bool, c string) string {
	if set {
		return c
	}
	return "n"
}

// language is the first four letters of the Accept-Language header, lowercase
// with punctuation removed and padded with zeros.
func language(v string) string {
	var out []byte
	for i := 0; i < len(v) && len(out) < 4; i++ {
		c := v[i]
		if c == ',' || c == ';' {
			break
		}
		if c == '-' || c == '_' || c == ' ' {
			continue
		}
		out = append(out, strings.ToLower(string(c))[0])
	}
	for len(out) < 4 {
		out = append(out, '0')
	}
	return string(out)
}

func hash(s string, none bool) string {
	if none {
		return empty
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
