// Package elasticsearch emulates the REST API of an unauthenticated
// Elasticsearch 1.4 node on tcp/9200: the version range scanners probe for the
// dynamic-scripting RCEs (CVE-2014-3120 MVEL, CVE-2015-1427 Groovy). The node
// is a fresh single-node cluster without indices, so searches never return
// hits and no script output is ever expected. Scripts are recorded, never
// evaluated. The endpoint list follows elasticpot
// (gitlab.com/bontchev/elasticpot); the responses are written from the public
// Elasticsearch 1.x REST API, no code is copied. The package does no I/O.
package elasticsearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

const (
	// Port is the Elasticsearch HTTP port; every path there is the ES persona.
	Port = 9200

	version        = "1.4.2"
	buildHash      = "927caff6f05403e936c20bf4529f144f0c89fd8c"
	buildTimestamp = "2014-12-16T14:11:12Z"
	luceneVersion  = "4.10.2"

	maxScripts   = 8
	maxScript    = 4 << 10
	maxJSONDepth = 32
	maxName      = 256

	jsonType = "application/json; charset=UTF-8"
	textType = "text/plain; charset=UTF-8"
)

// Request is what a read on the ES port asked for.
type Request struct {
	Operation string   `json:"operation"`           // info, search, cat_indices, create_index, index_document, delete_index, ...
	Index     string   `json:"index,omitempty"`     // target index (or pattern) from the path
	Type      string   `json:"type,omitempty"`      // document type from the path
	ID        string   `json:"id,omitempty"`        // document id from the path
	Lang      string   `json:"lang,omitempty"`      // script language (groovy, mvel, ...)
	Scripts   []string `json:"scripts,omitempty"`   // script sources from the body or ?source=
	Truncated bool     `json:"truncated,omitempty"` // a script, name or script-count cap applied
}

// Identity is the per-process node persona.
type Identity struct {
	Cluster  string
	Name     string
	NodeID   string
	Hostname string
	IP       string
}

var (
	identityOnce sync.Once
	identity     Identity

	// newDocID returns auto-generated document IDs; tests swap it.
	newDocID = func() string { return randomID(20) }
	// took is the reported search time in ms; tests swap it.
	took = func() int { return 1 + mrand.IntN(9) } // #nosec G404 -- persona, not a secret
)

// Node returns the stable node identity: random per sensor, or set with
// elasticsearch.cluster_name / elasticsearch.node_name.
func Node() Identity {
	identityOnce.Do(func() {
		identity = Identity{
			Cluster:  viper.GetString("elasticsearch.cluster_name"),
			Name:     viper.GetString("elasticsearch.node_name"),
			NodeID:   randomID(22),
			Hostname: pick([]string{"es01", "es-node-1", "elastic01", "search01", "elk", "es-master"}),
			IP:       fmt.Sprintf("172.31.%d.%d", mrand.IntN(64), 2+mrand.IntN(250)), // #nosec G404
		}
		if identity.Cluster == "" {
			identity.Cluster = "elasticsearch"
		}
		if identity.Name == "" {
			// ES 1.x names a node after a random Marvel character
			identity.Name = pick([]string{"Bucky", "Blackheart", "Gravity", "Nightcrawler", "Meteorite", "Puck", "Tiger Shark", "Wraith", "Silver Samurai", "Cloud 9"})
		}
	})
	return identity
}

func pick(names []string) string {
	return names[mrand.IntN(len(names))] // #nosec G404 -- persona, not a secret
}

const idAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func randomID(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = idAlphabet[mrand.IntN(len(idAlphabet))] // #nosec G404
	}
	return string(b)
}

func capName(s string, truncated *bool) string {
	if len(s) > maxName {
		*truncated = true
		return s[:maxName]
	}
	return s
}

// Inspect classifies a request to the ES port. escapedPath is the path as
// sent; rawQuery feeds the ?source= search body. It never returns nil.
func Inspect(method, escapedPath, rawQuery string, body []byte) *Request {
	req := &Request{}
	path, err := url.PathUnescape(escapedPath)
	if err != nil {
		path = escapedPath
	}
	var segs []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	req.Operation = classify(method, segs, req)
	req.Index = capName(req.Index, &req.Truncated)
	req.Type = capName(req.Type, &req.Truncated)
	req.ID = capName(req.ID, &req.Truncated)

	if src := sourceParam(rawQuery); src != "" {
		req.collectScripts([]byte(src))
	}
	if len(bytes.TrimSpace(body)) > 0 {
		req.collectScripts(body)
	}
	return req
}

func sourceParam(rawQuery string) string {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	return q.Get("source")
}

func classify(method string, segs []string, req *Request) string {
	if len(segs) == 0 {
		return "info"
	}
	first := segs[0]
	if strings.HasPrefix(first, "_") && first != "_all" {
		switch first {
		case "_cat":
			if len(segs) == 1 {
				return "cat"
			}
			switch segs[1] {
			case "indices", "nodes", "aliases", "shards", "master", "plugins":
				if len(segs) > 2 {
					req.Index = segs[2]
				}
				return "cat_" + segs[1]
			}
		case "_cluster":
			if len(segs) > 1 && segs[1] == "health" {
				return "cluster_health"
			}
		case "_nodes":
			return "nodes"
		case "_search":
			return "search"
		case "_stats", "_mapping", "_settings", "_aliases", "_alias", "_count":
			return strings.TrimPrefix(first, "_")
		}
		return "unknown"
	}

	req.Index = first
	if len(segs) == 1 {
		switch method {
		case http.MethodPut, http.MethodPost:
			return "create_index"
		case http.MethodDelete:
			return "delete_index"
		}
		return "get_index"
	}
	second := segs[1]
	if strings.HasPrefix(second, "_") {
		switch second {
		case "_search", "_count":
			return strings.TrimPrefix(second, "_")
		case "_stats", "_mapping", "_settings", "_aliases", "_alias":
			return strings.TrimPrefix(second, "_")
		}
		return "unknown"
	}
	req.Type = second
	if len(segs) > 2 && !strings.HasPrefix(segs[2], "_") {
		req.ID = segs[2]
	}
	if len(segs) > 2 && strings.HasPrefix(segs[2], "_") {
		switch segs[2] {
		case "_search", "_count":
			return strings.TrimPrefix(segs[2], "_")
		}
		return "unknown"
	}
	switch method {
	case http.MethodPut, http.MethodPost:
		return "index_document"
	case http.MethodDelete:
		return "delete_document"
	}
	return "get_document"
}

// collectScripts records every "script" value (a string, or the
// script/inline/source field of a script object) and the first "lang" in a
// JSON body.
func (r *Request) collectScripts(data []byte) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return
	}
	r.walk(v, 0)
}

func (r *Request) walk(v any, depth int) {
	if depth > maxJSONDepth {
		r.Truncated = true
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			switch k {
			case "script":
				switch s := child.(type) {
				case string:
					r.addScript(s)
					continue
				case map[string]any:
					for _, f := range []string{"script", "inline", "source"} {
						if src, ok := s[f].(string); ok {
							r.addScript(src)
						}
					}
					r.setLang(s["lang"])
					continue
				}
			case "lang":
				if r.setLang(child) {
					continue
				}
			}
			r.walk(child, depth+1)
		}
	case []any:
		for _, child := range t {
			r.walk(child, depth+1)
		}
	}
}

func (r *Request) setLang(v any) bool {
	s, ok := v.(string)
	if ok && r.Lang == "" {
		r.Lang = capName(s, &r.Truncated)
	}
	return ok
}

func (r *Request) addScript(s string) {
	if len(r.Scripts) >= maxScripts {
		r.Truncated = true
		return
	}
	if len(s) > maxScript {
		s = s[:maxScript]
		r.Truncated = true
	}
	r.Scripts = append(r.Scripts, s)
}

// Respond builds the node's reply to a request classified by Inspect.
func Respond(method, escapedPath, rawQuery string, req *Request) []byte {
	q, _ := url.ParseQuery(rawQuery)
	pretty := q.Has("pretty") && q.Get("pretty") != "false"
	node := Node()
	head := method == http.MethodHead

	reply := func(status string, body any) []byte {
		data, err := json.Marshal(body)
		if err != nil {
			return response("500 Internal Server Error", textType, nil, head)
		}
		if pretty || req.Operation == "info" {
			data = append(jacksonIndent(data), '\n')
		}
		return response(status, jsonType, data, head)
	}
	missing := func() []byte {
		return reply("404 Not Found", errorBody{fmt.Sprintf("IndexMissingException[[%s] missing]", req.Index), 404})
	}
	wildcard := req.Index == "_all" || strings.Contains(req.Index, "*")

	switch req.Operation {
	case "info":
		if method != http.MethodGet && method != http.MethodHead {
			break
		}
		return reply("200 OK", infoBody{
			Status:      200,
			Name:        node.Name,
			ClusterName: node.Cluster,
			Version: versionBody{
				Number:         version,
				BuildHash:      buildHash,
				BuildTimestamp: buildTimestamp,
				LuceneVersion:  luceneVersion,
			},
			Tagline: "You Know, for Search",
		})
	case "cluster_health":
		return reply("200 OK", healthBody{ClusterName: node.Cluster, Status: "green", NumberOfNodes: 1, NumberOfDataNodes: 1})
	case "nodes":
		return reply("200 OK", map[string]any{
			"cluster_name": node.Cluster,
			"nodes": map[string]any{
				node.NodeID: map[string]any{
					"name":              node.Name,
					"transport_address": fmt.Sprintf("inet[/%s:9300]", node.IP),
					"host":              node.Hostname,
					"ip":                node.IP,
					"version":           version,
					"build":             buildHash[:7],
					"http_address":      fmt.Sprintf("inet[/%s:%d]", node.IP, Port),
				},
			},
		})
	case "search", "count":
		if req.Index != "" && !wildcard {
			return missing()
		}
		if req.Operation == "count" {
			return reply("200 OK", map[string]any{"count": 0, "_shards": shards{}})
		}
		return reply("200 OK", searchBody{Took: took(), Hits: hitsBody{Hits: []any{}}})
	case "stats":
		return reply("200 OK", map[string]any{
			"_shards": shards{},
			"_all":    map[string]any{"primaries": struct{}{}, "total": struct{}{}},
			"indices": struct{}{},
		})
	case "mapping", "settings", "aliases", "alias":
		if req.Index != "" && !wildcard {
			return missing()
		}
		return reply("200 OK", struct{}{})
	case "get_index", "get_document", "delete_document":
		return missing()
	case "delete_index":
		if wildcard {
			return reply("200 OK", map[string]bool{"acknowledged": true})
		}
		return missing()
	case "create_index":
		return reply("200 OK", map[string]bool{"acknowledged": true})
	case "index_document":
		id := req.ID
		if id == "" {
			id = newDocID()
		}
		return reply("201 Created", indexedBody{Index: req.Index, Type: req.Type, ID: id, Version: 1, Created: true})
	case "cat":
		return response("200 OK", textType, []byte("=^.^=\n/_cat/allocation\n/_cat/shards\n/_cat/master\n/_cat/nodes\n/_cat/indices\n/_cat/aliases\n/_cat/count\n/_cat/health\n/_cat/plugins\n"), head)
	case "cat_indices", "cat_aliases", "cat_shards", "cat_plugins":
		if req.Index != "" && !wildcard {
			return missing()
		}
		return catTable(q, head, catHeaders[req.Operation], nil)
	case "cat_nodes":
		return catTable(q, head, catHeaders["cat_nodes"], []string{node.Hostname, node.IP, "9", "61", "0.00", "d", "*", node.Name})
	case "cat_master":
		return catTable(q, head, catHeaders["cat_master"], []string{node.NodeID, node.Hostname, node.IP, node.Name})
	}
	return response("400 Bad Request", textType, []byte(fmt.Sprintf("No handler found for uri [%s] and method [%s]", escapedPath, method)), head)
}

var catHeaders = map[string][]string{
	"cat_indices": {"health", "status", "index", "pri", "rep", "docs.count", "docs.deleted", "store.size", "pri.store.size"},
	"cat_aliases": {"alias", "index", "filter", "routing.index", "routing.search"},
	"cat_shards":  {"index", "shard", "prirep", "state", "docs", "store", "ip", "node"},
	"cat_plugins": {"name", "component", "version", "type", "url"},
	"cat_nodes":   {"host", "ip", "heap.percent", "ram.percent", "load", "node.role", "master", "name"},
	"cat_master":  {"id", "host", "ip", "node"},
}

// catTable renders a _cat reply: space-aligned text (header with ?v), or a
// JSON array of objects with ?format=json.
func catTable(q url.Values, head bool, headers, row []string) []byte {
	if q.Get("format") == "json" {
		rows := []map[string]string{}
		if row != nil {
			obj := map[string]string{}
			for i, h := range headers {
				obj[h] = row[i]
			}
			rows = append(rows, obj)
		}
		data, _ := json.Marshal(rows)
		return response("200 OK", jsonType, data, head)
	}
	var lines [][]string
	if q.Has("v") && q.Get("v") != "false" {
		lines = append(lines, headers)
	}
	if row != nil {
		lines = append(lines, row)
	}
	widths := make([]int, len(headers))
	for _, l := range lines {
		for i, c := range l {
			widths[i] = max(widths[i], len(c))
		}
	}
	var b strings.Builder
	for _, l := range lines {
		for i, c := range l {
			b.WriteString(c)
			if i < len(l)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len(c)+1))
			}
		}
		b.WriteString(" \n")
	}
	return response("200 OK", textType, []byte(b.String()), head)
}

type versionBody struct {
	Number         string `json:"number"`
	BuildHash      string `json:"build_hash"`
	BuildTimestamp string `json:"build_timestamp"`
	BuildSnapshot  bool   `json:"build_snapshot"`
	LuceneVersion  string `json:"lucene_version"`
}

type infoBody struct {
	Status      int         `json:"status"`
	Name        string      `json:"name"`
	ClusterName string      `json:"cluster_name"`
	Version     versionBody `json:"version"`
	Tagline     string      `json:"tagline"`
}

type healthBody struct {
	ClusterName         string `json:"cluster_name"`
	Status              string `json:"status"`
	TimedOut            bool   `json:"timed_out"`
	NumberOfNodes       int    `json:"number_of_nodes"`
	NumberOfDataNodes   int    `json:"number_of_data_nodes"`
	ActivePrimaryShards int    `json:"active_primary_shards"`
	ActiveShards        int    `json:"active_shards"`
	RelocatingShards    int    `json:"relocating_shards"`
	InitializingShards  int    `json:"initializing_shards"`
	UnassignedShards    int    `json:"unassigned_shards"`
}

type shards struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

type hitsBody struct {
	Total    int   `json:"total"`
	MaxScore *int  `json:"max_score"`
	Hits     []any `json:"hits"`
}

type searchBody struct {
	Took     int      `json:"took"`
	TimedOut bool     `json:"timed_out"`
	Shards   shards   `json:"_shards"`
	Hits     hitsBody `json:"hits"`
}

type indexedBody struct {
	Index   string `json:"_index"`
	Type    string `json:"_type"`
	ID      string `json:"_id"`
	Version int    `json:"_version"`
	Created bool   `json:"created"`
}

type errorBody struct {
	Error  string `json:"error"`
	Status int    `json:"status"`
}

// response frames an ES 1.x reply: Content-Type and Content-Length only.
// HEAD gets the status with an empty body, as ES 1.x sends it.
func response(status, contentType string, body []byte, head bool) []byte {
	if head {
		body = nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	return append([]byte(b.String()), body...)
}

// jacksonIndent pretty-prints compact JSON the way ES's Jackson printer does:
// two-space indent, `"key" : value`, and `{ }` / `[ ]` for empty containers.
func jacksonIndent(compact []byte) []byte {
	var buf bytes.Buffer
	if err := json.Indent(&buf, compact, "", "  "); err != nil {
		return compact
	}
	in := buf.Bytes()
	out := make([]byte, 0, len(in)+len(in)/8)
	inString, escaped := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == ':':
			out = append(out, ' ', ':')
		case (c == '{' || c == '[') && i+1 < len(in) && (in[i+1] == '}' || in[i+1] == ']'):
			out = append(out, c, ' ')
		default:
			out = append(out, c)
		}
	}
	return out
}
