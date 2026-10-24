package elasticsearch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Synthetic probes in the shape of the public CVE-2014-3120 (MVEL) and
// CVE-2015-1427 (Groovy) scanners.
const (
	mvelProbe   = `{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"command":{"script":"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"}}}`
	groovyProbe = `{"size":1,"script_fields":{"lupin":{"lang":"groovy","script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}`
)

func parseResponse(t *testing.T, raw []byte, method string) (*http.Response, string) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), &http.Request{Method: method})
	require.NoError(t, err)
	var body bytes.Buffer
	_, err = body.ReadFrom(resp.Body)
	require.NoError(t, err)
	return resp, body.String()
}

func TestInspectClassify(t *testing.T) {
	tests := []struct {
		method, path       string
		op, index, typ, id string
	}{
		{"GET", "/", "info", "", "", ""},
		{"HEAD", "/", "info", "", "", ""},
		{"GET", "/_cat/indices", "cat_indices", "", "", ""},
		{"GET", "/_cat/indices/abc", "cat_indices", "abc", "", ""},
		{"GET", "/_cat/nodes", "cat_nodes", "", "", ""},
		{"GET", "/_cat", "cat", "", "", ""},
		{"GET", "/_cluster/health", "cluster_health", "", "", ""},
		{"GET", "/_cluster/state", "unknown", "", "", ""},
		{"GET", "/_nodes/stats", "nodes", "", "", ""},
		{"POST", "/_search", "search", "", "", ""},
		{"GET", "/%2A/_alias", "alias", "*", "", ""},
		{"GET", "/_all/_search", "search", "_all", "", ""},
		{"GET", "/website/_search", "search", "website", "", ""},
		{"GET", "/website/blog/_search", "search", "website", "blog", ""},
		{"PUT", "/read_me", "create_index", "read_me", "", ""},
		{"DELETE", "/customers", "delete_index", "customers", "", ""},
		{"POST", "/read_me/_doc", "unknown", "read_me", "", ""},
		{"POST", "/website/blog/", "index_document", "website", "blog", ""},
		{"PUT", "/read_me/howtorecover/1", "index_document", "read_me", "howtorecover", "1"},
		{"GET", "/website/blog/1", "get_document", "website", "blog", "1"},
		{"DELETE", "/website/blog/1", "delete_document", "website", "blog", "1"},
		{"GET", "/.env", "get_index", ".env", "", ""},
		{"GET", "/_plugin/head", "unknown", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := Inspect(tt.method, tt.path, "", nil)
			require.Equal(t, tt.op, req.Operation)
			require.Equal(t, tt.index, req.Index)
			require.Equal(t, tt.typ, req.Type)
			require.Equal(t, tt.id, req.ID)
			require.Empty(t, req.Scripts)
			require.False(t, req.Truncated)
		})
	}
}

func TestInspectScripts(t *testing.T) {
	req := Inspect("POST", "/_search", "pretty", []byte(mvelProbe))
	require.Equal(t, "search", req.Operation)
	require.Equal(t, []string{`import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec("id").getInputStream()).useDelimiter("\\A").next();`}, req.Scripts)
	require.Empty(t, req.Lang)

	req = Inspect("POST", "/_search", "", []byte(groovyProbe))
	require.Equal(t, "groovy", req.Lang)
	require.Equal(t, []string{`java.lang.Math.class.forName("java.lang.Runtime").getRuntime().exec("id").getText()`}, req.Scripts)

	// GET with the body in ?source=
	req = Inspect("GET", "/_search", "source="+strings.ReplaceAll(groovyProbe, "\"", "%22"), nil)
	require.Equal(t, "groovy", req.Lang)
	require.Len(t, req.Scripts, 1)

	// script objects (ES 1.x "script":{"script":..}, later "inline"/"source")
	req = Inspect("POST", "/_search", "", []byte(`{"query":{"filtered":{"filter":{"script":{"script":"a","lang":"mvel"}}}},"sort":{"_script":{"script":{"inline":"b"}}}}`))
	require.ElementsMatch(t, []string{"a", "b"}, req.Scripts)
	require.Equal(t, "mvel", req.Lang)

	// a document field named source is data, not a script
	req = Inspect("PUT", "/read_me/howtorecover/1", "", []byte(`{"source":"backup","message":"send 0.01 BTC"}`))
	require.Empty(t, req.Scripts)

	// not JSON
	req = Inspect("POST", "/_search", "", []byte("script=id"))
	require.Empty(t, req.Scripts)
}

func TestInspectCaps(t *testing.T) {
	long := strings.Repeat("x", maxScript+10)
	req := Inspect("POST", "/_search", "", []byte(`{"script_fields":{"a":{"script":"`+long+`"}}}`))
	require.True(t, req.Truncated)
	require.Len(t, req.Scripts[0], maxScript)

	var fields []string
	for i := 0; i < maxScripts+3; i++ {
		fields = append(fields, `"f`+strings.Repeat("a", i+1)+`":{"script":"s"}`)
	}
	req = Inspect("POST", "/_search", "", []byte(`{"script_fields":{`+strings.Join(fields, ",")+`}}`))
	require.True(t, req.Truncated)
	require.Len(t, req.Scripts, maxScripts)

	deep := strings.Repeat(`{"a":`, maxJSONDepth+5) + `{"script":"deep"}` + strings.Repeat("}", maxJSONDepth+5)
	req = Inspect("POST", "/_search", "", []byte(deep))
	require.True(t, req.Truncated)
	require.Empty(t, req.Scripts)

	req = Inspect("PUT", "/"+strings.Repeat("i", maxName+1), "", nil)
	require.True(t, req.Truncated)
	require.Len(t, req.Index, maxName)
}

func TestRespondInfo(t *testing.T) {
	raw := Respond("GET", "/", "", Inspect("GET", "/", "", nil))
	resp, body := parseResponse(t, raw, "GET")
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "application/json; charset=UTF-8", resp.Header.Get("Content-Type"))
	require.Empty(t, resp.Header.Get("Server"))
	node := Node()
	require.Equal(t, `{
  "status" : 200,
  "name" : "`+node.Name+`",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "1.4.2",
    "build_hash" : "927caff6f05403e936c20bf4529f144f0c89fd8c",
    "build_timestamp" : "2014-12-16T14:11:12Z",
    "build_snapshot" : false,
    "lucene_version" : "4.10.2"
  },
  "tagline" : "You Know, for Search"
}
`, body)
	require.NotContains(t, strings.ToLower(body), "glutton")
	require.NotContains(t, strings.ToLower(body), "honeypot")

	head := Respond("HEAD", "/", "", Inspect("HEAD", "/", "", nil))
	require.Equal(t, "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 0\r\n\r\n", string(head))
}

func TestRespond(t *testing.T) {
	prevID, prevTook := newDocID, took
	newDocID = func() string { return "AUqrcQkZ1aF2xF8hUyRk" }
	took = func() int { return 3 }
	t.Cleanup(func() { newDocID, took = prevID, prevTook })

	tests := []struct {
		method, path, query string
		status              int
		ctype               string
		body                string
	}{
		{"POST", "/_search", "", 200, jsonType, `{"took":3,"timed_out":false,"_shards":{"total":0,"successful":0,"failed":0},"hits":{"total":0,"max_score":null,"hits":[]}}`},
		{"GET", "/_search", "pretty", 200, jsonType, "{\n  \"took\" : 3,\n  \"timed_out\" : false,\n  \"_shards\" : {\n    \"total\" : 0,\n    \"successful\" : 0,\n    \"failed\" : 0\n  },\n  \"hits\" : {\n    \"total\" : 0,\n    \"max_score\" : null,\n    \"hits\" : [ ]\n  }\n}\n"},
		{"GET", "/_all/_search", "size=5000", 200, jsonType, `{"took":3,"timed_out":false,"_shards":{"total":0,"successful":0,"failed":0},"hits":{"total":0,"max_score":null,"hits":[]}}`},
		{"GET", "/website/_search", "q=*:*", 404, jsonType, `{"error":"IndexMissingException[[website] missing]","status":404}`},
		{"GET", "/.env", "", 404, jsonType, `{"error":"IndexMissingException[[.env] missing]","status":404}`},
		{"DELETE", "/customers", "", 404, jsonType, `{"error":"IndexMissingException[[customers] missing]","status":404}`},
		{"DELETE", "/*", "", 200, jsonType, `{"acknowledged":true}`},
		{"PUT", "/read_me", "", 200, jsonType, `{"acknowledged":true}`},
		{"POST", "/website/blog/", "", 201, jsonType, `{"_index":"website","_type":"blog","_id":"AUqrcQkZ1aF2xF8hUyRk","_version":1,"created":true}`},
		{"PUT", "/read_me/howtorecover/1", "", 201, jsonType, `{"_index":"read_me","_type":"howtorecover","_id":"1","_version":1,"created":true}`},
		{"GET", "/_cluster/health", "", 200, jsonType, `{"cluster_name":"elasticsearch","status":"green","timed_out":false,"number_of_nodes":1,"number_of_data_nodes":1,"active_primary_shards":0,"active_shards":0,"relocating_shards":0,"initializing_shards":0,"unassigned_shards":0}`},
		{"GET", "/_cat/indices", "", 200, textType, ""},
		{"GET", "/_cat/indices", "v", 200, textType, "health status index pri rep docs.count docs.deleted store.size pri.store.size \n"},
		{"GET", "/_cat/indices", "format=json&h=index", 200, jsonType, "[]"},
		{"GET", "/_mapping", "", 200, jsonType, "{}"},
		{"GET", "/%2A/_alias", "", 200, jsonType, "{}"},
		{"GET", "/_stats", "", 200, jsonType, `{"_all":{"primaries":{},"total":{}},"_shards":{"total":0,"successful":0,"failed":0},"indices":{}}`},
		{"GET", "/_cluster/state", "", 400, textType, "No handler found for uri [/_cluster/state] and method [GET]"},
		{"POST", "/", "", 400, textType, "No handler found for uri [/] and method [POST]"},
		{"GET", "/_plugin/head", "", 400, textType, "No handler found for uri [/_plugin/head] and method [GET]"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path+"?"+tt.query, func(t *testing.T) {
			req := Inspect(tt.method, tt.path, tt.query, nil)
			resp, body := parseResponse(t, Respond(tt.method, tt.path, tt.query, req), tt.method)
			require.Equal(t, tt.status, resp.StatusCode)
			require.Equal(t, tt.ctype, resp.Header.Get("Content-Type"))
			require.Equal(t, tt.body, body)
			require.Equal(t, int64(len(body)), resp.ContentLength)
		})
	}
}

func TestRespondCatNodes(t *testing.T) {
	node := Node()
	_, body := parseResponse(t, Respond("GET", "/_cat/nodes", "v", Inspect("GET", "/_cat/nodes", "v", nil)), "GET")
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	require.Len(t, lines, 2)
	require.True(t, strings.HasPrefix(lines[0], "host "))
	require.Equal(t, strings.Index(lines[0], "ip"), strings.Index(lines[1], node.IP))
	require.True(t, strings.HasSuffix(lines[1], node.Name+" "))

	_, body = parseResponse(t, Respond("GET", "/_cat/nodes", "format=json", Inspect("GET", "/_cat/nodes", "format=json", nil)), "GET")
	var rows []map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &rows))
	require.Len(t, rows, 1)
	require.Equal(t, node.Name, rows[0]["name"])
	require.Equal(t, node.IP, rows[0]["ip"])
}

func TestJacksonIndent(t *testing.T) {
	require.Equal(t, "{\n  \"a\" : \"x\\\": {}\",\n  \"b\" : { },\n  \"c\" : [ ]\n}", string(jacksonIndent([]byte(`{"a":"x\": {}","b":{},"c":[]}`))))
	require.Equal(t, "not json", string(jacksonIndent([]byte("not json"))))
}
