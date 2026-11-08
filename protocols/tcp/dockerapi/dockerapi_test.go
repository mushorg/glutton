package dockerapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, 11, 8, 11, 42, 22, 0, time.UTC)

func parse(t *testing.T, raw []byte, method string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), &http.Request{Method: method})
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}

func respond(method, path, rawQuery string, body, version []byte) []byte {
	return Respond(method, Inspect(method, path, rawQuery, body), version, testNow)
}

func withRand(t *testing.T, b byte) {
	t.Helper()
	prev := randRead
	randRead = func(p []byte) (int, error) {
		for i := range p {
			p[i] = b
		}
		return len(p), nil
	}
	t.Cleanup(func() { randRead = prev })
}

func TestIsPort(t *testing.T) {
	require.True(t, IsPort(2375))
	require.True(t, IsPort(2376))
	require.False(t, IsPort(2377))
}

func TestRoute(t *testing.T) {
	for in, want := range map[string]string{
		"/_ping":                 "/_ping",
		"/v1.41/_ping":           "/_ping",
		"/v1.16/version":         "/version",
		"/version/":              "/version",
		"/v1.24/containers/json": "/containers/json",
		"/v1.41":                 "/",
		"/":                      "/",
		"/vx/version":            "/vx/version",
	} {
		require.Equal(t, want, Route(in), in)
	}
}

func TestRespondPing(t *testing.T) {
	resp, body := parse(t, respond(http.MethodGet, "/_ping", "", nil, nil), http.MethodGet)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "OK", string(body))
	require.Equal(t, "1.41", resp.Header.Get("Api-Version"))
	require.Equal(t, "false", resp.Header.Get("Docker-Experimental"))
	require.Equal(t, "linux", resp.Header.Get("Ostype"))
	require.Equal(t, "2", resp.Header.Get("Builder-Version"))
	require.Equal(t, "Docker/20.10.9 (linux)", resp.Header.Get("Server"))
	require.Equal(t, "Sun, 08 Nov 2026 11:42:22 GMT", resp.Header.Get("Date"))
}

func TestRespondPingHead(t *testing.T) {
	raw := respond(http.MethodHead, "/_ping", "", nil, nil)
	require.True(t, bytes.HasSuffix(raw, []byte("Content-Length: 2\r\n\r\n")))
}

func TestRespondVersion(t *testing.T) {
	version := []byte(`{"ApiVersion":"1.41"}`)
	resp, body := parse(t, respond(http.MethodGet, "/v1.24/version", "", nil, version), http.MethodGet)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	require.Equal(t, "{\"ApiVersion\":\"1.41\"}\n", string(body))
	require.Equal(t, `{"ApiVersion":"1.41"}`, string(version), "caller's slice must not be modified")
}

func TestRespondLists(t *testing.T) {
	for _, path := range []string{"/containers/json", "/v1.41/images/json"} {
		resp, body := parse(t, respond(http.MethodGet, path, "", nil, nil), http.MethodGet)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.Equal(t, "[]\n", string(body), path)
	}
}

func TestRespondInfo(t *testing.T) {
	resp, body := parse(t, respond(http.MethodGet, "/v1.41/info", "", nil, nil), http.MethodGet)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var info map[string]any
	require.NoError(t, json.Unmarshal(body, &info))
	require.Equal(t, "20.10.9", info["ServerVersion"])
	require.Equal(t, "5.14.10-1-amd64", info["KernelVersion"])
	require.EqualValues(t, 0, info["Containers"])
	require.Regexp(t, `^srv-[0-9a-f]{6}$`, info["Name"])
	require.Regexp(t, `^[A-Z2-7]{4}(:[A-Z2-7]{4}){11}$`, info["ID"])
	require.Equal(t, "2026-11-08T11:42:22Z", info["SystemTime"])
	_, again := parse(t, respond(http.MethodGet, "/info", "", nil, nil), http.MethodGet)
	require.Equal(t, string(body), string(again), "identity is stable per sensor")
}

// createBody is a typical cryptojacking container create (synthetic).
const createBody = `{"Image":"alpine","Cmd":["sh","-c","echo hi"],"Env":["A=1"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}`

func TestInspectCreate(t *testing.T) {
	r := Inspect(http.MethodPost, "/v1.41/containers/create", "name=x", []byte(createBody))
	require.Equal(t, &Request{
		Operation:  OpContainerCreate,
		Image:      "alpine",
		Cmd:        []string{"sh", "-c", "echo hi"},
		Env:        []string{"A=1"},
		Binds:      []string{"/:/host"},
		Privileged: true,
	}, r)
	require.True(t, r.Artifact())

	// Cmd and Entrypoint may be a plain string
	r = Inspect(http.MethodPost, "/containers/create", "", []byte(`{"Image":"busybox","Entrypoint":"/bin/sh","Cmd":"id"}`))
	require.Equal(t, []string{"/bin/sh"}, r.Entrypoint)
	require.Equal(t, []string{"id"}, r.Cmd)

	// a malformed body keeps the operation
	r = Inspect(http.MethodPost, "/containers/create", "", []byte(`{"Image":`))
	require.Equal(t, &Request{Operation: OpContainerCreate}, r)
	require.False(t, Inspect(http.MethodGet, "/_ping", "", nil).Artifact())
}

func TestInspectCaps(t *testing.T) {
	cmd := make([]string, maxArgs+5)
	for i := range cmd {
		cmd[i] = "x"
	}
	cmd[0] = strings.Repeat("a", maxArg+10)
	body, err := json.Marshal(map[string]any{"Image": strings.Repeat("i", maxField+1), "Cmd": cmd})
	require.NoError(t, err)
	r := Inspect(http.MethodPost, "/containers/create", "", body)
	require.True(t, r.Truncated)
	require.Len(t, r.Cmd, maxArgs)
	require.Len(t, r.Cmd[0], maxArg)
	require.Len(t, r.Image, maxField)
}

func TestInspectOperations(t *testing.T) {
	id := strings.Repeat("ab", 32)
	for _, c := range []struct {
		method, path, query string
		want                Request
	}{
		{http.MethodGet, "/_ping", "", Request{Operation: OpPing}},
		{http.MethodPost, "/containers/" + id + "/start", "", Request{Operation: OpContainerStart, ID: id}},
		{http.MethodPost, "/v1.41/containers/" + id + "/wait", "", Request{Operation: OpContainerWait, ID: id}},
		{http.MethodPost, "/containers/" + id + "/attach", "stream=1", Request{Operation: OpContainerAttach, ID: id}},
		{http.MethodPost, "/containers/" + id + "/kill", "", Request{Operation: OpContainerKill, ID: id}},
		{http.MethodDelete, "/containers/" + id, "force=1", Request{Operation: OpContainerDelete, ID: id}},
		{http.MethodGet, "/containers/" + id + "/logs", "", Request{Operation: OpContainerLogs, ID: id}},
		{http.MethodPost, "/exec/" + id + "/start", "", Request{Operation: OpExecStart, ID: id}},
		{http.MethodGet, "/exec/" + id + "/json", "", Request{Operation: OpExecInspect, ID: id}},
		{http.MethodPost, "/images/create", "fromImage=alpine&tag=3.18", Request{Operation: OpImageCreate, Image: "alpine:3.18"}},
		{http.MethodPost, "/images/create", "fromImage=user/miner", Request{Operation: OpImageCreate, Image: "user/miner"}},
		{http.MethodPost, "/containers/" + id + "/bogus", "", Request{Operation: OpUnknown}},
		{http.MethodPost, "/_ping", "", Request{Operation: OpUnknown}},
	} {
		require.Equal(t, &c.want, Inspect(c.method, c.path, c.query, nil), c.method+" "+c.path)
	}
	r := Inspect(http.MethodPost, "/containers/"+id+"/exec", "", []byte(`{"Cmd":["cat","/etc/shadow"],"User":"root","Privileged":true}`))
	require.Equal(t, &Request{Operation: OpContainerExec, ID: id, Cmd: []string{"cat", "/etc/shadow"}, User: "root", Privileged: true}, r)
}

func TestRespondContainerChain(t *testing.T) {
	withRand(t, 0xab)
	id := strings.Repeat("ab", 32)

	resp, body := parse(t, respond(http.MethodPost, "/v1.41/containers/create", "", []byte(createBody), nil), http.MethodPost)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.Equal(t, `{"Id":"`+id+`","Warnings":[]}`+"\n", string(body))

	raw := respond(http.MethodPost, "/containers/"+id+"/start", "", nil, nil)
	resp, body = parse(t, raw, http.MethodPost)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.Empty(t, body)
	require.NotContains(t, string(raw), "Content-Length")
	require.NotContains(t, string(raw), "Content-Type")

	resp, body = parse(t, respond(http.MethodPost, "/containers/"+id+"/wait", "", nil, nil), http.MethodPost)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "{\"Error\":null,\"StatusCode\":0}\n", string(body))

	resp, body = parse(t, respond(http.MethodPost, "/containers/"+id+"/attach", "stream=1&stdout=1", nil, nil), http.MethodPost)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/vnd.docker.raw-stream", resp.Header.Get("Content-Type"))
	require.Empty(t, body)

	resp, body = parse(t, respond(http.MethodPost, "/containers/"+id+"/exec", "", []byte(`{"Cmd":["id"]}`), nil), http.MethodPost)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.Equal(t, `{"Id":"`+id+`"}`+"\n", string(body))

	resp, body = parse(t, respond(http.MethodPost, "/exec/"+id+"/start", "", []byte(`{"Detach":false}`), nil), http.MethodPost)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, body)

	resp, body = parse(t, respond(http.MethodGet, "/exec/"+id+"/json", "", nil, nil), http.MethodGet)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, `{"ID":"`+id+`","Running":false,"ExitCode":0,"Pid":0}`+"\n", string(body))
}

func TestRespondImagePull(t *testing.T) {
	resp, body := parse(t, respond(http.MethodPost, "/images/create", "fromImage=alpine&tag=latest", nil, nil), http.MethodPost)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	lines := strings.Split(strings.TrimSpace(string(body)), "\r\n")
	require.Len(t, lines, 3)
	require.Equal(t, `{"id":"latest","status":"Pulling from library/alpine"}`, lines[0])
	require.Regexp(t, `^\{"status":"Digest: sha256:[0-9a-f]{64}"\}$`, lines[1])
	require.Equal(t, `{"status":"Status: Image is up to date for alpine:latest"}`, lines[2])

	_, again := parse(t, respond(http.MethodPost, "/images/create", "fromImage=alpine", nil, nil), http.MethodPost)
	require.Equal(t, string(body), string(again), "tag defaults to latest, digest is stable")

	_, body = parse(t, respond(http.MethodPost, "/images/create", "fromImage=user/miner&tag=v2", nil, nil), http.MethodPost)
	require.Contains(t, string(body), `"Pulling from user/miner"`)
	require.Contains(t, string(body), `"id":"v2"`)

	_, body = parse(t, respond(http.MethodPost, "/images/create", "", nil, nil), http.MethodPost)
	require.Equal(t, "{\"message\":\"invalid reference format\"}\n", string(body))
}

func TestRespondNotFound(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodPost, "/_ping"},
		{http.MethodGet, "/containers/create"},
	} {
		resp, body := parse(t, respond(c.method, c.path, "", nil, nil), c.method)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, c.path)
		require.Equal(t, "{\"message\":\"page not found\"}\n", string(body), c.path)
	}
	resp, _ := parse(t, Respond(http.MethodGet, nil, nil, testNow), http.MethodGet)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}
