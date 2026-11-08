package dockerapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Operation names set in Request.Operation.
const (
	OpPing             = "ping"
	OpVersion          = "version"
	OpInfo             = "info"
	OpContainerList    = "container_list"
	OpImageList        = "image_list"
	OpContainerCreate  = "container_create"
	OpContainerStart   = "container_start"
	OpContainerStop    = "container_stop"
	OpContainerKill    = "container_kill"
	OpContainerRestart = "container_restart"
	OpContainerDelete  = "container_delete"
	OpContainerWait    = "container_wait"
	OpContainerAttach  = "container_attach"
	OpContainerLogs    = "container_logs"
	OpContainerExec    = "container_exec"
	OpExecStart        = "exec_start"
	OpExecInspect      = "exec_inspect"
	OpImageCreate      = "image_create"
	OpUnknown          = "unknown"
)

// Capture caps; Request.Truncated is set when one applies.
const (
	maxField = 256     // image, id, user
	maxArgs  = 32      // cmd, entrypoint, binds, env entries
	maxArg   = 4 << 10 // one cmd/entrypoint/env entry
	maxBind  = 1 << 10 // one bind
)

// Request is the decoded Docker API operation of one request. Container and
// exec bodies carry the attack: the image, the command and host mounts.
type Request struct {
	Operation  string   `json:"operation"`
	ID         string   `json:"id,omitempty"`         // container or exec ID from the path
	Image      string   `json:"image,omitempty"`      // create body Image, or images/create fromImage[:tag]
	Cmd        []string `json:"cmd,omitempty"`        // create or exec Cmd
	Entrypoint []string `json:"entrypoint,omitempty"` // create Entrypoint
	Env        []string `json:"env,omitempty"`        // create or exec Env
	Binds      []string `json:"binds,omitempty"`      // create HostConfig.Binds (e.g. /:/host)
	Privileged bool     `json:"privileged,omitempty"` // create HostConfig.Privileged or exec Privileged
	User       string   `json:"user,omitempty"`       // create or exec User
	Truncated  bool     `json:"truncated,omitempty"`
}

// Inspect decodes the Docker API operation of a request. path is the URL
// path, rawQuery the query string and body the request body.
func Inspect(method, path, rawQuery string, body []byte) *Request {
	r := &Request{Operation: OpUnknown}
	get := method == http.MethodGet || method == http.MethodHead
	post := method == http.MethodPost
	route := Route(path)
	parts := strings.Split(strings.TrimPrefix(route, "/"), "/")
	switch {
	case route == "/_ping" && get:
		r.Operation = OpPing
	case route == "/version" && get:
		r.Operation = OpVersion
	case route == "/info" && get:
		r.Operation = OpInfo
	case route == "/containers/json" && get:
		r.Operation = OpContainerList
	case route == "/images/json" && get:
		r.Operation = OpImageList
	case route == "/containers/create" && post:
		r.Operation = OpContainerCreate
		r.parseCreate(body)
	case route == "/images/create" && post:
		r.Operation = OpImageCreate
		q, _ := url.ParseQuery(rawQuery)
		image := q.Get("fromImage")
		if tag := q.Get("tag"); image != "" && tag != "" {
			sep := ":"
			if strings.HasPrefix(tag, "sha256:") {
				sep = "@"
			}
			image += sep + tag
		}
		r.Image = r.clip(image, maxField)
	case len(parts) == 2 && parts[0] == "containers" && method == http.MethodDelete:
		r.Operation = OpContainerDelete
		r.ID = r.clip(parts[1], maxField)
	case len(parts) == 3 && parts[0] == "containers" && post:
		r.ID = r.clip(parts[1], maxField)
		switch parts[2] {
		case "start":
			r.Operation = OpContainerStart
		case "stop":
			r.Operation = OpContainerStop
		case "kill":
			r.Operation = OpContainerKill
		case "restart":
			r.Operation = OpContainerRestart
		case "wait":
			r.Operation = OpContainerWait
		case "attach":
			r.Operation = OpContainerAttach
		case "exec":
			r.Operation = OpContainerExec
			r.parseExec(body)
		default:
			r.ID = ""
		}
	case len(parts) == 3 && parts[0] == "containers" && parts[2] == "logs" && get:
		r.Operation = OpContainerLogs
		r.ID = r.clip(parts[1], maxField)
	case len(parts) == 3 && parts[0] == "exec" && parts[2] == "start" && post:
		r.Operation = OpExecStart
		r.ID = r.clip(parts[1], maxField)
	case len(parts) == 3 && parts[0] == "exec" && parts[2] == "json" && get:
		r.Operation = OpExecInspect
		r.ID = r.clip(parts[1], maxField)
	}
	return r
}

// strSlice is Docker's string-or-array JSON type (Cmd, Entrypoint).
type strSlice []string

func (s *strSlice) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		*s = nil
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func (r *Request) parseCreate(body []byte) {
	var c struct {
		Image      string
		Cmd        strSlice
		Entrypoint strSlice
		Env        []string
		User       string
		HostConfig struct {
			Binds      []string
			Privileged bool
		}
	}
	if json.Unmarshal(body, &c) != nil {
		return
	}
	r.Image = r.clip(c.Image, maxField)
	r.Cmd = r.capList(c.Cmd, maxArg)
	r.Entrypoint = r.capList(c.Entrypoint, maxArg)
	r.Env = r.capList(c.Env, maxArg)
	r.Binds = r.capList(c.HostConfig.Binds, maxBind)
	r.Privileged = c.HostConfig.Privileged
	r.User = r.clip(c.User, maxField)
}

func (r *Request) parseExec(body []byte) {
	var e struct {
		Cmd        strSlice
		Env        []string
		User       string
		Privileged bool
	}
	if json.Unmarshal(body, &e) != nil {
		return
	}
	r.Cmd = r.capList(e.Cmd, maxArg)
	r.Env = r.capList(e.Env, maxArg)
	r.Privileged = e.Privileged
	r.User = r.clip(e.User, maxField)
}

func (r *Request) clip(s string, n int) string {
	if len(s) > n {
		r.Truncated = true
		return s[:n]
	}
	return s
}

func (r *Request) capList(in []string, n int) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxArgs {
		r.Truncated = true
		in = in[:maxArgs]
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.clip(s, n)
	}
	return out
}

// Artifact reports whether the request body carries what the bot wants to run
// (a container create or exec config) and should be stored.
func (r *Request) Artifact() bool {
	return r != nil && (r.Operation == OpContainerCreate || r.Operation == OpContainerExec)
}
