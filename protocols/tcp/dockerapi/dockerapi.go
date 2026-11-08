// Package dockerapi emulates an unauthenticated Docker Engine API (dockerd on
// tcp/2375 plain, tcp/2376 TLS): the ping, version, info and empty list
// routes scanners fingerprint with, and the container create/start/exec and
// image pull routes cryptojacking bots use next. Nothing is pulled, created or
// executed: every container and exec ID is made up and every stream is empty.
// The package does no I/O.
package dockerapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// PlainPort and TLSPort are the IANA Docker ports; every path there is the
	// Docker persona.
	PlainPort = 2375
	TLSPort   = 2376

	// engineVersion, apiVersion and kernelVersion must match
	// resources/docker_api.json.
	engineVersion = "20.10.9"
	apiVersion    = "1.41"
	kernelVersion = "5.14.10-1-amd64"

	rawStream = "application/vnd.docker.raw-stream"
)

// versionPrefix matches the optional /vX.Y API version prefix of a route.
var versionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+(/|$)`)

// randRead fills container/exec IDs and the per-sensor identity; tests swap it.
var randRead = rand.Read

// IsPort reports whether port is a Docker Engine API port.
func IsPort(port uint16) bool {
	return port == PlainPort || port == TLSPort
}

// Route strips the /vX.Y version prefix and a trailing slash from path.
func Route(path string) string {
	if loc := versionPrefix.FindStringIndex(path); loc != nil {
		path = "/" + path[loc[1]:]
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

// Respond builds the dockerd reply for a request inspected into req. version
// is the GET /version JSON body; now sets the Date header.
func Respond(method string, req *Request, version []byte, now time.Time) []byte {
	op := ""
	if req != nil {
		op = req.Operation
	}
	switch op {
	case OpPing:
		return response(method, "200 OK", "text/plain; charset=utf-8", []byte("OK"), true, now)
	case OpVersion:
		return response(method, "200 OK", "application/json", append(append([]byte{}, version...), '\n'), false, now)
	case OpInfo:
		return response(method, "200 OK", "application/json", infoBody(now), false, now)
	case OpContainerList, OpImageList:
		return response(method, "200 OK", "application/json", []byte("[]\n"), false, now)
	case OpContainerCreate:
		body, _ := json.Marshal(struct {
			ID       string   `json:"Id"`
			Warnings []string `json:"Warnings"`
		}{newID(), []string{}})
		return response(method, "201 Created", "application/json", append(body, '\n'), false, now)
	case OpContainerExec:
		body, _ := json.Marshal(struct {
			ID string `json:"Id"`
		}{newID()})
		return response(method, "201 Created", "application/json", append(body, '\n'), false, now)
	case OpContainerStart, OpContainerStop, OpContainerKill, OpContainerRestart, OpContainerDelete:
		return response(method, "204 No Content", "", nil, false, now)
	case OpContainerWait:
		return response(method, "200 OK", "application/json", []byte("{\"Error\":null,\"StatusCode\":0}\n"), false, now)
	case OpContainerAttach, OpContainerLogs, OpExecStart:
		// the real daemon hijacks the connection here; an empty stream reads
		// as a command that printed nothing
		return response(method, "200 OK", rawStream, nil, false, now)
	case OpExecInspect:
		body, _ := json.Marshal(struct {
			ID       string `json:"ID"`
			Running  bool   `json:"Running"`
			ExitCode int    `json:"ExitCode"`
			Pid      int    `json:"Pid"`
		}{req.ID, false, 0, 0})
		return response(method, "200 OK", "application/json", append(body, '\n'), false, now)
	case OpImageCreate:
		return response(method, "200 OK", "application/json", pullStream(req.Image), false, now)
	}
	return response(method, "404 Not Found", "application/json", []byte("{\"message\":\"page not found\"}\n"), false, now)
}

func response(method, status, contentType string, body []byte, ping bool, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
	fmt.Fprintf(&b, "Api-Version: %s\r\n", apiVersion)
	if ping {
		b.WriteString("Builder-Version: 2\r\n")
		b.WriteString("Cache-Control: no-cache, no-store, must-revalidate\r\n")
	}
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	}
	b.WriteString("Docker-Experimental: false\r\n")
	b.WriteString("Ostype: linux\r\n")
	if ping {
		b.WriteString("Pragma: no-cache\r\n")
	}
	fmt.Fprintf(&b, "Server: Docker/%s (linux)\r\n", engineVersion)
	fmt.Fprintf(&b, "Date: %s\r\n", now.UTC().Format(http.TimeFormat))
	if !strings.HasPrefix(status, "204") {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	if method == http.MethodHead {
		return []byte(b.String())
	}
	return append([]byte(b.String()), body...)
}

// newID returns a 64-hex container or exec ID.
func newID() string {
	buf := make([]byte, 32)
	_, _ = randRead(buf)
	return hex.EncodeToString(buf)
}

// identity is the per-sensor host name and daemon ID reported by /info.
var identity struct {
	once     sync.Once
	hostname string
	daemonID string
}

func sensorIdentity() (string, string) {
	identity.once.Do(func() {
		buf := make([]byte, 3+48)
		_, _ = randRead(buf)
		identity.hostname = "srv-" + hex.EncodeToString(buf[:3])
		// daemon IDs are 12 colon-separated groups of 4 base32 characters
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		groups := make([]string, 12)
		for i := range groups {
			g := make([]byte, 4)
			for j := range g {
				g[j] = alphabet[int(buf[3+i*4+j])%len(alphabet)]
			}
			groups[i] = string(g)
		}
		identity.daemonID = strings.Join(groups, ":")
	})
	return identity.hostname, identity.daemonID
}

// infoBody is GET /info for a small idle Debian 11 host with no containers or
// images, matching the version object.
func infoBody(now time.Time) []byte {
	hostname, daemonID := sensorIdentity()
	body, _ := json.Marshal(map[string]any{
		"ID":                 daemonID,
		"Containers":         0,
		"ContainersRunning":  0,
		"ContainersPaused":   0,
		"ContainersStopped":  0,
		"Images":             0,
		"Driver":             "overlay2",
		"DriverStatus":       [][]string{{"Backing Filesystem", "extfs"}, {"Supports d_type", "true"}, {"Native Overlay Diff", "true"}, {"userxattr", "false"}},
		"Plugins":            map[string][]string{"Volume": {"local"}, "Network": {"bridge", "host", "ipvlan", "macvlan", "null", "overlay"}, "Log": {"awslogs", "fluentd", "gcplogs", "gelf", "journald", "json-file", "local", "logentries", "splunk", "syslog"}},
		"MemoryLimit":        true,
		"SwapLimit":          false,
		"CpuCfsPeriod":       true,
		"CpuCfsQuota":        true,
		"CPUShares":          true,
		"CPUSet":             true,
		"PidsLimit":          true,
		"IPv4Forwarding":     true,
		"Debug":              false,
		"NFd":                24,
		"OomKillDisable":     true,
		"NGoroutines":        34,
		"SystemTime":         now.UTC().Format(time.RFC3339Nano),
		"LoggingDriver":      "json-file",
		"CgroupDriver":       "systemd",
		"CgroupVersion":      "2",
		"NEventsListener":    0,
		"KernelVersion":      kernelVersion,
		"OperatingSystem":    "Debian GNU/Linux 11 (bullseye)",
		"OSVersion":          "11",
		"OSType":             "linux",
		"Architecture":       "x86_64",
		"IndexServerAddress": "https://index.docker.io/v1/",
		"NCPU":               4,
		"MemTotal":           8331653120,
		"DockerRootDir":      "/var/lib/docker",
		"Name":               hostname,
		"Labels":             []string{},
		"ExperimentalBuild":  false,
		"ServerVersion":      engineVersion,
		"Runtimes":           map[string]any{"io.containerd.runc.v2": map[string]string{"path": "runc"}, "runc": map[string]string{"path": "runc"}},
		"DefaultRuntime":     "runc",
		"Swarm":              map[string]any{"NodeID": "", "NodeAddr": "", "LocalNodeState": "inactive", "ControlAvailable": false, "Error": "", "RemoteManagers": nil},
		"LiveRestoreEnabled": false,
		"Isolation":          "",
		"InitBinary":         "docker-init",
		"SecurityOptions":    []string{"name=apparmor", "name=seccomp,profile=default", "name=cgroupns"},
		"Warnings":           []string{"WARNING: No swap limit support"},
	})
	return append(body, '\n')
}

// pullStream is the POST /images/create progress stream for image: the image
// is reported as already up to date, so no layer progress is needed. The
// digest is derived from the name so repeated pulls agree.
func pullStream(image string) []byte {
	if image == "" {
		return []byte("{\"message\":\"invalid reference format\"}\n")
	}
	name, tag := image, "latest"
	if i := strings.Index(image, "@"); i >= 0 {
		name, tag = image[:i], image[i+1:]
	} else if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		name, tag = image[:i], image[i+1:]
	}
	sum := sha256.Sum256([]byte(name + ":" + tag))
	repo := name
	if !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	var b strings.Builder
	for _, line := range []map[string]string{
		{"status": "Pulling from " + repo, "id": tag},
		{"status": "Digest: sha256:" + hex.EncodeToString(sum[:])},
		{"status": "Status: Image is up to date for " + name + ":" + tag},
	} {
		enc, _ := json.Marshal(line)
		b.Write(enc)
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}
