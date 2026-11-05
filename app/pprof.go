package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// pprofMux serves the runtime profiles on a dedicated mux, so nothing else
// registered on http.DefaultServeMux is exposed alongside them.
func pprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// listenPprof binds addr, which must be a loopback address: the honeypot
// accepts traffic on every port, so profiles are only reachable over an SSH
// tunnel (ssh -L 6060:127.0.0.1:6060 host).
func listenPprof(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("pprof.addr %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("pprof.addr %q: host must be a loopback address", addr)
	}
	return net.Listen("tcp", addr)
}

// startPprof serves profiles on addr in the background.
func startPprof(addr string) (net.Listener, error) {
	ln, err := listenPprof(addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: pprofMux(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return ln, nil
}
