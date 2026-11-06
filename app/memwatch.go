package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"
)

// memWatchConfig controls when the watcher writes profiles. The sensor has
// been OOM-killed by spikes of ~1.4 GB inside two minutes while memory was
// flat for hours before, so profiles pulled by hand never see the spike: the
// watcher samples RSS often and dumps while the spike is happening.
type memWatchConfig struct {
	Threshold uint64        // RSS bytes that trigger the first dump
	Step      uint64        // further RSS growth that triggers another dump
	Interval  time.Duration // RSS sampling period
	Dir       string        // dumps go to <Dir>/<time>-pid<pid>-rss<MiB>/
	MaxDumps  int           // dump directories kept on disk, oldest removed first
}

// memWatcher dumps profiles when the process RSS crosses Threshold, again
// after every further Step of growth, and re-arms once RSS falls back below
// Threshold. RSS includes memory the Go heap does not see (Spicy's C++
// parsers), which status.txt separates from the Go runtime's share.
type memWatcher struct {
	cfg    memWatchConfig
	logger *slog.Logger
	rss    func() (uint64, error)
	now    func() time.Time
	next   uint64 // RSS that triggers the next dump
}

func newMemWatcher(cfg memWatchConfig, logger *slog.Logger) (*memWatcher, error) {
	if cfg.Threshold == 0 {
		return nil, errors.New("memwatch.threshold must be > 0")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.Step == 0 {
		cfg.Step = 256 << 20
	}
	if cfg.MaxDumps <= 0 {
		cfg.MaxDumps = 10
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("memwatch.dir %q: %w", cfg.Dir, err)
	}
	return &memWatcher{cfg: cfg, logger: logger, rss: procRSS, now: time.Now, next: cfg.Threshold}, nil
}

// run samples RSS every Interval until ctx is done.
func (w *memWatcher) run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check()
		}
	}
}

// check samples RSS once and dumps if it reached the next trigger. It returns
// the dump directory, or "" when nothing was written.
func (w *memWatcher) check() string {
	rss, err := w.rss()
	if err != nil {
		w.logger.Debug("Failed to read RSS", slog.String("reporter", "memwatch"), slog.String("error", err.Error()))
		return ""
	}
	if rss < w.cfg.Threshold {
		w.next = w.cfg.Threshold
		return ""
	}
	if rss < w.next {
		return ""
	}
	// the next dump waits for another Step above what was just seen, so a
	// fast spike yields one dump per Step rather than one per sample
	w.next = rss + w.cfg.Step
	dir, err := w.dump(rss)
	if err != nil {
		w.logger.Error("Failed to write memory dump", slog.String("reporter", "memwatch"), slog.String("dir", dir), slog.String("error", err.Error()))
	} else {
		w.logger.Warn("RSS over threshold, wrote memory dump", slog.String("reporter", "memwatch"),
			slog.Uint64("rss_mib", rss>>20), slog.Uint64("threshold_mib", w.cfg.Threshold>>20), slog.String("dir", dir))
	}
	w.prune()
	return dir
}

// dump writes, cheapest and most telling first since the OOM killer may
// arrive mid-dump: goroutine stacks (which handler is busy), memory status,
// then the heap and allocs profiles.
func (w *memWatcher) dump(rss uint64) (string, error) {
	name := fmt.Sprintf("%s-pid%d-rss%d", w.now().UTC().Format("20060102T150405Z"), os.Getpid(), rss>>20)
	dir := filepath.Join(w.cfg.Dir, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return dir, err
	}
	var errs []error
	errs = append(errs, writeProfile(filepath.Join(dir, "goroutine.txt"), "goroutine", 2))
	errs = append(errs, os.WriteFile(filepath.Join(dir, "status.txt"), memStatus(rss), 0o640))
	runtime.GC() // heap in-use figures reflect the last GC
	errs = append(errs, writeProfile(filepath.Join(dir, "heap.pb.gz"), "heap", 0))
	errs = append(errs, writeProfile(filepath.Join(dir, "allocs.pb.gz"), "allocs", 0))
	return dir, errors.Join(errs...)
}

func writeProfile(path, profile string, debug int) error {
	p := pprof.Lookup(profile)
	if p == nil {
		return fmt.Errorf("no %s profile", profile)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if err := p.WriteTo(f, debug); err != nil {
		_ = f.Close()
		return fmt.Errorf("%s: %w", profile, err)
	}
	return f.Close()
}

// memStatus reports RSS next to the Go runtime's own accounting; RSS well
// above Sys points at non-Go (cgo/Spicy) memory.
func memStatus(rss uint64) []byte {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var b bytes.Buffer
	fmt.Fprintf(&b, "time: %s\npid: %d\n", time.Now().UTC().Format(time.RFC3339Nano), os.Getpid())
	fmt.Fprintf(&b, "rss_bytes: %d\n", rss)
	fmt.Fprintf(&b, "go_sys_bytes: %d\n", ms.Sys)
	fmt.Fprintf(&b, "non_go_bytes_estimate: %d\n", int64(rss)-int64(ms.Sys))
	fmt.Fprintf(&b, "go_heap_alloc_bytes: %d\ngo_heap_inuse_bytes: %d\ngo_heap_objects: %d\n", ms.HeapAlloc, ms.HeapInuse, ms.HeapObjects)
	fmt.Fprintf(&b, "go_stack_inuse_bytes: %d\ngo_num_gc: %d\ngoroutines: %d\n", ms.StackInuse, ms.NumGC, runtime.NumGoroutine())
	if s, err := os.ReadFile("/proc/self/status"); err == nil {
		b.WriteString("\n/proc/self/status:\n")
		b.Write(s)
	}
	return b.Bytes()
}

// prune keeps the newest MaxDumps dump directories. Names start with a UTC
// timestamp, so lexical order is chronological.
func (w *memWatcher) prune() {
	entries, err := os.ReadDir(w.cfg.Dir)
	if err != nil {
		return
	}
	var dumps []string
	for _, e := range entries {
		if e.IsDir() && strings.Contains(e.Name(), "-pid") {
			dumps = append(dumps, e.Name())
		}
	}
	sort.Strings(dumps)
	for len(dumps) > w.cfg.MaxDumps {
		_ = os.RemoveAll(filepath.Join(w.cfg.Dir, dumps[0]))
		dumps = dumps[1:]
	}
}

// procRSS reads the resident set size from /proc/self/statm.
func procRSS() (uint64, error) {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	return parseStatmRSS(b, uint64(os.Getpagesize()))
}

func parseStatmRSS(b []byte, pageSize uint64) (uint64, error) {
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0, fmt.Errorf("statm: %q", b)
	}
	pages, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("statm: %w", err)
	}
	return pages * pageSize, nil
}
