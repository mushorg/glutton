package helpers

import (
	"container/list"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// StoreLimits bounds what Store keeps on disk, summed over every folder it
// writes to. When a new file would exceed a limit, the oldest stored files are
// deleted first. 0 disables a limit.
type StoreLimits struct {
	MaxBytes int64 // total size of stored files
	MaxFiles int   // number of stored files (each one costs an inode)
}

// DefaultStoreLimits keeps at most 1 GiB in 100000 files.
func DefaultStoreLimits() StoreLimits {
	return StoreLimits{MaxBytes: 1 << 30, MaxFiles: 100000}
}

// ErrStoreTooLarge is returned for data bigger than StoreLimits.MaxBytes.
var ErrStoreTooLarge = errors.New("data exceeds the storage size limit")

type storedFile struct {
	path    string
	size    int64
	modTime time.Time
}

// fileStore indexes the files Store manages, oldest first. A folder's existing
// files are indexed the first time Store writes to it, so files from earlier
// runs count against the limits and are evicted first.
type fileStore struct {
	mu      sync.Mutex
	limits  StoreLimits
	scanned map[string]bool
	files   *list.List // of *storedFile, ordered by modTime
	index   map[string]*list.Element
	bytes   int64
}

func newFileStore(limits StoreLimits) *fileStore {
	return &fileStore{
		limits:  limits,
		scanned: map[string]bool{},
		files:   list.New(),
		index:   map[string]*list.Element{},
	}
}

var store = newFileStore(DefaultStoreLimits())

// ConfigureStore sets the limits Store enforces and evicts indexed files that
// no longer fit.
func ConfigureStore(limits StoreLimits) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.limits = limits
	store.evict(0, 0)
}

// Store writes data to folder under its SHA-256 hex digest and returns the
// digest. Content already stored keeps its file. Old files are deleted to stay
// within the StoreLimits set by ConfigureStore.
func Store(data []byte, folder string) (string, error) {
	sha256Hash := SHA256Hex(data)
	// the index is keyed by absolute path, so a working directory change
	// cannot make a file look stored when it is not
	abs, err := filepath.Abs(folder)
	if err != nil {
		return "", err
	}
	if err := store.put(abs, filepath.Join(abs, sha256Hash), data); err != nil {
		return "", err
	}
	return sha256Hash, nil
}

func (s *fileStore) put(folder, path string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.scan(folder); err != nil {
		return err
	}
	if _, ok := s.index[path]; ok {
		// already stored: same content, same hash
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	size := int64(len(data))
	if s.limits.MaxBytes > 0 && size > s.limits.MaxBytes {
		return ErrStoreTooLarge
	}
	s.evict(size, 1)
	if err := writeFile(path, data); err != nil {
		return err
	}
	s.add(&storedFile{path: path, size: size, modTime: time.Now()})
	return nil
}

// writeFile creates path with data, removing a partly written file.
func writeFile(path string, data []byte) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = out.Write(data)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// scan creates folder and indexes the regular files already in it, once.
func (s *fileStore) scan(folder string) error {
	if s.scanned[folder] {
		return nil
	}
	if err := os.MkdirAll(folder, os.ModePerm); err != nil {
		return err
	}
	entries, err := os.ReadDir(folder)
	if err != nil {
		return fmt.Errorf("index stored files: %w", err)
	}
	var found []*storedFile
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(folder, e.Name())
		if _, ok := s.index[path]; ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		found = append(found, &storedFile{path: path, size: info.Size(), modTime: info.ModTime()})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].modTime.Before(found[j].modTime) })
	// merge into the oldest-first list
	el := s.files.Front()
	for _, f := range found {
		for el != nil && !el.Value.(*storedFile).modTime.After(f.modTime) {
			el = el.Next()
		}
		if el == nil {
			s.index[f.path] = s.files.PushBack(f)
		} else {
			s.index[f.path] = s.files.InsertBefore(f, el)
		}
		s.bytes += f.size
	}
	s.scanned[folder] = true
	s.evict(0, 0)
	return nil
}

func (s *fileStore) add(f *storedFile) {
	s.index[f.path] = s.files.PushBack(f)
	s.bytes += f.size
}

// evict deletes the oldest files until size more bytes in n more files fit.
func (s *fileStore) evict(size int64, n int) {
	for s.files.Len() > 0 &&
		((s.limits.MaxBytes > 0 && s.bytes+size > s.limits.MaxBytes) ||
			(s.limits.MaxFiles > 0 && s.files.Len()+n > s.limits.MaxFiles)) {
		f := s.files.Front().Value.(*storedFile)
		if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
			// still on disk: keep it indexed and stop rather than spin
			return
		}
		s.files.Remove(s.files.Front())
		delete(s.index, f.path)
		s.bytes -= f.size
	}
}
