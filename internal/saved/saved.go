package saved

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/session"
)

type Folder struct {
	Path    string    `json:"path"`
	Count   int       `json:"count"`
	Updated time.Time `json:"updated"`
}

func (f Folder) Name() string { return filepath.Base(f.Path) }

func (f Folder) Parent() string {
	if i := strings.LastIndexByte(f.Path, '/'); i >= 0 {
		return f.Path[:i]
	}
	return ""
}

type Store struct {
	dir string

	mu      sync.Mutex
	folders []Folder
	version uint64
}

func Open(dir string) *Store {
	s := &Store{dir: dir}
	if b, err := os.ReadFile(s.index()); err == nil {
		_ = json.Unmarshal(b, &s.folders)
	}
	return s
}

func (s *Store) index() string { return filepath.Join(s.dir, "folders.json") }

func Clean(path string) (string, error) {
	var parts []string
	for p := range strings.SplitSeq(path, "/") {
		p = strings.TrimSpace(p)
		switch p {
		case "":
			continue
		case ".", "..":
			return "", fmt.Errorf("a folder cannot be named %q", p)
		}
		if strings.ContainsAny(p, "\x00:\\") {
			return "", fmt.Errorf("a folder's name cannot hold %q", ":")
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "", errors.New("enter the folder's name")
	}
	return strings.Join(parts, "/"), nil
}

func (s *Store) file(path string) string {
	return filepath.Join(s.dir, filepath.FromSlash(path)+session.Ext)
}

func (s *Store) Folders() []Folder {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.folders)
	slices.SortFunc(out, func(a, b Folder) int { return strings.Compare(strings.ToLower(a.Path), strings.ToLower(b.Path)) })
	return out
}

func (s *Store) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

func (s *Store) Create(path string) error {
	path, err := Clean(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(path, nil)
}

func (s *Store) Add(path string, flows []*flow.Flow, icons map[string]string) (int, error) {
	path, err := Clean(path)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.openLocked(path)
	if err != nil {
		return 0, err
	}
	for _, f := range flows {
		c := f.Clone()
		b.Flows = slices.DeleteFunc(b.Flows, func(x *flow.Flow) bool { return x.UniqueID == c.UniqueID })
		b.Flows = append(b.Flows, c)
	}
	for k, v := range icons {
		b.Icons[k] = v
	}
	return len(b.Flows), s.writeBundleLocked(path, b)
}

func (s *Store) Remove(path string, ids ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.openLocked(path)
	if err != nil {
		return err
	}
	b.Flows = slices.DeleteFunc(b.Flows, func(f *flow.Flow) bool { return slices.Contains(ids, f.UniqueID) })
	return s.writeBundleLocked(path, b)
}

func (s *Store) Open(path string) (*session.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openLocked(path)
}

func (s *Store) File(path string) string { return s.file(path) }

func (s *Store) openLocked(path string) (*session.Bundle, error) {
	b, err := session.Read(s.file(path))
	if errors.Is(err, os.ErrNotExist) || err != nil && !s.hasLocked(path) {
		return &session.Bundle{Icons: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) hasLocked(path string) bool {
	return slices.ContainsFunc(s.folders, func(f Folder) bool { return f.Path == path })
}

func (s *Store) writeLocked(path string, flows []*flow.Flow) error {
	return s.writeBundleLocked(path, &session.Bundle{Flows: flows, Icons: map[string]string{}})
}

func (s *Store) writeBundleLocked(path string, b *session.Bundle) error {
	if err := session.Write(s.file(path), b.Flows, b.Icons); err != nil {
		return err
	}
	s.setLocked(path, len(b.Flows))
	for p := path; strings.Contains(p, "/"); {
		p = p[:strings.LastIndexByte(p, '/')]
		if !s.hasLocked(p) {
			if err := session.Write(s.file(p), nil, nil); err != nil {
				return err
			}
			s.setLocked(p, 0)
		}
	}
	return s.saveLocked()
}

func (s *Store) setLocked(path string, n int) {
	f := Folder{Path: path, Count: n, Updated: time.Now()}
	if i := slices.IndexFunc(s.folders, func(x Folder) bool { return x.Path == path }); i >= 0 {
		s.folders[i] = f
	} else {
		s.folders = append(s.folders, f)
	}
}

func (s *Store) saveLocked() error {
	s.version++
	b, err := json.MarshalIndent(s.folders, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(s.index(), b, 0o600)
}

func (s *Store) Delete(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.folders = slices.DeleteFunc(s.folders, func(f Folder) bool {
		if f.Path == path || strings.HasPrefix(f.Path, path+"/") {
			_ = os.Remove(s.file(f.Path))
			return true
		}
		return false
	})
	_ = os.RemoveAll(filepath.Join(s.dir, filepath.FromSlash(path)))
	return s.saveLocked()
}

func (s *Store) Rename(from, to string) error {
	to, err := Clean(to)
	if err != nil {
		return err
	}
	if to == from || strings.HasPrefix(to, from+"/") {
		return errors.New("a folder cannot move into itself")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasLocked(to) {
		return fmt.Errorf("a folder %q exists already", to)
	}
	for i, f := range s.folders {
		if f.Path != from && !strings.HasPrefix(f.Path, from+"/") {
			continue
		}
		np := to + strings.TrimPrefix(f.Path, from)
		if err := os.MkdirAll(filepath.Dir(s.file(np)), 0o750); err != nil {
			return err
		}
		if err := os.Rename(s.file(f.Path), s.file(np)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		s.folders[i].Path = np
	}
	_ = os.RemoveAll(filepath.Join(s.dir, filepath.FromSlash(from)))
	return s.saveLocked()
}
