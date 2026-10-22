package store

import (
	"cmp"
	"maps"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"proxygo/internal/flow"
)

type Store struct {
	mu       sync.RWMutex
	flows    []*flow.Flow
	byID     map[string]*flow.Flow
	max      int
	nextRow  int
	up       int64
	down     int64
	version  atomic.Uint64
	memLimit int64
}

func New(max int) *Store {
	return &Store{byID: map[string]*flow.Flow{}, max: cmp.Or(max, 50000)}
}

func (s *Store) SetLimit(max int) {
	s.mu.Lock()
	s.max = cmp.Or(max, 50000)
	s.trimLocked()
	s.mu.Unlock()
	s.version.Add(1)
}

func (s *Store) SetMemoryLimit(bytes int64) {
	s.mu.Lock()
	s.memLimit = max(bytes, 0)
	s.trimLocked()
	s.mu.Unlock()
	s.version.Add(1)
}

func (s *Store) Upsert(f *flow.Flow) {
	if f == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.UniqueID == "" {
		f.UniqueID = flow.NewUniqueID()
	}
	old := s.byID[f.UniqueID]
	if old == nil {
		s.nextRow++
		f.ID = strconv.Itoa(s.nextRow)
		f.Name = f.ID
		f.Index = len(s.flows)
		s.flows = append(s.flows, f)
		s.byID[f.UniqueID] = f
		s.addTraffic(f, 1)
		s.trimLocked()
		s.version.Add(1)
		return
	}
	f.ID, f.Name, f.Index = old.ID, old.Name, old.Index
	f.Saved = f.Saved || old.Saved
	f.Strikethrough = f.Strikethrough || old.Strikethrough
	f.Comment = cmp.Or(old.Comment, f.Comment)
	f.Highlight = cmp.Or(old.Highlight, f.Highlight)
	if old.WebSocketMessageStorage != nil && (f.WebSocketMessageStorage == nil || len(f.WebSocketMessageStorage.Messages) < len(old.WebSocketMessageStorage.Messages)) {
		f.WebSocketMessageStorage = old.WebSocketMessageStorage
	}
	s.replaceLocked(old, f)
}

func (s *Store) replaceLocked(old, f *flow.Flow) {
	for i := len(s.flows) - 1; i >= 0; i-- {
		if s.flows[i] == old {
			s.flows[i] = f
			break
		}
	}
	s.byID[f.UniqueID] = f
	s.addTraffic(old, -1)
	s.addTraffic(f, 1)
	s.version.Add(1)
}

func (s *Store) Update(id string, fn func(*flow.Flow)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.byID[id]
	if old == nil {
		return
	}
	cp := *old
	fn(&cp)
	s.replaceLocked(old, &cp)
}

func (s *Store) Remove(ids ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	gone := map[*flow.Flow]bool{}
	for _, id := range ids {
		if f := s.byID[id]; f != nil {
			gone[f] = true
			delete(s.byID, id)
			s.addTraffic(f, -1)
		}
	}
	if len(gone) == 0 {
		return
	}
	s.flows = slices.DeleteFunc(slices.Clone(s.flows), func(f *flow.Flow) bool { return gone[f] })
	s.version.Add(1)
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.flows = nil
	s.byID = map[string]*flow.Flow{}
	s.nextRow = 0
	s.up, s.down = 0, 0
	s.mu.Unlock()
	s.version.Add(1)
}

func (s *Store) Replace(flows []*flow.Flow) {
	s.mu.Lock()
	s.flows = make([]*flow.Flow, 0, len(flows))
	s.byID = make(map[string]*flow.Flow, len(flows))
	s.nextRow = 0
	s.up, s.down = 0, 0
	for _, f := range flows {
		if f == nil || s.byID[f.UniqueID] != nil {
			continue
		}
		if f.UniqueID == "" {
			f.UniqueID = flow.NewUniqueID()
		}
		s.nextRow++
		f.ID = strconv.Itoa(s.nextRow)
		f.Name = f.ID
		f.Index = len(s.flows)
		s.flows = append(s.flows, f)
		s.byID[f.UniqueID] = f
		s.addTraffic(f, 1)
	}
	s.trimLocked()
	s.mu.Unlock()
	s.version.Add(1)
}

func (s *Store) Append(flows []*flow.Flow) {
	for _, f := range flows {
		f = f.Clone()
		if _, ok := s.Lookup(f.UniqueID); ok || f.UniqueID == "" {
			f.UniqueID = flow.NewUniqueID()
		}
		s.Upsert(f)
	}
}

func (s *Store) trimLocked() {
	if len(s.flows) > s.max {
		drop := min(len(s.flows), len(s.flows)-s.max+s.max/10)
		for _, f := range s.flows[:drop] {
			delete(s.byID, f.UniqueID)
			s.addTraffic(f, -1)
		}
		s.flows = slices.Clone(s.flows[drop:])
	}
	if s.memLimit <= 0 || s.up+s.down <= s.memLimit {
		return
	}
	target := s.memLimit * 9 / 10
	kept := make([]*flow.Flow, 0, len(s.flows))
	for i, f := range s.flows {
		if s.up+s.down <= target {
			kept = append(kept, s.flows[i:]...)
			break
		}
		if f.Saved {
			kept = append(kept, f)
			continue
		}
		delete(s.byID, f.UniqueID)
		s.addTraffic(f, -1)
	}
	s.flows = kept
}

func (s *Store) addTraffic(f *flow.Flow, sign int64) {
	s.up += sign * int64(f.RequestSize())
	s.down += sign * int64(f.ResponseSize())
}

func (s *Store) Snapshot() []*flow.Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.flows)
}

func (s *Store) Lookup(id string) (*flow.Flow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.byID[id]
	return f, ok
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.flows)
}

func (s *Store) Version() uint64 { return s.version.Load() }

func (s *Store) Traffic() (up, down int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.up, s.down
}

func Counts(flows []*flow.Flow, key func(*flow.Flow) string) map[string]int {
	out := map[string]int{}
	for _, f := range flows {
		if k := key(f); k != "" {
			out[k]++
		}
	}
	return out
}

func Apps(flows []*flow.Flow) map[string]int {
	return Counts(flows, func(f *flow.Flow) string { return cmp.Or(f.Client.Name, "System") })
}

func Domains(flows []*flow.Flow) map[string]int {
	return Counts(flows, (*flow.Flow).Host)
}

func ByCount(m map[string]int) []string {
	return slices.SortedFunc(maps.Keys(m), func(a, b string) int {
		return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b))
	})
}
