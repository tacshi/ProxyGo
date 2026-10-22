package script

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"sync"

	"github.com/dop251/goja"
)

type sharedLease struct {
	mu   *sync.Mutex
	held bool
}

func (l *sharedLease) hold() {
	if !l.held {
		l.mu.Lock()
		l.held = true
	}
}

func (l *sharedLease) release() {
	if l.held {
		l.held = false
		l.mu.Unlock()
	}
}

type sharedMap struct {
	vm *goja.Runtime
	l  *sharedLease
	m  map[string]any
}

func (s *sharedMap) Get(key string) goja.Value {
	s.l.hold()
	v, ok := s.m[key]
	if !ok {
		return nil
	}
	return sharedJS(s.vm, s.l, v)
}

func (s *sharedMap) Set(key string, val goja.Value) bool {
	s.l.hold()
	s.m[key] = sharedGo(val.Export(), map[uintptr]any{})
	return true
}

func (s *sharedMap) Has(key string) bool {
	s.l.hold()
	_, ok := s.m[key]
	return ok
}

func (s *sharedMap) Delete(key string) bool {
	s.l.hold()
	delete(s.m, key)
	return true
}

func (s *sharedMap) Keys() []string {
	s.l.hold()
	return slices.Sorted(maps.Keys(s.m))
}

func (s *sharedMap) MarshalJSON() ([]byte, error) {
	s.l.hold()
	return json.Marshal(s.m)
}

type sharedList struct {
	vm *goja.Runtime
	l  *sharedLease
	p  *[]any
}

func (s *sharedList) Len() int {
	s.l.hold()
	return len(*s.p)
}

func (s *sharedList) Get(i int) goja.Value {
	s.l.hold()
	if i < 0 || i >= len(*s.p) {
		return nil
	}
	return sharedJS(s.vm, s.l, (*s.p)[i])
}

func (s *sharedList) Set(i int, val goja.Value) bool {
	s.l.hold()
	if i < 0 {
		return false
	}
	if i >= len(*s.p) {
		*s.p = resize(*s.p, i+1)
	}
	(*s.p)[i] = sharedGo(val.Export(), map[uintptr]any{})
	return true
}

func (s *sharedList) SetLen(n int) bool {
	s.l.hold()
	*s.p = resize(*s.p, n)
	return true
}

func (s *sharedList) MarshalJSON() ([]byte, error) {
	s.l.hold()
	return json.Marshal(*s.p)
}

func resize(a []any, n int) []any {
	if n <= len(a) {
		return a[:n]
	}
	return append(a, make([]any, n-len(a))...)
}

func sharedJS(vm *goja.Runtime, l *sharedLease, v any) goja.Value {
	switch x := v.(type) {
	case map[string]any:
		return vm.NewDynamicObject(&sharedMap{vm: vm, l: l, m: x})
	case *[]any:
		return vm.NewDynamicArray(&sharedList{vm: vm, l: l, p: x})
	}
	return vm.ToValue(v)
}

func sharedGo(v any, seen map[uintptr]any) any {
	switch x := v.(type) {
	case *sharedMap:
		return x.m
	case *sharedList:
		return x.p
	case map[string]any:
		ptr := reflect.ValueOf(x).Pointer()
		if _, ok := seen[ptr]; ok {
			return x
		}
		seen[ptr] = x
		for k, c := range x {
			x[k] = sharedGo(c, seen)
		}
		return x
	case []any:
		if len(x) == 0 {
			return &x
		}
		ptr := reflect.ValueOf(x).Pointer()
		if p, ok := seen[ptr]; ok {
			return p
		}
		seen[ptr] = &x
		for i, c := range x {
			x[i] = sharedGo(c, seen)
		}
		return &x
	}
	return v
}
