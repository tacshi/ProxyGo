package script

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

const wsQueue = 256

type WebSocketSession struct {
	e      *Engine
	rules  []*rules.ScriptRule
	f      *flow.Flow
	req    *Request
	resp   *Response
	vms    map[string]*wsVM
	closed chan struct{}

	mu    sync.Mutex
	ch    chan flow.WebSocketMessage
	done  bool
	skips int
}

type wsVM struct {
	vm    *goja.Runtime
	lease *sharedLease
	fn    goja.Callable
	args  []goja.Value
}

func HasWebSocketHook(r *rules.ScriptRule) bool {
	return strings.Contains(r.Script, "onWebsocket")
}

func (e *Engine) NewWebSocketSession(list []*rules.ScriptRule, f *flow.Flow, req *Request, resp *Response) *WebSocketSession {
	var hooked []*rules.ScriptRule
	for _, r := range list {
		if HasWebSocketHook(r) {
			hooked = append(hooked, r)
		}
	}
	if len(hooked) == 0 {
		return nil
	}
	s := &WebSocketSession{e: e, rules: hooked, f: f.Clone(), req: req, resp: resp,
		ch: make(chan flow.WebSocketMessage, wsQueue), vms: map[string]*wsVM{}, closed: make(chan struct{})}
	go s.loop()
	return s
}

func (s *WebSocketSession) Add(m flow.WebSocketMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	select {
	case s.ch <- m:
		s.skips = 0
	default:
		s.skips++
		if s.skips == 1 {
			s.e.addLog(s.rules[0].Name, "warn", "onWebsocket() can't keep up: a script is slow or stuck. New messages skip onWebsocket() until it catches up.")
		}
	}
}

func (s *WebSocketSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done {
		s.done = true
		close(s.ch)
	}
}

func (s *WebSocketSession) Wait() { <-s.closed }

func (s *WebSocketSession) loop() {
	defer close(s.closed)
	for m := range s.ch {
		for _, r := range s.rules {
			if err := s.run(r, m); err != nil {
				s.e.addLog(r.Name, "error", "onWebsocket: "+err.Error())
			}
		}
	}
}

func (s *WebSocketSession) run(r *rules.ScriptRule, m flow.WebSocketMessage) error {
	w, err := s.vm(r)
	if err != nil || w == nil {
		return err
	}
	defer w.lease.release()
	timer := time.AfterFunc(30*time.Second, func() { w.vm.Interrupt("onWebsocket timed out after 30 s") })
	defer timer.Stop()
	msg := w.vm.NewObject()
	_ = msg.Set("type", m.Type)
	_ = msg.Set("from", m.From)
	data := m.Data
	if m.Type == "binary" {
		data = fmt.Sprintf("<%d bytes of binary>", len(m.RawData))
		if arr, err := w.vm.New(w.vm.Get("Uint8Array"), w.vm.ToValue(w.vm.NewArrayBuffer(append([]byte(nil), m.RawData...)))); err == nil {
			_ = msg.Set("rawData", arr)
		}
	}
	_ = msg.Set("data", data)
	if m.Type == "close" {
		_ = msg.Set("closeCode", m.CloseCode)
	}
	_ = msg.Set("time", m.Time)
	_, err = w.fn(goja.Undefined(), append(w.args, msg)...)
	w.vm.ClearInterrupt()
	if err != nil {
		delete(s.vms, r.ID)
	}
	return err
}

func (s *WebSocketSession) vm(r *rules.ScriptRule) (*wsVM, error) {
	if w, ok := s.vms[r.ID]; ok {
		return w, nil
	}
	prog, err := s.e.program(r)
	if err != nil {
		return nil, err
	}
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	lease := s.e.installRuntime(vm, r.Name)
	defer lease.release()
	timer := time.AfterFunc(30*time.Second, func() { vm.Interrupt("the script timed out after 30 s") })
	_, err = vm.RunProgram(prog)
	timer.Stop()
	if err != nil {
		return nil, err
	}
	fn, ok := goja.AssertFunction(vm.Get("onWebsocket"))
	if !ok {
		s.vms[r.ID] = nil
		return nil, nil
	}
	ctx := vm.NewObject()
	_ = ctx.Set("scriptName", r.Name)
	_ = ctx.Set("matchingRule", r.URL)
	_ = ctx.Set("flow", flowInfo(s.f))
	args := []goja.Value{ctx, vm.ToValue(s.req.URL()), requestValue(vm, s.req)}
	if s.resp != nil {
		args = append(args, responseValue(vm, s.resp))
	} else {
		args = append(args, goja.Undefined())
	}
	w := &wsVM{vm: vm, lease: lease, fn: fn, args: args}
	s.vms[r.ID] = w
	return w, nil
}
