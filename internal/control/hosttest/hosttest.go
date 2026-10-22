package hosttest

import (
	"errors"
	"sync"

	"proxygo/internal/certs"
	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/session"
	"proxygo/internal/store"
)

type Host struct {
	S *store.Store
	R *rules.Store
	P *proxy.Server
	C *certs.Manager

	mu        sync.Mutex
	recording bool
	sysProxy  bool
	mcp       bool
	opened    []string
	selected  []*flow.Flow
}

func New(dir string) (*Host, error) {
	c, err := certs.New(dir)
	if err != nil {
		return nil, err
	}
	h := &Host{S: store.New(1000), R: rules.Memory(rules.Data{}), C: c, recording: true}
	h.P = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Certs: c, Rules: h.R, Sink: h.S})
	return h, nil
}

func (h *Host) Store() *store.Store   { return h.S }
func (h *Host) Rules() *rules.Store   { return h.R }
func (h *Host) Proxy() *proxy.Server  { return h.P }
func (h *Host) Certs() *certs.Manager { return h.C }
func (h *Host) Version() string       { return "test" }
func (h *Host) ProxyAddress() (string, int) {
	return "192.0.2.1", 9090
}

func (h *Host) Recording() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.recording
}

func (h *Host) SetRecording(on bool) {
	h.mu.Lock()
	h.recording = on
	h.mu.Unlock()
	h.P.SetPaused(!on)
}

func (h *Host) SystemProxy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sysProxy
}

func (h *Host) SetSystemProxy(on bool) error {
	h.mu.Lock()
	h.sysProxy = on
	h.mu.Unlock()
	return nil
}

func (h *Host) ClearSession() { h.S.Clear() }

func (h *Host) Selected() []*flow.Flow {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.selected
}

func (h *Host) Select(fs ...*flow.Flow) {
	h.mu.Lock()
	h.selected = fs
	h.mu.Unlock()
}

func (h *Host) MCP() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mcp
}

func (h *Host) SetMCP(on bool) error {
	h.mu.Lock()
	h.mcp = on
	h.mu.Unlock()
	return nil
}

func (h *Host) Open(window string) error {
	if window == "" {
		return errors.New("no window")
	}
	h.mu.Lock()
	h.opened = append(h.opened, window)
	h.mu.Unlock()
	return nil
}

func (h *Host) Opened() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.opened...)
}

func (h *Host) Export(path, format string, flows []*flow.Flow) error {
	return session.Export(path, format, flows, nil)
}
