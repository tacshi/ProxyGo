package control_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxygo/internal/control"
	"proxygo/internal/control/hosttest"
	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func newHost(t *testing.T) *hosttest.Host {
	t.Helper()
	h, err := hosttest.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func call(t *testing.T, path, method string, params any) json.RawMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := control.Dial(ctx, path, method, params)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return out
}

func TestSocket(t *testing.T) {
	dir := shortDir(t)
	h := newHost(t)
	path := control.SocketPath(dir)
	if _, err := control.Dial(context.Background(), path, "status", nil); err != control.ErrNotRunning {
		t.Fatalf("without ProxyGo: %v", err)
	}
	srv, err := control.Serve(h, path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(control.RunDir(dir)); fi.Mode().Perm() != 0o700 {
		t.Errorf("folder mode %v", fi.Mode().Perm())
	}
	if _, err := control.Serve(h, path); err == nil {
		t.Error("a second server took the socket of a running one")
	}
	var st control.Status
	json.Unmarshal(call(t, path, "status", nil), &st)
	if st.Version != "test" || st.Port != 9090 || !st.Recording || st.HTTPVersion != rules.PreferHTTP2 {
		t.Errorf("%+v", st)
	}
	if got := string(call(t, path, "proxy.host", nil)); got != `{"host":"192.0.2.1","port":9090}` {
		t.Errorf("proxy-host %s", got)
	}
	call(t, path, "proxy.set", map[string]bool{"on": true})
	if !h.SystemProxy() {
		t.Error("proxy on")
	}
	call(t, path, "http.version.set", map[string]string{"mode": "http1_only"})
	if !h.R.Current().DisableHTTP2 {
		t.Error("http1_only")
	}
	if _, err := control.Dial(context.Background(), path, "http.version.set", map[string]string{"mode": "auto"}); err == nil || !strings.Contains(err.Error(), "prefer_http2") {
		t.Errorf("a bad mode: %v", err)
	}
	call(t, path, "tool.set", map[string]any{"tool": "map-remote", "on": false})
	call(t, path, "tool.set", map[string]any{"tool": "no-caching", "on": true})
	var tools map[string]bool
	json.Unmarshal(call(t, path, "tool.status", nil), &tools)
	if tools["map-remote"] || !tools["no-caching"] || !tools["breakpoint"] {
		t.Errorf("tools %v", tools)
	}
	h.S.Upsert(&flow.Flow{UniqueID: "A", Request: &flow.Request{Host: "api.dev", FullPath: "https://api.dev/a", Method: flow.Method{Name: "GET"}}})
	h.S.Upsert(&flow.Flow{UniqueID: "B", Request: &flow.Request{Host: "cdn.dev", FullPath: "https://cdn.dev/b", Method: flow.Method{Name: "GET"}}})
	out := filepath.Join(t.TempDir(), "s.har")
	var exported map[string]any
	json.Unmarshal(call(t, path, "session.export", map[string]any{"path": out, "format": "har", "domains": []string{"api.dev"}}), &exported)
	if exported["flows"] != float64(1) {
		t.Errorf("export %v", exported)
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "https://api.dev/a") || strings.Contains(string(b), "cdn.dev") {
		t.Errorf("har %s", b)
	}
	call(t, path, "session.clear", nil)
	if h.S.Len() != 0 {
		t.Error("clear")
	}
	call(t, path, "open", map[string]string{"window": "maplocal"})
	if o := h.Opened(); len(o) != 1 || o[0] != "maplocal" {
		t.Errorf("opened %v", o)
	}
	if _, err := control.Dial(context.Background(), path, "nope", nil); err == nil {
		t.Error("an unknown method")
	}
	srv.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the socket outlived the server")
	}
}

func TestRuleCalls(t *testing.T) {
	h := newHost(t)
	created, err := control.Call(h, "rules.create", mustJSON(map[string]any{"tool": "map-local", "rule": map[string]any{"name": "Users", "url": "https://api.dev/users", "status_code": 201, "body": "[]"}}))
	if err != nil {
		t.Fatal(err)
	}
	r := created.(*rules.MapLocalRule)
	if r.ID == "" || !r.Enabled || r.StatusCode != 201 {
		t.Fatalf("%+v", r)
	}
	if _, err := control.Call(h, "rules.update", mustJSON(map[string]any{"tool": "map-local", "id": r.ID, "rule": map[string]any{"status_code": 404}})); err != nil {
		t.Fatal(err)
	}
	got := h.R.Current().MapLocal[0]
	if got.StatusCode != 404 || got.Name != "Users" || got.Body != "[]" || got.ID != r.ID {
		t.Errorf("an update changes only the fields it names: %+v", got)
	}
	if _, err := control.Call(h, "rules.disable", mustJSON(map[string]any{"tool": "map-local", "id": r.ID})); err != nil || h.R.Current().MapLocal[0].Enabled {
		t.Errorf("disable %v", err)
	}
	if _, err := control.Call(h, "rules.create", mustJSON(map[string]any{"tool": "map-local", "rule": map[string]any{"name": "No URL"}})); err == nil {
		t.Error("a rule without a URL")
	}
	if _, err := control.Call(h, "rules.list", mustJSON(map[string]any{"tool": "nope"})); err == nil || !strings.Contains(err.Error(), "map-local") {
		t.Errorf("unknown tool: %v", err)
	}
	listed, _ := control.Call(h, "rules.list", mustJSON(map[string]any{"tool": "map-local"}))
	if l := listed.([]*rules.MapLocalRule); len(l) != 1 {
		t.Errorf("list %v", l)
	}

	path := filepath.Join(t.TempDir(), "rules.json")
	control.Call(h, "rules.create", mustJSON(map[string]any{"tool": "block-list", "rule": map[string]any{"url": "ads.example.com"}}))
	if _, err := control.Call(h, "rules.export", mustJSON(map[string]any{"path": path, "enabledOnly": true})); err != nil {
		t.Fatal(err)
	}
	other := newHost(t)
	if _, err := control.Call(other, "rules.import", mustJSON(map[string]any{"path": path})); err != nil {
		t.Fatal(err)
	}
	d := other.R.Current()
	if len(d.MapLocal) != 0 || len(d.Block) != 1 {
		t.Errorf("imported %d map local, %d block", len(d.MapLocal), len(d.Block))
	}
	control.Call(other, "rules.import", mustJSON(map[string]any{"path": path}))
	if d := other.R.Current(); len(d.Block) != 2 || d.Block[0].ID == d.Block[1].ID {
		t.Errorf("append twice: %+v", d.Block)
	}
	if _, err := control.Call(other, "rules.delete", mustJSON(map[string]any{"tool": "block-list", "id": other.R.Current().Block[0].ID})); err != nil || len(other.R.Current().Block) != 1 {
		t.Errorf("delete %v", err)
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
