package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/script"
)

func toolMeta(f *flow.Flow, key string) any {
	m, _ := f.ToolMetadata.(map[string]any)
	return m[key]
}

func TestBlockAndAllowLists(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.Block = append(d.Block,
			&rules.URLRule{ID: "1", Enabled: true, Name: "ads", Matcher: rules.Matcher{URL: "*/ads/*"}},
			&rules.URLRule{ID: "2", Enabled: true, Name: "hidden", Matcher: rules.Matcher{URL: "*/hidden"}, Action: rules.BlockHide},
		)
	})
	resp, body := get(t, e.client(false), ts.URL+"/ads/banner")
	if resp.StatusCode != 403 || !strings.Contains(body, "Blocked by ProxyGo") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if toolMeta(e.waitFlow(byPath("/ads/banner")), "block") != "ads" {
		t.Fatal("block not marked")
	}
	if _, err := e.client(false).Get(ts.URL + "/hidden"); err == nil {
		t.Fatal("hidden block answered")
	}

	e.update(func(d *rules.Data) {
		d.Block = nil
		d.Allow = append(d.Allow, &rules.URLRule{ID: "3", Enabled: true, Matcher: rules.Matcher{URL: "*/ok/*"}})
	})
	if resp, _ := get(t, e.client(false), ts.URL+"/ok/1"); resp.StatusCode != 200 {
		t.Fatal("allowed URL blocked")
	}
	if resp, _ := get(t, e.client(false), ts.URL+"/other"); resp.StatusCode != 403 {
		t.Fatal("URL outside the allow list passed")
	}
	time.Sleep(30 * time.Millisecond)
	for _, f := range e.store.Snapshot() {
		if strings.Contains(f.URL(), "/hidden") {
			t.Fatal("hidden block recorded")
		}
	}
}

func TestMapLocal(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "static", "css"), 0o750)
	_ = os.WriteFile(filepath.Join(dir, "static", "css", "site.css"), []byte("body{}"), 0o600)
	e.update(func(d *rules.Data) {
		d.MapLocal = append(d.MapLocal,
			&rules.MapLocalRule{ID: "f", Enabled: true, Name: "file", Matcher: rules.Matcher{URL: ts.URL + "/app.js"}, Path: filepath.Join(dir, "app.js")},
			&rules.MapLocalRule{ID: "d", Enabled: true, Name: "dir", Matcher: rules.Matcher{URL: ts.URL + "/assets/*"}, Path: filepath.Join(dir, "static")},
			&rules.MapLocalRule{ID: "i", Enabled: true, Name: "inline", Matcher: rules.Matcher{URL: ts.URL + "/api/user", Method: "GET"}, StatusCode: 201,
				Headers: []rules.Pair{{Name: "X-Mock", Value: "1"}}, Body: `{"name":"mock"}`, DelayMS: 120},
		)
	})
	resp, body := get(t, e.client(false), ts.URL+"/app.js")
	if body != "console.log(1)" || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("file: %q %q", body, resp.Header.Get("Content-Type"))
	}
	resp, body = get(t, e.client(false), ts.URL+"/assets/css/site.css")
	if body != "body{}" || !strings.Contains(resp.Header.Get("Content-Type"), "css") {
		t.Fatalf("directory: %q", body)
	}
	if resp, _ := get(t, e.client(false), ts.URL+"/assets/../../etc/passwd"); resp.StatusCode != 404 {
		t.Fatalf("path escaped the directory: %d", resp.StatusCode)
	}
	start := time.Now()
	resp, body = get(t, e.client(false), ts.URL+"/api/user")
	if resp.StatusCode != 201 || body != `{"name":"mock"}` || resp.Header.Get("X-Mock") != "1" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("inline: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if time.Since(start) < 120*time.Millisecond {
		t.Fatal("delay not applied")
	}
	f := e.waitFlow(byPath("/api/user"))
	if toolMeta(f, "mapLocal") == nil || f.StatusCode() != 201 {
		t.Fatal("map local not recorded")
	}
	resp, err := e.client(false).Post(ts.URL+"/api/user", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("method not matched")
	}
}

func TestMapRemote(t *testing.T) {
	e := newEnv(t)
	prod := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "prod") }))
	defer prod.Close()
	staging := httptest.NewServer(echoServer())
	defer staging.Close()
	e.update(func(d *rules.Data) {
		d.MapRemote = append(d.MapRemote, &rules.MapRemoteRule{ID: "m", Enabled: true, Name: "to staging", Matcher: rules.Matcher{URL: prod.URL + "/*"}, NewURL: staging.URL})
	})
	resp, body := get(t, e.client(false), prod.URL+"/v1/items?id=3")
	if !strings.Contains(body, `"path":"/v1/items?id=3"`) {
		t.Fatalf("not mapped: %s", body)
	}
	if resp.Header.Get("X-Host") != strings.TrimPrefix(staging.URL, "http://") {
		t.Fatalf("Host header %q", resp.Header.Get("X-Host"))
	}
	f := e.waitFlow(byPath("/v1/items"))
	if !strings.HasPrefix(f.URL(), staging.URL) || toolMeta(f, "mapRemote") == nil {
		t.Fatalf("flow URL %s", f.URL())
	}

	e.update(func(d *rules.Data) { d.MapRemote[0].PreserveHost = true })
	resp, _ = get(t, e.client(false), prod.URL+"/keep")
	if resp.Header.Get("X-Host") != strings.TrimPrefix(prod.URL, "http://") {
		t.Fatalf("Host not preserved: %q", resp.Header.Get("X-Host"))
	}
}

func TestScripting(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Scripts = script.New() })
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"items":[1,2]}`))
	_ = zw.Close()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Seen", r.Header.Get("X-Script"))
		_, _ = w.Write(gz.Bytes())
	}))
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.Scripts = append(d.Scripts, &rules.ScriptRule{ID: "s", Enabled: true, Name: "edit", Matcher: rules.Matcher{URL: ts.URL + "/*"}, OnRequest: true, OnResponse: true, Script: `
			function onRequest(ctx, url, req) { req.headers["X-Script"] = "on"; req.comment = "from script"; return req; }
			function onResponse(ctx, url, req, res) { res.body.items.push(3); res.headers["X-Res"] = "on"; return res; }`})
	})
	req, _ := http.NewRequest("GET", ts.URL+"/list", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	c := e.client(false)
	c.Transport.(*http.Transport).DisableCompression = true
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Header.Get("X-Seen") != "on" || resp.Header.Get("X-Res") != "on" {
		t.Fatalf("headers %v", resp.Header)
	}
	if string(body) != `{"items":[1,2,3]}` || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("body %q encoding %q", body, resp.Header.Get("Content-Encoding"))
	}
	f := e.waitFlow(byPath("/list"))
	if f.Comment != "from script" || toolMeta(f, "script") != "edit" {
		t.Fatalf("comment %q tools %v", f.Comment, f.ToolMetadata)
	}

	e.update(func(d *rules.Data) {
		d.Scripts = []*rules.ScriptRule{{ID: "m", Enabled: true, Name: "mock", Matcher: rules.Matcher{URL: "*/mock"}, MockResponse: true, Script: `
			function onResponse(ctx, url, req, res) { res.statusCode = 202; res.headers["Content-Type"] = "text/plain"; res.body = "mocked"; return res; }`}}
	})
	resp, body2 := get(t, e.client(false), ts.URL+"/mock")
	if resp.StatusCode != 202 || body2 != "mocked" {
		t.Fatalf("mock API: %d %q", resp.StatusCode, body2)
	}
}

func TestBreakpoints(t *testing.T) {
	var pauses []Pause
	e := newEnv(t, func(o *Options) {
		o.Breakpoint = func(ctx context.Context, p *Pause) (Message, bool) {
			pauses = append(pauses, *p)
			m := p.Message
			if strings.Contains(m.URL, "/abort") {
				return m, false
			}
			if p.Response {
				m.StatusCode = 418
				m.Body = []byte("edited response")
				m.Header.Set("X-Edited", "response")
				return m, true
			}
			m.Method = "PUT"
			m.Header.Set("X-Test", "from breakpoint")
			m.Body = []byte("edited request")
			return m, true
		}
	})
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.Breakpoints = append(d.Breakpoints, &rules.BreakpointRule{ID: "b", Enabled: true, Name: "bp", Matcher: rules.Matcher{URL: ts.URL + "/*"}, Phase: rules.PhaseRequest})
	})
	resp, err := e.client(false).Post(ts.URL+"/edit", "text/plain", strings.NewReader("original"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), `"method":"PUT"`) || !strings.Contains(string(body), `"body":"edited request"`) || resp.Header.Get("X-Seen-Header") != "from breakpoint" {
		t.Fatalf("request edits lost: %s %v", body, resp.Header)
	}
	f := e.waitFlow(byPath("/edit"))
	if f.MethodName() != "PUT" || string(f.Request.BodyData) != "edited request" || toolMeta(f, "breakpoint") != "bp" {
		t.Fatalf("flow %s %q", f.MethodName(), f.Request.BodyData)
	}
	if f.Request.Header.Get("Content-Length") != "" && f.Request.Header.Get("Content-Length") != "14" {
		t.Fatalf("stale Content-Length %q", f.Request.Header.Get("Content-Length"))
	}

	e.update(func(d *rules.Data) { d.Breakpoints[0].Phase = rules.PhaseResponse })
	resp, body2 := get(t, e.client(false), ts.URL+"/resp")
	if resp.StatusCode != 418 || body2 != "edited response" || resp.Header.Get("X-Edited") != "response" {
		t.Fatalf("response edits lost: %d %q", resp.StatusCode, body2)
	}
	last := pauses[len(pauses)-1]
	if !last.Response || last.Message.StatusCode != 200 || !strings.Contains(string(last.Message.Body), "/resp") {
		t.Fatalf("pause %+v", last)
	}

	resp, _ = get(t, e.client(false), ts.URL+"/abort")
	if resp.StatusCode != 403 {
		t.Fatalf("abort: %d", resp.StatusCode)
	}
	e.update(func(d *rules.Data) { d.DisabledTools = map[string]bool{rules.ToolBreakpoint: true} })
	n := len(pauses)
	get(t, e.client(false), ts.URL+"/off")
	if len(pauses) != n {
		t.Fatal("disabled breakpoint tool paused")
	}
}

func TestStreamingResponse(t *testing.T) {
	e := newEnv(t)
	next := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-next:
		case <-time.After(5 * time.Second):
		}
		_, _ = io.WriteString(w, "data: two\n\n")
	}))
	defer ts.Close()
	resp, err := e.client(false).Get(ts.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	got := make(chan string, 1)
	go func() {
		line, _ := br.ReadString('\n')
		got <- line
	}()
	select {
	case line := <-got:
		if line != "data: one\n" {
			t.Fatalf("first event %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first event was held back until the response ended")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && e.store.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if e.store.Len() == 0 || e.store.Snapshot()[0].StatusCode() != 200 {
		t.Fatal("streaming flow not recorded while active")
	}
	close(next)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("rest %q", rest)
	}
	f := e.waitFlow(byPath("/events"))
	if string(f.Response.BodyData) != "data: one\n\ndata: two\n\n" {
		t.Fatalf("captured %q", f.Response.BodyData)
	}
}

func TestNetworkConditions(t *testing.T) {
	e := newEnv(t)
	payload := strings.Repeat("x", 20*1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tiny" {
			_, _ = io.WriteString(w, "tiny")
			return
		}
		_, _ = io.WriteString(w, payload)
	}))
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.NetworkConditions = append(d.NetworkConditions,
			&rules.NetworkCondition{ID: "slow", Enabled: true, Name: "Slow", Matcher: rules.Matcher{URL: "*/slow"}, LatencyMS: 150, DownloadKBps: 40},
			&rules.NetworkCondition{ID: "lost", Enabled: true, Name: "Lossy", Matcher: rules.Matcher{URL: "*/lost"}, PacketLoss: 100},
			&rules.NetworkCondition{ID: "tiny", Enabled: true, Name: "Crawl", Matcher: rules.Matcher{URL: "*/tiny"}, DownloadKBps: 0.01},
		)
	})
	start := time.Now()
	_, body := get(t, e.client(false), ts.URL+"/slow")
	elapsed := time.Since(start)
	if len(body) != len(payload) || elapsed < 550*time.Millisecond {
		t.Fatalf("got %d bytes in %v", len(body), elapsed)
	}
	f := e.waitFlow(byPath("/slow"))
	if !f.IsUnderNetworkCondition || toolMeta(f, "network") != "Slow" {
		t.Fatal("condition not recorded")
	}
	if len(f.Response.BodyData) != len(payload) {
		t.Fatalf("flow kept %d of %d bytes", len(f.Response.BodyData), len(payload))
	}
	_, body = get(t, e.client(false), ts.URL+"/tiny")
	ended := func(f *flow.Flow) bool { return byPath("/tiny")(f) && f.Timing.ResponseEndedAt != nil }
	if f := e.waitFlow(ended); body != "tiny" || string(f.Response.BodyData) != "tiny" {
		t.Fatalf("client got %q, flow kept %q", body, f.Response.BodyData)
	}
	resp, _ := get(t, e.client(false), ts.URL+"/lost")
	if resp.StatusCode != 502 || !e.waitFlow(byPath("/lost")).IsError() {
		t.Fatalf("packet loss: %d", resp.StatusCode)
	}
	start = time.Now()
	get(t, e.client(false), ts.URL+"/fast")
	if time.Since(start) > 400*time.Millisecond {
		t.Fatal("unmatched URL slowed down")
	}
}

func TestDNSSpoofing(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	port := ts.URL[strings.LastIndex(ts.URL, ":")+1:]
	e.update(func(d *rules.Data) {
		d.DNS = append(d.DNS, &rules.DNSRule{ID: "d", Enabled: true, Host: "api.proxygo.test", IP: "127.0.0.1"})
	})
	resp, body := get(t, e.client(false), "http://api.proxygo.test:"+port+"/spoofed")
	if resp.StatusCode != 200 || !strings.Contains(body, "/spoofed") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if toolMeta(e.waitFlow(byPath("/spoofed")), "dns") != "127.0.0.1" {
		t.Fatal("DNS spoof not recorded")
	}
}

func TestNoCaching(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("X-Conditional", r.Header.Get("If-None-Match"))
		_, _ = io.WriteString(w, "fresh")
	}))
	defer ts.Close()
	e.update(func(d *rules.Data) { d.NoCaching = true })
	req, _ := http.NewRequest("GET", ts.URL+"/cached", nil)
	req.Header.Set("If-None-Match", `"abc"`)
	resp, err := e.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("X-Conditional") != "" || resp.Header.Get("ETag") != "" || !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("caching headers kept: %v", resp.Header)
	}
}

func TestReplayAndRepeat(t *testing.T) {
	e := newEnv(t)
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s %s %s", r.Method, r.Header.Get("X-Test"), b)
	}))
	defer ts.Close()
	var h flow.Header
	h.Set("X-Test", "replayed")
	h.Set("Content-Length", "999")
	f, err := e.proxy.Replay(t.Context(), Message{Method: "post", URL: ts.URL + "/again", Header: h, Body: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	if f.StatusCode() != 200 || string(f.Response.BodyData) != "POST replayed body" {
		t.Fatalf("replay %d %q", f.StatusCode(), f.Response.BodyData)
	}
	if f.Client.Name != "ProxyGo" {
		t.Fatalf("client %q", f.Client.Name)
	}
	e.waitFlow(byPath("/again"))

	results := e.proxy.Repeat(t.Context(), MessageOf(f), 6, 3, 0)
	for i, r := range results {
		if r.Err != nil || r.Flow.StatusCode() != 200 {
			t.Fatalf("repeat %d: %v", i, r.Err)
		}
	}
	if hits.Load() != 7 {
		t.Fatalf("%d requests reached the server", hits.Load())
	}
	start := time.Now()
	e.proxy.Repeat(t.Context(), MessageOf(f), 3, 3, 80*time.Millisecond)
	if took := time.Since(start); took < 160*time.Millisecond {
		t.Fatalf("3 requests 80 ms apart took %v", took)
	}
	if _, err := e.proxy.Replay(t.Context(), Message{URL: "ftp://x"}); err == nil {
		t.Fatal("bad scheme replayed")
	}
}

func TestRepeatEncodedBody(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%q %s", r.Header.Get("Content-Encoding"), b)
	}))
	defer ts.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"event":"track"}`))
	_ = zw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/batch", bytes.NewReader(gz.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := e.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	f := e.waitFlow(byPath("/batch"))
	again, err := e.proxy.Replay(t.Context(), MessageOf(f))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(again.Response.BodyData); got != `"" {"event":"track"}` {
		t.Fatalf("the server got %s", got)
	}
}

func TestUpstreamProxy(t *testing.T) {
	upstream := newEnv(t)
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	tls := httptest.NewTLSServer(echoServer())
	defer tls.Close()
	upstream.trustServer(tls)
	e.trustServer(tls)
	e.update(func(d *rules.Data) {
		d.Upstream = rules.Upstream{Enabled: true, HTTP: upstream.proxy.Addr(), HTTPS: upstream.proxy.Addr()}
	})
	get(t, e.client(false), ts.URL+"/chained")
	upstream.waitFlow(byPath("/chained"))
	e.waitFlow(byPath("/chained"))

	e.update(func(d *rules.Data) {
		d.SSL.Enabled = true
		d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: "a", Enabled: true, List: "include", Target: "127.0.0.1"})
	})
	get(t, e.client(false), tls.URL+"/secure-chained")
	e.waitFlow(byPath("/secure-chained"))
	tunneled := false
	for _, f := range upstream.store.Snapshot() {
		tunneled = tunneled || f.MethodName() == "CONNECT"
		if strings.Contains(f.URL(), "/secure-chained") {
			t.Fatal("the upstream proxy saw the decrypted request")
		}
	}
	if !tunneled {
		t.Fatal("no tunnel through the upstream proxy")
	}
}

func TestTLSKeyLog(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewTLSServer(echoServer())
	defer ts.Close()
	e.trustServer(ts)
	keyLog := filepath.Join(t.TempDir(), "keys.log")
	e.update(func(d *rules.Data) {
		d.KeyLogPath = keyLog
		d.SSL.Enabled = true
		d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: "a", Enabled: true, List: "include", Target: "127.0.0.1"})
	})
	get(t, e.client(false), ts.URL+"/logged")
	e.waitFlow(byPath("/logged"))
	b, err := os.ReadFile(keyLog) // #nosec G304 -- a file of the test's directory.
	if err != nil || !bytes.Contains(b, []byte("CLIENT_")) && !bytes.Contains(b, []byte("TRAFFIC_SECRET")) {
		t.Fatalf("key log %q %v", b, err)
	}
}
