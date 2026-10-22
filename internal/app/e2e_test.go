package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/session"
)

type live struct {
	t      *testing.T
	a      *App
	client *http.Client
	plain  *httptest.Server
	secure *httptest.Server
	other  *httptest.Server
}

func newLive(t *testing.T) *live {
	t.Helper()
	a, _ := testApp(t)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-If-None-Match", r.Header.Get("If-None-Match"))
		_, _ = fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.RequestURI(), b)
	})
	l := &live{t: t, a: a, plain: httptest.NewServer(echo), secure: httptest.NewTLSServer(echo),
		other: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "other %s", r.URL.RequestURI())
		}))}
	t.Cleanup(l.plain.Close)
	t.Cleanup(l.secure.Close)
	t.Cleanup(l.other.Close)
	servers := x509.NewCertPool()
	servers.AddCert(l.secure.Certificate())
	a.proxy = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Certs: a.certs, Rules: a.rules, Scripts: a.scripts,
		Sink: a.store, Breakpoint: a.breakpoint, RootCAs: servers})
	if err := a.proxy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.proxy.Stop)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(a.certs.CertPEM())
	roots.AddCert(l.secure.Certificate())
	proxyURL, _ := url.Parse("http://" + a.proxy.Addr())
	l.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true,
	}}
	return l
}

func (l *live) do(method, rawURL, body string, header ...string) (int, string, http.Header) {
	l.t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		l.t.Fatal(err)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := l.client.Do(req)
	if err != nil {
		l.t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (l *live) flow(match func(*flow.Flow) bool) *flow.Flow {
	l.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range l.a.store.Snapshot() {
			if !f.IsActive() && match(f) {
				return f
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.t.Fatal("no such flow")
	return nil
}

func withPath(p string) func(*flow.Flow) bool {
	return func(f *flow.Flow) bool { return strings.HasPrefix(f.URLPath(), p) }
}

func (l *live) saveRule(kind string, edit func(draft any)) {
	l.t.Helper()
	st := l.a.toolState(kind)
	if !st.editing {
		l.t.Fatalf("%s: no rule open", kind)
	}
	edit(st.draft)
	l.a.saveDraft(ruleKinds[kind], st)
}

func TestFeaturesEndToEnd(t *testing.T) {
	t.Run("records HTTP and shows it", func(t *testing.T) {
		l := newLive(t)
		tt := ui.NewTester(l.a.view, 1440, 900)
		if code, body, _ := l.do("POST", l.plain.URL+"/hello?x=1", "hi"); code != 200 || body != "POST /hello?x=1 hi" {
			t.Fatalf("%d %q", code, body)
		}
		f := l.flow(withPath("/hello"))
		if f.StatusCode() != 200 || string(f.Request.BodyData) != "hi" || string(f.Response.BodyData) != "POST /hello?x=1 hi" {
			t.Fatalf("flow %d %q %q", f.StatusCode(), f.Request.BodyData, f.Response.BodyData)
		}
		tt.Frame()
		if !tt.HasText(l.plain.URL + "/hello?x=1") {
			t.Fatal("not in the table")
		}
	})

	t.Run("pauses recording", func(t *testing.T) {
		l := newLive(t)
		l.a.setPaused(true)
		l.do("GET", l.plain.URL+"/unseen", "")
		l.a.setPaused(false)
		l.do("GET", l.plain.URL+"/seen", "")
		l.flow(withPath("/seen"))
		for _, f := range l.a.store.Snapshot() {
			if strings.HasPrefix(f.URLPath(), "/unseen") {
				t.Fatal("recorded while paused")
			}
		}
	})

	t.Run("decrypts HTTPS once SSL Proxying is on", func(t *testing.T) {
		l := newLive(t)
		if code, _, _ := l.do("GET", l.secure.URL+"/before", ""); code != 200 {
			t.Fatalf("tunnel %d", code)
		}
		l.client.CloseIdleConnections()
		tunnel := l.flow(func(f *flow.Flow) bool { return f.IsTunnel() })
		if tunnel.StatusCode() != 200 {
			t.Fatalf("tunnel %s", tunnel.StatusLine())
		}
		l.a.enableSSL("127.0.0.1", false)
		if code, body, _ := l.do("GET", l.secure.URL+"/after", ""); code != 200 || body != "GET /after " {
			t.Fatalf("%d %q", code, body)
		}
		f := l.flow(withPath("/after"))
		if !f.IsHTTPS() || f.IsTunnel() || string(f.Response.BodyData) != "GET /after " || f.Request.Version.Major != 2 {
			t.Fatalf("decrypted flow: https %v tunnel %v body %q HTTP/%d", f.IsHTTPS(), f.IsTunnel(), f.Response.BodyData, f.Request.Version.Major)
		}
	})

	t.Run("Map Local from a flow", func(t *testing.T) {
		l := newLive(t)
		l.do("GET", l.plain.URL+"/item", "")
		l.a.mapLocalFromFlow(l.flow(withPath("/item")))
		st := l.a.toolState("maplocal")
		l.saveRule("maplocal", func(any) { st.body.Buffer.Set(`{"mocked":true}`) })
		code, body, h := l.do("GET", l.plain.URL+"/item?any=query", "")
		if code != 200 || body != `{"mocked":true}` || h.Get("Content-Type") != "text/plain" {
			t.Fatalf("%d %q %q", code, body, h.Get("Content-Type"))
		}
		if f := l.flow(withPath("/item?any")); !strings.Contains(fmt.Sprint(f.ToolMetadata), "mapLocal") {
			t.Fatalf("not marked: %v", f.ToolMetadata)
		}
	})

	t.Run("Map Remote from a flow", func(t *testing.T) {
		l := newLive(t)
		l.do("GET", l.plain.URL+"/api/users", "")
		l.a.mapRemoteFromFlow(l.flow(withPath("/api/users")))
		l.saveRule("mapremote", func(d any) { d.(*rules.MapRemoteRule).NewURL = l.other.URL + "/v2/users" })
		if code, body, _ := l.do("GET", l.plain.URL+"/api/users", ""); code != 200 || body != "other /v2/users" {
			t.Fatalf("%d %q", code, body)
		}
	})

	t.Run("Breakpoint edits the request and the response", func(t *testing.T) {
		l := newLive(t)
		l.do("POST", l.plain.URL+"/order", "original")
		l.a.breakpointFromFlow(l.flow(withPath("/order")))
		bp := ui.NewTester(func(c *ui.Context) { l.a.toolWindow(c, "bpedit") }, 1000, 700)
		got := make(chan string, 1)
		go func() {
			_, body, _ := l.do("POST", l.plain.URL+"/order", "original")
			got <- body
		}()
		wait := func(response bool) *pending {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				bp.Frame()
				for _, pd := range l.a.pauses {
					if pd.Response == response {
						return pd
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("not paused at the %v phase", map[bool]string{true: "response", false: "request"}[response])
			return nil
		}
		wait(false).edit.body.Buffer.Set("edited request")
		mustClick(t, bp, "Execute")
		resp := wait(true)
		if b := resp.edit.body.Buffer.String(); b != "POST /order edited request" {
			t.Fatalf("the server got %q", b)
		}
		resp.edit.body.Buffer.Set("edited response")
		mustClick(t, bp, "Execute")
		if body := <-got; body != "edited response" {
			t.Fatalf("the client got %q", body)
		}
	})

	t.Run("Block and Allow Lists", func(t *testing.T) {
		l := newLive(t)
		l.do("GET", l.plain.URL+"/ads", "")
		l.a.blockFromFlow(l.flow(withPath("/ads")), false)
		if code, _, _ := l.do("GET", l.plain.URL+"/ads", ""); code != http.StatusForbidden {
			t.Fatalf("blocked %d", code)
		}
		l.a.setTool(rules.ToolBlock, false)
		if code, _, _ := l.do("GET", l.plain.URL+"/ads", ""); code != 200 {
			t.Fatalf("with the Block List off %d", code)
		}
		l.a.blockFromFlow(l.flow(withPath("/ads")), true)
		if code, _, _ := l.do("GET", l.plain.URL+"/ads", ""); code != 200 {
			t.Fatalf("allowed %d", code)
		}
		if code, _, _ := l.do("GET", l.other.URL+"/elsewhere", ""); code != http.StatusForbidden {
			t.Fatalf("not in the Allow List %d", code)
		}
	})

	t.Run("Network Conditions from a flow", func(t *testing.T) {
		l := newLive(t)
		l.do("GET", l.plain.URL+"/slow", "")
		l.a.throttleFromFlow(l.flow(withPath("/slow")))
		l.saveRule("network", func(d any) {
			c := d.(*rules.NetworkCondition)
			c.LatencyMS, c.DownloadKBps, c.UploadKBps = 250, 0, 0
		})
		start := time.Now()
		l.do("GET", l.plain.URL+"/slow", "")
		if took := time.Since(start); took < 250*time.Millisecond {
			t.Fatalf("took %v", took)
		}
	})

	t.Run("Scripting from a flow", func(t *testing.T) {
		l := newLive(t)
		l.do("GET", l.plain.URL+"/script", "")
		l.a.scriptFromFlow(l.flow(withPath("/script")))
		r := l.a.rules.Current().Scripts[0]
		d := l.a.scriptDraft(r)
		d.code.Buffer.Set(`function onRequest(ctx, url, req) { req.headers["If-None-Match"] = "from-script"; return req; }
function onResponse(ctx, url, req, res) { res.body = "scripted " + res.headers["X-If-None-Match"]; return res; }`)
		l.a.saveScript(d)
		if l.a.scriptUI.err != "" {
			t.Fatal(l.a.scriptUI.err)
		}
		if _, body, _ := l.do("GET", l.plain.URL+"/script", ""); body != "scripted from-script" {
			t.Fatalf("%q", body)
		}
	})

	t.Run("Repeat, Advanced Repeat and Compose", func(t *testing.T) {
		l := newLive(t)
		l.do("PUT", l.plain.URL+"/again", "body")
		f := l.flow(withPath("/again"))
		l.a.repeatFlows([]*flow.Flow{f})
		l.flow(func(g *flow.Flow) bool { return g.Client.Name == "ProxyGo" && g.URLPath() == "/again" })
		l.a.advancedRepeat([]*flow.Flow{f})
		l.a.repeat.count, l.a.repeat.concurrency, l.a.repeat.delay = 3, 3, 60
		start := time.Now()
		l.a.runAdvancedRepeat()
		deadline := time.Now().Add(5 * time.Second)
		for l.a.repeat.running && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
			l.a.runQueued()
		}
		if l.a.repeat.running || time.Since(start) < 120*time.Millisecond {
			t.Fatalf("advanced repeat: running %v after %v", l.a.repeat.running, time.Since(start))
		}
		n := 0
		for _, g := range l.a.store.Snapshot() {
			if g.URLPath() == "/again" && g.Request.Method.Name == "PUT" && string(g.Request.BodyData) == "body" {
				n++
			}
		}
		if n != 5 {
			t.Fatalf("%d PUT /again flows, want 5", n)
		}
		l.a.composeFrom(f)
		l.a.compose.edit.url = l.plain.URL + "/composed"
		l.a.sendCompose()
		deadline = time.Now().Add(5 * time.Second)
		for l.a.compose.result == "" && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
			l.a.runQueued()
		}
		g, _ := l.a.store.Lookup(l.a.compose.result)
		if g == nil || string(g.Response.BodyData) != "PUT /composed body" {
			t.Fatalf("compose: %v %q", g, l.a.compose.err)
		}
	})

	t.Run("marks survive saving and opening the session", func(t *testing.T) {
		l := newLive(t)
		l.do("GET", l.plain.URL+"/keep", "")
		f := l.flow(withPath("/keep"))
		l.a.setSaved([]*flow.Flow{f}, true)
		l.a.setHighlight([]*flow.Flow{f}, "green")
		l.a.editComment([]*flow.Flow{f})
		l.a.comment.text = "look at this"
		l.a.saveComment()
		path := filepath.Join(t.TempDir(), "kept.proxygosession")
		l.a.sessionPath = path
		l.a.saveSession()
		har := filepath.Join(t.TempDir(), "kept.har")
		if err := session.WriteHAR(har, l.a.store.Snapshot()); err != nil {
			t.Fatal(err)
		}

		b, _ := testApp(t)
		b.openPath(path, false)
		b.runQueued()
		g, _ := b.store.Lookup(f.UniqueID)
		if g == nil || !g.Saved || g.Highlight != "green" || g.Comment != "look at this" || string(g.Response.BodyData) != "GET /keep " {
			t.Fatalf("reopened %+v", g)
		}
		b.openPath(har, true)
		b.runQueued()
		if b.store.Len() != 2 {
			t.Fatalf("%d flows after importing the HAR", b.store.Len())
		}
	})

	t.Run("filters and the sidebar", func(t *testing.T) {
		l := newLive(t)
		l.do("GET", l.plain.URL+"/api/v1/users", "")
		l.do("GET", l.plain.URL+"/static/app.js", "")
		l.do("GET", l.other.URL+"/elsewhere", "")
		l.flow(withPath("/elsewhere"))
		l.flow(withPath("/static"))
		l.flow(withPath("/api"))
		tt := ui.NewTester(l.a.view, 1440, 900)
		count := func() int { tt.Frame(); return len(l.a.visible) }
		if n := count(); n != 3 {
			t.Fatalf("%d flows", n)
		}
		l.a.query = "users"
		if n := count(); n != 1 {
			t.Fatalf("query: %d", n)
		}
		l.a.query = ""
		host := strings.TrimPrefix(l.plain.URL, "http://")
		hostOnly, _, _ := net.SplitHostPort(host)
		l.a.section = "src:" + "\x1f" + hostOnly + "\x1f/api"
		if n := count(); n != 1 {
			t.Fatalf("path node: %d", n)
		}
		l.a.section = "domain:" + hostOnly
		if n := count(); n != 3 {
			t.Fatalf("domain node: %d", n)
		}
		l.a.section = "all"
		l.a.deleteFlows(l.a.visible[:1])
		if n := count(); n != 2 {
			t.Fatalf("after delete: %d", n)
		}
		l.a.clearFlows()
		if n := count(); n != 0 {
			t.Fatalf("after clear: %d", n)
		}
	})

	t.Run("SOCKS proxy", func(t *testing.T) {
		l := newLive(t)
		port := freePort(t)
		l.a.rules.Update(func(d *rules.Data) { d.Socks = rules.Socks{Enabled: true, Port: port} })
		socks, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(port))
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(socks)}}
		var resp *http.Response
		var err error
		for range 50 {
			if resp, err = c.Get(l.plain.URL + "/via-socks"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		l.flow(withPath("/via-socks"))
	})

	t.Run("Reverse Proxy", func(t *testing.T) {
		l := newLive(t)
		port := freePort(t)
		l.a.rules.Update(func(d *rules.Data) {
			d.ReverseProxies = []*rules.ReverseProxy{{ID: "r", Enabled: true, ListenPort: port, Target: l.plain.URL}}
		})
		var resp *http.Response
		var err error
		for range 50 {
			if resp, err = http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/reversed"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(b) != "GET /reversed " {
			t.Fatalf("%q", b)
		}
		l.flow(withPath("/reversed"))
	})

	t.Run("DNS Spoofing", func(t *testing.T) {
		l := newLive(t)
		l.a.rules.Update(func(d *rules.Data) {
			d.DNS = []*rules.DNSRule{{ID: "d", Enabled: true, Host: "spoofed.test", IP: "127.0.0.1"}}
		})
		_, port, _ := net.SplitHostPort(strings.TrimPrefix(l.plain.URL, "http://"))
		if code, body, _ := l.do("GET", "http://spoofed.test:"+port+"/spoofed", ""); code != 200 || body != "GET /spoofed " {
			t.Fatalf("%d %q", code, body)
		}
	})

	t.Run("No Caching", func(t *testing.T) {
		l := newLive(t)
		l.a.setNoCaching(true)
		_, _, h := l.do("GET", l.plain.URL+"/cached", "", "If-None-Match", `"v1"`)
		if h.Get("X-If-None-Match") != "" || !strings.Contains(h.Get("Cache-Control"), "no-store") {
			t.Fatalf("server saw %q, cache control %q", h.Get("X-If-None-Match"), h.Get("Cache-Control"))
		}
	})

	t.Run("copies as cURL", func(t *testing.T) {
		l := newLive(t)
		l.do("POST", l.plain.URL+"/curl", `{"a":1}`, "Content-Type", "application/json")
		f := l.flow(withPath("/curl"))
		var copied string
		l.a.clipboard = func(s string) { copied = s }
		l.a.copyCode([]*flow.Flow{f}, "cURL")
		for _, want := range []string{"curl", l.plain.URL + "/curl", "-X POST", `{"a":1}`, "Content-Type: application/json"} {
			if !strings.Contains(copied, want) {
				t.Fatalf("%q lacks %q", copied, want)
			}
		}
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}
