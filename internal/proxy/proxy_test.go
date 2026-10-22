package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxygo/internal/certs"
	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/store"
)

type env struct {
	t     *testing.T
	store *store.Store
	rules *rules.Store
	certs *certs.Manager
	proxy *Server
	url   *url.URL
}

func newEnv(t *testing.T, configure ...func(*Options)) *env {
	t.Helper()
	cm, err := certs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, store: store.New(1000), rules: rules.Memory(rules.Data{}), certs: cm}
	opts := Options{Addr: "127.0.0.1:0", Certs: cm, Rules: e.rules, Sink: e.store, RootCAs: x509.NewCertPool()}
	for _, fn := range configure {
		fn(&opts)
	}
	e.proxy = New(opts)
	if err := e.proxy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.proxy.Stop)
	e.url = &url.URL{Scheme: "http", Host: e.proxy.Addr()}
	return e
}

func (e *env) trustServer(ts *httptest.Server) {
	e.proxy.opts.RootCAs.AddCert(ts.Certificate())
}

func (e *env) client(h2 bool, roots ...*x509.CertPool) *http.Client {
	pool := e.certs.Pool()
	if len(roots) > 0 {
		pool = roots[0]
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(e.url),
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			ForceAttemptHTTP2: h2,
			DisableKeepAlives: !h2,
		},
	}
}

func (e *env) update(fn func(*rules.Data)) { e.rules.Update(fn) }

func (e *env) waitFlow(match func(*flow.Flow) bool) *flow.Flow {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range e.store.Snapshot() {
			if match(f) && !f.IsActive() {
				return f
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	var urls []string
	for _, f := range e.store.Snapshot() {
		urls = append(urls, f.MethodName()+" "+f.URL()+" "+f.StatusText())
	}
	e.t.Fatalf("no matching flow; have %v", urls)
	return nil
}

func byPath(path string) func(*flow.Flow) bool {
	return func(f *flow.Flow) bool { return strings.Contains(f.URL(), path) }
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func echoServer() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Proto", r.Proto)
		w.Header().Set("X-Seen-Header", r.Header.Get("X-Test"))
		w.Header().Set("X-Host", r.Host)
		_, _ = io.WriteString(w, `{"method":"`+r.Method+`","path":"`+r.URL.RequestURI()+`","body":"`+string(body)+`"}`)
	})
}

func TestForwardHTTP(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()

	resp, body := get(t, e.client(false), ts.URL+"/hello?x=1")
	if resp.StatusCode != 200 || !strings.Contains(body, `"path":"/hello?x=1"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/submit", strings.NewReader("payload"))
	req.Header.Set("X-Test", "yes")
	resp, err := e.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("X-Seen-Header") != "yes" {
		t.Fatal("header not forwarded")
	}

	f := e.waitFlow(byPath("/hello"))
	if f.StatusCode() != 200 || f.MethodName() != "GET" || f.Host() != "127.0.0.1" {
		t.Fatalf("flow %s %s %d", f.MethodName(), f.URL(), f.StatusCode())
	}
	if f.Request.Header.Get("Host") == "" || f.Response.Header.Get("Content-Type") != "application/json" {
		t.Fatal("headers not recorded")
	}
	if f.Timing.RequestStartedAt == nil || f.Timing.ResponseEndedAt == nil || f.Duration() <= 0 {
		t.Fatal("timings not recorded")
	}
	if f.Summary.ServerIPAddress != "127.0.0.1" {
		t.Fatalf("server IP %q", f.Summary.ServerIPAddress)
	}
	p := e.waitFlow(byPath("/submit"))
	if string(p.Request.BodyData) != "payload" || !strings.Contains(string(p.Response.BodyData), `"body":"payload"`) {
		t.Fatalf("bodies %q %q", p.Request.BodyData, p.Response.BodyData)
	}
	if up, down := e.store.Traffic(); up == 0 || down == 0 {
		t.Fatal("traffic not counted")
	}
}

func TestTunnelWithoutDecryption(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewTLSServer(echoServer())
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	resp, body := get(t, e.client(false, pool), ts.URL+"/secret")
	if resp.StatusCode != 200 || !strings.Contains(body, "/secret") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	f := e.waitFlow(func(f *flow.Flow) bool { return f.MethodName() == "CONNECT" })
	if f.StatusCode() != 200 || !f.IsTunnel() {
		t.Fatalf("tunnel flow %d", f.StatusCode())
	}
	if strings.Contains(f.URL(), "/secret") {
		t.Fatal("encrypted path leaked into the tunnel flow")
	}
	if md, _ := f.ToolMetadata.(map[string]any); md["tunnel"] == nil {
		t.Fatal("tunnel byte counts missing")
	}
}

func TestDecryptHTTP1AndHTTP2(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewUnstartedServer(echoServer())
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	e.trustServer(ts)
	e.update(func(d *rules.Data) {
		d.SSL.Enabled = true
		d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: "a", Enabled: true, List: "include", Target: "127.0.0.1"})
	})

	resp, body := get(t, e.client(true), ts.URL+"/h2?x=1")
	if resp.ProtoMajor != 2 {
		t.Fatalf("client spoke %s to the proxy", resp.Proto)
	}
	if resp.Header.Get("X-Proto") != "HTTP/2.0" {
		t.Fatalf("proxy spoke %s to the server", resp.Header.Get("X-Proto"))
	}
	if !strings.Contains(body, "/h2?x=1") {
		t.Fatal(body)
	}
	f := e.waitFlow(byPath("/h2"))
	if f.HTTPVersionLabel() != "h2" || !f.IsSSL || f.StatusCode() != 200 {
		t.Fatalf("flow %s ssl %v status %d", f.HTTPVersionLabel(), f.IsSSL, f.StatusCode())
	}
	if f.Timing.ClientTLSEndedAt == nil {
		t.Fatal("client TLS timing missing")
	}

	resp, _ = get(t, e.client(false), ts.URL+"/h1")
	if resp.ProtoMajor != 1 {
		t.Fatalf("HTTP/1.1 client got %s", resp.Proto)
	}
	if e.waitFlow(byPath("/h1")).HTTPVersionLabel() != "h1" {
		t.Fatal("h1 flow labeled otherwise")
	}
	for _, f := range e.store.Snapshot() {
		if f.MethodName() == "CONNECT" {
			t.Fatal("a decrypted tunnel was recorded as CONNECT")
		}
	}
}

func TestUntrustedClientRecordsHandshakeFailure(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewTLSServer(echoServer())
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.SSL.Enabled = true
		d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: "a", Enabled: true, List: "include", Target: "*"})
	})
	if _, err := e.client(false, x509.NewCertPool()).Get(ts.URL + "/"); err == nil {
		t.Fatal("client trusted a certificate it should not")
	}
	f := e.waitFlow(func(f *flow.Flow) bool { return f.MethodName() == "CONNECT" })
	if !f.IsError() || !strings.Contains(f.ErrorText(), "ProxyGo") {
		t.Fatalf("handshake failure not explained: %q", f.ErrorText())
	}
}

func TestPlainHTTPThroughConnect(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	c, err := net.Dial("tcp", e.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	host := strings.TrimPrefix(ts.URL, "http://")
	_, _ = io.WriteString(c, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	buf := make([]byte, 39)
	if _, err := io.ReadFull(c, buf); err != nil || !strings.Contains(string(buf), "200") {
		t.Fatalf("connect: %q %v", buf, err)
	}
	_, _ = io.WriteString(c, "GET /inside HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "/inside") {
		t.Fatalf("response %q", b)
	}
	f := e.waitFlow(byPath("/inside"))
	if f.StatusCode() != 200 || f.IsSSL {
		t.Fatalf("flow %d ssl %v", f.StatusCode(), f.IsSSL)
	}
}

func TestPausedRecording(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	e.proxy.SetPaused(true)
	resp, _ := get(t, e.client(false), ts.URL+"/quiet")
	if resp.StatusCode != 200 {
		t.Fatal("traffic stopped while paused")
	}
	time.Sleep(50 * time.Millisecond)
	if e.store.Len() != 0 {
		t.Fatal("flow recorded while paused")
	}
	e.proxy.SetPaused(false)
	get(t, e.client(false), ts.URL+"/loud")
	e.waitFlow(byPath("/loud"))
}

func TestCertificatePageAndSelfRequests(t *testing.T) {
	e := newEnv(t)
	resp, body := get(t, e.client(false), "http://proxy.go/ssl")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("certificate: %d %.40q", resp.StatusCode, body)
	}
	resp, body = get(t, e.client(false), "http://proxy.go/ssl.crt")
	if resp.Header.Get("Content-Type") != "application/x-x509-ca-cert" || string(e.certs.CertDER()) != body {
		t.Fatal("DER certificate")
	}
	direct := &http.Client{Timeout: 5 * time.Second}
	resp, body = get(t, direct, "http://"+e.proxy.Addr()+"/")
	if resp.StatusCode != 200 || !strings.Contains(body, "Download Certificate") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	resp, _ = get(t, e.client(false), "http://"+e.proxy.Addr()+"/")
	if resp.StatusCode != 200 {
		t.Fatalf("self request: %d", resp.StatusCode)
	}
	if e.store.Len() != 0 {
		t.Fatal("ProxyGo's own pages were recorded")
	}
}

func TestAccessControl(t *testing.T) {
	e := newEnv(t)
	e.update(func(d *rules.Data) { d.Access = rules.AccessControl{Mode: rules.AccessLocal} })
	if !e.proxy.allowed("127.0.0.1:5000") || e.proxy.allowed("203.0.113.9:5000") {
		t.Fatal("local-only access")
	}
	e.update(func(d *rules.Data) {
		d.Access = rules.AccessControl{Mode: rules.AccessList, IPs: []string{"203.0.113.0/24"}}
	})
	if !e.proxy.allowed("203.0.113.9:5000") {
		t.Fatal("listed range denied")
	}
}

func TestSetAddr(t *testing.T) {
	e := newEnv(t)
	old := e.proxy.Addr()
	if err := e.proxy.SetAddr("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if e.proxy.Addr() == old || e.proxy.Port() == 0 {
		t.Fatal("address did not change")
	}
	if _, err := net.DialTimeout("tcp", old, 200*time.Millisecond); err == nil {
		t.Fatal("old listener still open")
	}
}
