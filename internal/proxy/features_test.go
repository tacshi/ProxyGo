package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
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
)

func TestTLSDetailsAndPinning(t *testing.T) {
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
	get(t, e.client(true), ts.URL+"/tls")
	f := e.waitFlow(byPath("/tls"))
	if f.TLS == nil || f.TLS.Client == nil || f.TLS.Server == nil {
		t.Fatalf("TLS details %+v", f.TLS)
	}
	if f.TLS.Client.ALPN != "h2" || !strings.HasPrefix(f.TLS.Client.Version, "TLS 1.") || len(f.TLS.Client.Offered) == 0 {
		t.Errorf("client side %+v", f.TLS.Client)
	}
	if len(f.TLS.Server.Certificates) == 0 || f.TLS.Server.Certificates[0].SHA256 == "" || f.TLS.Server.CipherSuite == "" {
		t.Errorf("server side %+v", f.TLS.Server)
	}

	if _, err := e.client(false, x509.NewCertPool()).Get(ts.URL + "/pinned"); err == nil {
		t.Fatal("trusted")
	}
	fail := e.waitFlow(func(f *flow.Flow) bool { return f.MethodName() == "CONNECT" && f.IsError() })
	if fail.TLS == nil || fail.TLS.Client == nil || !fail.TLS.Client.PinningLikely || fail.TLS.Client.Error == "" {
		t.Errorf("handshake failure %+v", fail.TLS)
	}
}

func selfSigned(t *testing.T, names ...string) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return certPath, keyPath, cert
}

func TestCustomServerCertificate(t *testing.T) {
	e := newEnv(t)
	certPath, keyPath, own := selfSigned(t, "pinned.test")
	e.update(func(d *rules.Data) {
		d.SSL.Enabled = true
		d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: "a", Enabled: true, List: "include", Target: "*"})
		d.ServerCerts = append(d.ServerCerts, &rules.ServerCertificate{ID: "s", Enabled: true, CertPath: certPath, KeyPath: keyPath})
	})
	seen := func(host string) *x509.Certificate {
		c, err := net.Dial("tcp", e.proxy.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
		buf := make([]byte, 39)
		if _, err := c.Read(buf); err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		return tc.ConnectionState().PeerCertificates[0]
	}
	if got := seen("pinned.test"); !got.Equal(own) {
		t.Errorf("pinned.test got %s, not its own certificate", got.Subject)
	}
	if got := seen("other.test"); got.Equal(own) || got.Subject.CommonName != "other.test" {
		t.Errorf("other.test got %s", got.Subject)
	}
}

func TestPACChoosesTheUpstream(t *testing.T) {
	upstream := newEnv(t)
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	pacSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `function FindProxyForURL(url, host) {
			if (url.indexOf("/via-pac") >= 0) return "PROXY %s; DIRECT";
			return "DIRECT";
		}`, upstream.proxy.Addr())
	}))
	defer pacSrv.Close()
	e.update(func(d *rules.Data) { d.Upstream = rules.Upstream{Enabled: true, PACURL: pacSrv.URL + "/proxy.pac"} })
	get(t, e.client(false), ts.URL+"/via-pac")
	upstream.waitFlow(byPath("/via-pac"))
	get(t, e.client(false), ts.URL+"/direct")
	e.waitFlow(byPath("/direct"))
	for _, f := range upstream.store.Snapshot() {
		if strings.Contains(f.URL(), "/direct") {
			t.Error("a DIRECT request went through the upstream")
		}
	}
}

func TestBlockThisApp(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	e.update(func(d *rules.Data) { d.BlockedApps = []*rules.AppRule{{ID: "a", Enabled: true, AppName: "ProxyGo"}} })
	f, err := e.proxy.Replay(context.Background(), Message{Method: "GET", URL: ts.URL + "/app"})
	if err != nil || f.StatusCode() != http.StatusForbidden || toolMeta(f, "blockedApp") != "ProxyGo" {
		t.Errorf("%v %s %v", err, f.StatusLine(), f.ToolMetadata)
	}
	e.update(func(d *rules.Data) { d.BlockedApps[0].AppName = "Other" })
	if f, _ := e.proxy.Replay(context.Background(), Message{Method: "GET", URL: ts.URL + "/app"}); f.StatusCode() != 200 {
		t.Errorf("another app's rule blocked ProxyGo: %s", f.StatusLine())
	}
}

func TestBreakpointDecisionsAndDiagnostics(t *testing.T) {
	var decide func(*Pause) (Message, bool)
	e := newEnv(t, func(o *Options) {
		o.Breakpoint = func(_ context.Context, p *Pause) (Message, bool) { return decide(p) }
	})
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.DiagnosticHeaders = true
		d.Breakpoints = []*rules.BreakpointRule{{ID: "b", Enabled: true, Name: "Pause API", Matcher: rules.Matcher{URL: ts.URL + "/bp"}, Phase: rules.PhaseRequest}}
		d.MapLocal = []*rules.MapLocalRule{{ID: "m", Enabled: true, Name: "Local users", Matcher: rules.Matcher{URL: ts.URL + "/local"}, Body: "{}"}}
	})
	var h flow.Header
	h.Set("Content-Type", "text/plain")
	decide = func(p *Pause) (Message, bool) {
		m := p.Message
		m.Respond, m.StatusCode, m.Header, m.Body = true, http.StatusServiceUnavailable, h, []byte("down")
		return m, true
	}
	resp, body := get(t, e.client(false), ts.URL+"/bp")
	if resp.StatusCode != 503 || body != "down" || resp.Header.Get("X-ProxyGo-Breakpoint") != "Pause API" {
		t.Errorf("respond: %d %q %v", resp.StatusCode, body, resp.Header)
	}

	decide = func(p *Pause) (Message, bool) { return Message{Drop: true}, false }
	if _, err := e.client(false).Get(ts.URL + "/bp?drop"); err == nil {
		t.Error("a dropped connection answered")
	}
	f := e.waitFlow(byPath("/bp?drop"))
	if !f.IsError() || !strings.Contains(f.ErrorText(), "dropped") {
		t.Errorf("drop recorded as %s", f.StatusLine())
	}

	resp, _ = get(t, e.client(false), ts.URL+"/local")
	if resp.Header.Get("X-ProxyGo-Map-Local") != "Local users" {
		t.Errorf("Map Local's diagnostic header: %v", resp.Header)
	}
	e.update(func(d *rules.Data) { d.DiagnosticHeaders = false })
	if resp, _ := get(t, e.client(false), ts.URL+"/local"); resp.Header.Get("X-ProxyGo-Map-Local") != "" {
		t.Error("diagnostic headers while off")
	}
}

func TestListenLocalhostOnly(t *testing.T) {
	e := newEnv(t)
	if err := e.proxy.SetListen("127.0.0.1:0", "tcp4"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.proxy.Addr(), "127.0.0.1:") {
		t.Fatalf("listening on %s", e.proxy.Addr())
	}
	port := freePort(t)
	e.update(func(d *rules.Data) { d.Socks = rules.Socks{Enabled: true, Port: port} })
	waitListening(t, port)
	if _, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), time.Second); err == nil {
		t.Error("SOCKS took an IPv6 connection on an IPv4-only proxy")
	}
}

func TestAskForNewDevices(t *testing.T) {
	store := rules.Memory(rules.Data{Access: rules.AccessControl{Mode: rules.AccessAsk, IPs: []string{"10.0.0.5"}}})
	var asks atomic.Int32
	answer := make(chan bool)
	s := New(Options{Rules: store, AskDevice: func(ip string) bool {
		asks.Add(1)
		ok := <-answer
		if ok {
			store.Update(func(d *rules.Data) { d.Access.IPs = append(d.Access.IPs, ip) })
		}
		return ok
	}})
	if !s.allowed("10.0.0.5:5000") || !s.allowed("127.0.0.1:5000") {
		t.Fatal("a listed device and this Mac connect without asking")
	}
	results := make(chan bool, 3)
	for range 3 {
		go func() { results <- s.allowed("10.0.0.9:5000") }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for asks.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	answer <- true
	for range 3 {
		if !<-results {
			t.Fatal("an allowed device was turned away")
		}
	}
	if !s.allowed("10.0.0.9:6000") || asks.Load() != 1 {
		t.Fatalf("asked %d times", asks.Load())
	}
	go func() { answer <- false }()
	if s.allowed("10.0.0.7:5000") || s.allowed("10.0.0.7:5001") || asks.Load() != 2 {
		t.Fatalf("refusal: asked %d times", asks.Load())
	}
}
