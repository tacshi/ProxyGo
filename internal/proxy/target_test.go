package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/script"
)

func rawServer(t *testing.T, network, addr, reply string) (net.Listener, chan string) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	heads := make(chan string, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				var head strings.Builder
				for {
					l, err := br.ReadString('\n')
					head.WriteString(l)
					if err != nil || l == "\r\n" {
						break
					}
				}
				heads <- head.String()
				_, _ = io.WriteString(c, reply)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln, heads
}

func rawRequest(t *testing.T, proxyAddr, req string) string {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, req)
	b, _ := io.ReadAll(c)
	return string(b)
}

func nextHead(t *testing.T, heads chan string) string {
	t.Helper()
	select {
	case h := <-heads:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("the server got no request")
		return ""
	}
}

const okReply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

var rawTargets = []string{
	"/a|b/{c}/%7c/%2F/x+y;z/'q'/~u//dbl/%41?q=%20+|&r=a%2Bb&s=\"x\"",
	"/sig?b=2&a=1&b=3",
	"/%E4%B8%AD/中",
	"/empty?",
}

func TestRequestTargetIsForwardedAsSent(t *testing.T) {
	e := newEnv(t)
	ln, heads := rawServer(t, "tcp", "127.0.0.1:0", okReply)
	for _, target := range rawTargets {
		resp := rawRequest(t, e.proxy.Addr(), fmt.Sprintf("GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ln.Addr(), target, ln.Addr()))
		if !strings.HasPrefix(resp, "HTTP/1.1 200") {
			t.Fatalf("%s: %q", target, resp)
		}
		if line, _, _ := strings.Cut(nextHead(t, heads), "\r\n"); line != "GET "+target+" HTTP/1.1" {
			t.Errorf("sent %q, the server got %q", target, line)
		}
		f := e.waitFlow(func(f *flow.Flow) bool { return f.Request.URI == target })
		if f.URL() != "http://"+ln.Addr().String()+target {
			t.Errorf("flow URL %q", f.URL())
		}
	}
}

func TestRequestTargetThroughUpstreamProxy(t *testing.T) {
	upstream := newEnv(t)
	e := newEnv(t)
	e.update(func(d *rules.Data) {
		d.Upstream = rules.Upstream{Enabled: true, HTTP: upstream.proxy.Addr(), HTTPS: upstream.proxy.Addr()}
	})
	ln, heads := rawServer(t, "tcp", "127.0.0.1:0", okReply)
	target := rawTargets[0]
	resp := rawRequest(t, e.proxy.Addr(), fmt.Sprintf("GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ln.Addr(), target, ln.Addr()))
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("%q", resp)
	}
	if line, _, _ := strings.Cut(nextHead(t, heads), "\r\n"); line != "GET "+target+" HTTP/1.1" {
		t.Fatalf("the server got %q", line)
	}
	upstream.waitFlow(func(f *flow.Flow) bool { return f.Request.URI == target })
}

func TestRequestTargetDecryptedHTTP2(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto+" "+r.RequestURI)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	e.trustServer(ts)
	e.update(func(d *rules.Data) {
		d.SSL.Enabled = true
		d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: "a", Enabled: true, List: "include", Target: "127.0.0.1"})
	})
	for _, h2 := range []bool{true, false} {
		target := "/a|b/%2F/%41/{x}?q=|&r=%2B"
		req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
		req.URL.Opaque, req.URL.RawQuery = "/a|b/%2F/%41/{x}", "q=|&r=%2B"
		resp, err := e.client(h2).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if want := "HTTP/2.0 " + target; string(body) != want {
			t.Errorf("h2 client %v: the server got %q, want %q", h2, body, want)
		}
	}
}

func TestIPv6Upstream(t *testing.T) {
	e := newEnv(t)
	ln, heads := rawServer(t, "tcp6", "[::1]:0", okReply)
	resp := rawRequest(t, e.proxy.Addr(), fmt.Sprintf("GET http://%s/v6 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ln.Addr(), ln.Addr()))
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("%q", resp)
	}
	if head := nextHead(t, heads); !strings.Contains(head, "Host: "+ln.Addr().String()+"\r\n") {
		t.Fatalf("the server got %q", head)
	}
	if f := e.waitFlow(byPath("/v6")); f.URL() != "http://"+ln.Addr().String()+"/v6" {
		t.Fatalf("flow URL %q", f.URL())
	}
}

func TestWebSocketUpgradeIsForwardedAsSent(t *testing.T) {
	e := newEnv(t)
	ln, heads := rawServer(t, "tcp", "127.0.0.1:0", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: graphql-ws\r\n\r\n")
	c, err := net.Dial("tcp", e.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "GET http://%s/ws|x?a=%%2F HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: graphql-ws, graphql-transport-ws\r\n\r\n", ln.Addr(), ln.Addr())
	head := nextHead(t, heads)
	if line, _, _ := strings.Cut(head, "\r\n"); line != "GET /ws|x?a=%2F HTTP/1.1" {
		t.Errorf("the server got %q", line)
	}
	if strings.Contains(head, "User-Agent") {
		t.Errorf("the proxy added a User-Agent: %q", head)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Protocol") != "graphql-ws" {
		t.Fatalf("client got %d %v", resp.StatusCode, resp.Header)
	}
}

func TestReverseProxyKeepsRequestTarget(t *testing.T) {
	e := newEnv(t)
	ln, heads := rawServer(t, "tcp", "127.0.0.1:0", okReply)
	port := freePort(t)
	e.update(func(d *rules.Data) {
		d.ReverseProxies = append(d.ReverseProxies, &rules.ReverseProxy{ID: "r", Enabled: true, ListenPort: port, Target: "http://" + ln.Addr().String() + "/base?k=1"})
	})
	waitListening(t, port)
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	resp := rawRequest(t, addr, "GET /a|b/%2F?q=| HTTP/1.1\r\nHost: "+addr+"\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("%q", resp)
	}
	if line, _, _ := strings.Cut(nextHead(t, heads), "\r\n"); line != "GET /base/a|b/%2F?k=1&q=| HTTP/1.1" {
		t.Fatalf("the server got %q", line)
	}
}

func TestLargeResponseWithScriptIsNotTruncated(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Scripts = script.New() })
	size := int64(maxBodyCapture + 1<<20)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(size))
		_, _ = io.CopyN(w, zeros{}, size)
	}))
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.Scripts = append(d.Scripts, &rules.ScriptRule{ID: "s", Enabled: true, Name: "big", Matcher: rules.Matcher{URL: "*"}, OnResponse: true,
			Script: `function onResponse(c, u, req, res) { res.headers["X-Scripted"] = "1"; return res; }`})
	})
	resp, err := e.client(false).Get(ts.URL + "/big")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil || n != size {
		t.Fatalf("got %d of %d bytes: %v", n, size, err)
	}
	f := e.waitFlow(byPath("/big"))
	if m, _ := f.ToolMetadata.(map[string]any); m["bodyTooLarge"] == nil {
		t.Fatalf("metadata %v", f.ToolMetadata)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
