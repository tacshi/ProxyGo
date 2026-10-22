package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

func namesOf(h flow.Header) []string {
	var out []string
	for _, e := range h.Entries {
		out = append(out, e.Key.Name)
	}
	return out
}

func TestHeadersInWireOrder(t *testing.T) {
	e := newEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	reached := make(chan []string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				names, err := headNames(bufio.NewReader(c))
				if err != nil {
					return
				}
				reached <- names
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nZ-Last: 1\r\nContent-Type: text/plain\r\nx-lower: y\r\nZ-Last: 2\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}()
		}
	}()

	c, err := net.Dial("tcp", e.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr := ln.Addr().String()
	_, _ = io.WriteString(c, "GET http://"+addr+"/order HTTP/1.1\r\nUser-Agent: t\r\nHost: "+addr+"\r\nx-custom: 1\r\nAccept: */*\r\n\r\n")
	got, err := headNames(bufio.NewReader(c))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Z-Last", "Content-Type", "x-lower", "Z-Last", "Content-Length"}; !slices.Equal(got[:len(want)], want) {
		t.Errorf("client got headers %q, want %q first", got, want)
	}
	if got, want := <-reached, []string{"User-Agent", "Host", "x-custom", "Accept"}; !slices.Equal(got, want) {
		t.Errorf("server got headers %q, want %q", got, want)
	}

	f := e.waitFlow(byPath("/order"))
	if got, want := namesOf(f.Request.Header), []string{"User-Agent", "Host", "x-custom", "Accept"}; !slices.Equal(got, want) {
		t.Errorf("request headers %q, want %q", got, want)
	}
	if got, want := namesOf(f.Response.Header), []string{"Z-Last", "Content-Type", "x-lower", "Z-Last", "Content-Length", "Connection"}; !slices.Equal(got, want) {
		t.Errorf("response headers %q, want %q", got, want)
	}
	if v := f.Response.Header.Values("Z-Last"); !slices.Equal(v, []string{"1", "2"}) {
		t.Errorf("Z-Last %q", v)
	}
}

func headNames(r *bufio.Reader) ([]string, error) {
	var names []string
	if _, err := r.ReadString('\n'); err != nil {
		return nil, err
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return names, nil
		}
		name, _, _ := strings.Cut(line, ":")
		names = append(names, name)
	}
}

func TestHTTP2HeadersAsSent(t *testing.T) {
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
	req, _ := http.NewRequest("GET", ts.URL+"/h2order", nil)
	req.Header.Set("X-Test", "yes")
	resp, err := e.client(true).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("client spoke %s", resp.Proto)
	}
	f := e.waitFlow(byPath("/h2order"))
	for _, h := range []flow.Header{f.Request.Header, f.Response.Header} {
		for _, name := range namesOf(h) {
			if name != strings.ToLower(name) {
				t.Errorf("%q not as HTTP/2 sent it", name)
			}
		}
	}
	if f.Request.Header.Get("X-Test") != "yes" || f.Response.Header.Get("X-Seen-Header") != "yes" {
		t.Fatal("headers lost")
	}
	if f.Request.Header.Get(":authority") == "" || f.Request.Header.Get("Host") != "" || f.Response.Header.Get(":status") != "200" {
		t.Fatalf("request %q response %q", namesOf(f.Request.Header), namesOf(f.Response.Header))
	}
}
