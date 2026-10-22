package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxygo/internal/flow"
)

func TestReplayWithRedirects(t *testing.T) {
	e := newEnv(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "other "+r.Method)
	}))
	defer other.Close()
	var srvURL string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/301", "/302", "/303", "/307", "/308":
			code := map[string]int{"/301": 301, "/302": 302, "/303": 303, "/307": 307, "/308": 308}[r.URL.Path]
			http.Redirect(w, r, "/end", code)
		case "/end":
			w.Header().Set("X-Auth", r.Header.Get("Authorization"))
			_, _ = io.WriteString(w, r.Method+" "+string(body)+" "+r.Header.Get("Content-Type"))
		case "/away":
			http.Redirect(w, r, other.URL+"/x", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, srvURL+"/loop", http.StatusFound)
		}
	}))
	defer ts.Close()
	srvURL = ts.URL

	post := func(path string) Message {
		var h flow.Header
		h.Set("Content-Type", "text/plain")
		h.Set("Authorization", "Bearer t")
		return Message{Method: "POST", URL: ts.URL + path, Header: h, Body: []byte("payload")}
	}
	for path, want := range map[string]string{
		"/301": "GET  ", "/302": "GET  ", "/303": "GET  ",
		"/307": "POST payload text/plain", "/308": "POST payload text/plain",
	} {
		f, err := e.proxy.ReplayWith(context.Background(), post(path), ReplayOptions{FollowRedirects: true})
		if err != nil {
			t.Fatal(path, err)
		}
		if got := string(f.DecodedResponseBody()); got != want || !strings.HasSuffix(f.URL(), "/end") {
			t.Errorf("%s: %q at %s, want %q", path, got, f.URL(), want)
		}
		if f.Response.Header.Get("X-Auth") != "Bearer t" {
			t.Errorf("%s: credentials stay on the same host", path)
		}
	}

	f, err := e.proxy.ReplayWith(context.Background(), post("/302"), ReplayOptions{})
	if err != nil || f.StatusCode() != http.StatusFound {
		t.Errorf("without following: %v %d", err, f.StatusCode())
	}

	f, err = e.proxy.ReplayWith(context.Background(), post("/away"), ReplayOptions{FollowRedirects: true})
	if err != nil || string(f.DecodedResponseBody()) != "other GET" || f.Response.Header.Get("X-Auth") != "" {
		t.Errorf("another host: %v %q auth %q", err, f.DecodedResponseBody(), f.Response.Header.Get("X-Auth"))
	}

	if _, err := e.proxy.ReplayWith(context.Background(), Message{Method: "GET", URL: ts.URL + "/loop"}, ReplayOptions{FollowRedirects: true, MaxRedirects: 3}); !errors.Is(err, ErrTooManyRedirects) {
		t.Errorf("a loop: %v", err)
	}
	if n := len(e.store.Snapshot()); n < 10 {
		t.Errorf("%d flows recorded", n)
	}
}

func TestReplayWithTimeout(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer ts.Close()
	start := time.Now()
	f, err := e.proxy.ReplayWith(context.Background(), Message{Method: "GET", URL: ts.URL}, ReplayOptions{Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !f.IsError() || time.Since(start) > 3*time.Second {
		t.Errorf("a request past its timeout fails: %s after %v", f.StatusLine(), time.Since(start))
	}
}

func TestReplayRefusesWebSocket(t *testing.T) {
	e := newEnv(t)
	var h flow.Header
	h.Set("Upgrade", "websocket")
	h.Set("Connection", "Upgrade")
	if _, err := e.proxy.Replay(context.Background(), Message{Method: "GET", URL: "http://example.com/ws", Header: h}); !errors.Is(err, ErrWebSocketRepeat) {
		t.Errorf("err %v", err)
	}
}
