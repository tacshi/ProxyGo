package proxy

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"proxygo/internal/flow"
)

func (s *Server) Replay(ctx context.Context, m Message) (*flow.Flow, error) {
	u, err := url.Parse(strings.TrimSpace(m.URL))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("a request's URL must start with http:// or https://")
	}
	if u.Host == "" {
		return nil, errors.New("the URL has no host")
	}
	method := strings.ToUpper(strings.TrimSpace(m.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method == http.MethodConnect {
		return nil, errors.New("CONNECT requests cannot be repeated")
	}
	if strings.EqualFold(m.Header.Get("Upgrade"), "websocket") {
		return nil, ErrWebSocketRepeat
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(m.Body))
	if err != nil {
		return nil, err
	}
	req.Header = m.Header.HTTP()
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Host = u.Host
	if h := req.Header.Get("Host"); h != "" {
		req.Host = h
	}
	req.Header.Del("Host")
	req.Header.Del("Content-Length")
	req.RemoteAddr = "127.0.0.1:0"
	req.RequestURI = cmp.Or(targetOf(strings.TrimSpace(m.URL)), u.RequestURI())
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	client := flow.Client{Name: "ProxyGo", PID: os.Getpid(), Path: executablePath()}
	f := s.exchange(req, bytes.Clone(m.Body), nil, client, nil, &discardSink{})
	return f, nil
}

var ErrWebSocketRepeat = errors.New("a WebSocket request cannot be repeated: open it in Compose as a WebSocket")

type ReplayOptions struct {
	Timeout         time.Duration
	FollowRedirects bool
	MaxRedirects    int
}

var ErrTooManyRedirects = errors.New("too many redirects")

func (s *Server) ReplayWith(ctx context.Context, m Message, o ReplayOptions) (*flow.Flow, error) {
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	f, err := s.Replay(ctx, m)
	if err != nil || !o.FollowRedirects {
		return f, err
	}
	limit := o.MaxRedirects
	if limit <= 0 {
		limit = 10
	}
	for hops := 0; ; hops++ {
		next, ok := redirect(f, m)
		if !ok {
			return f, nil
		}
		if hops >= limit {
			return f, ErrTooManyRedirects
		}
		m = next
		if f, err = s.Replay(ctx, m); err != nil {
			return f, err
		}
	}
}

func redirect(f *flow.Flow, m Message) (Message, bool) {
	code := f.StatusCode()
	if f.Response == nil || f.IsError() {
		return m, false
	}
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return m, false
	}
	loc := f.Response.Header.Get("Location")
	if loc == "" {
		return m, false
	}
	base, err := url.Parse(m.URL)
	if err != nil {
		return m, false
	}
	to, err := base.Parse(loc)
	if err != nil || (to.Scheme != "http" && to.Scheme != "https") {
		return m, false
	}
	next := Message{Method: m.Method, URL: to.String(), Header: m.Header.Clone(), Body: m.Body}
	method := strings.ToUpper(cmp.Or(m.Method, http.MethodGet))
	if code == http.StatusSeeOther && method != http.MethodHead ||
		(code == http.StatusMovedPermanently || code == http.StatusFound) && method == http.MethodPost {
		next.Method, next.Body = http.MethodGet, nil
		for _, h := range []string{"Content-Type", "Content-Length", "Content-Encoding", "Transfer-Encoding"} {
			next.Header.Del(h)
		}
	}
	if !sameOrigin(base, to) {
		for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Cookie2"} {
			next.Header.Del(h)
		}
	}
	if next.Header.Get("Host") != "" {
		next.Header.Set("Host", to.Host)
	}
	return next, true
}

func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string { return cmp.Or(u.Port(), map[string]string{"https": "443"}[u.Scheme], "80") }
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

type RepeatResult struct {
	Flow *flow.Flow
	Err  error
}

func (s *Server) Repeat(ctx context.Context, m Message, count, concurrency int, delay time.Duration) []RepeatResult {
	count = max(count, 1)
	concurrency = min(max(concurrency, 1), count)
	results := make([]RepeatResult, count)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range count {
		if i > 0 && delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
			}
		}
		if ctx.Err() != nil {
			results[i].Err = ctx.Err()
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i].Err = ctx.Err()
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			f, err := s.Replay(ctx, m)
			results[i] = RepeatResult{Flow: f, Err: err}
		})
	}
	wg.Wait()
	return results
}

func MessageOf(f *flow.Flow) Message {
	if f == nil || f.Request == nil {
		return Message{Method: http.MethodGet, Header: flow.Header{}}
	}
	h := f.Request.Header.Clone()
	body, decoded := flow.DecodeBody(f.Request.BodyData, h.Get("Content-Encoding"))
	if decoded {
		h.Del("Content-Encoding")
	}
	return Message{Method: f.MethodName(), URL: f.URL(), Header: h, Body: bytes.Clone(body)}
}
