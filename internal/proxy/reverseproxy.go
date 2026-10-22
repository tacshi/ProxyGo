package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"proxygo/internal/rules"
	"proxygo/internal/wire"
)

type reverseServer struct {
	srv    *http.Server
	target string
}

func (s *Server) reconcileReverseProxies(data *rules.Data) {
	want := map[int]*rules.ReverseProxy{}
	if data.ToolOn(rules.ToolReverse) {
		for _, r := range data.ReverseProxies {
			if r != nil && r.Enabled && r.ListenPort > 0 && r.Target != "" {
				want[r.ListenPort] = r
			}
		}
	}
	host, network := s.bindHost()
	key := func(r *rules.ReverseProxy) string {
		return r.Target + "|" + strconv.FormatBool(r.PreserveHost) + "|" + host + "|" + network
	}
	s.revMu.Lock()
	defer s.revMu.Unlock()
	for port, rs := range s.revServers {
		if r, ok := want[port]; !ok || rs.target != key(r) {
			_ = rs.srv.Close()
			delete(s.revServers, port)
		}
	}
	for port, r := range want {
		if _, ok := s.revServers[port]; ok {
			continue
		}
		target, err := reverseTarget(r.Target)
		if err != nil {
			s.logf("reverse proxy %s: %v", r.Target, err)
			continue
		}
		ln, err := net.Listen(network, net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			s.logf("reverse proxy :%d: %v", port, err)
			continue
		}
		preserve := r.PreserveHost
		srv := &http.Server{
			Handler:           http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { s.reverse(w, req, target, preserve) }),
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
			ConnContext:       wire.WithConn,
		}
		s.revServers[port] = &reverseServer{srv: srv, target: key(r)}
		go func() { _ = srv.Serve(wire.Listener(ln)) }()
		s.logf("reverse proxy :%d → %s", port, target)
	}
}

func reverseTarget(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, &url.Error{Op: "parse", URL: raw, Err: errNoHost}
	}
	return u, nil
}

var errNoHost = errors.New("no host")

func (s *Server) reverse(w http.ResponseWriter, r *http.Request, target *url.URL, preserveHost bool) {
	if !s.allowed(r.RemoteAddr) {
		http.Error(w, "ProxyGo: this device is not allowed by Access Control", http.StatusForbidden)
		return
	}
	u := r.URL.Clone()
	u.Scheme = target.Scheme
	u.Host = target.Host
	u.Path = strings.TrimSuffix(target.Path, "/") + r.URL.Path
	u.RawPath = ""
	if target.RawQuery != "" {
		u.RawQuery = strings.Trim(target.RawQuery+"&"+r.URL.RawQuery, "&")
	}
	r2 := r.Clone(r.Context())
	r2.URL = u
	if !preserveHost {
		r2.Host = target.Host
	}
	s.forward(w, r2, nil)
}

func (s *Server) stopReverseProxies() {
	s.revMu.Lock()
	servers := s.revServers
	s.revServers = map[int]*reverseServer{}
	s.revMu.Unlock()
	for _, rs := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = rs.srv.Shutdown(ctx)
		cancel()
	}
}

func (s *Server) ReverseProxyPorts() []int {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	out := make([]int, 0, len(s.revServers))
	for p := range s.revServers {
		out = append(out, p)
	}
	return out
}
