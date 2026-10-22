package proxy

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"proxygo/internal/certs"
	"proxygo/internal/pac"
	"proxygo/internal/rules"
	"proxygo/internal/wire"
)

func (s *Server) transport() *http.Transport {
	data := s.rules()
	key := fmt.Sprintf("%v|%v|%v|%v", data.Upstream, data.InsecureTLS, data.DisableHTTP2, data.KeyLogPath)
	s.upMu.Lock()
	defer s.upMu.Unlock()
	if s.upstream != nil && s.upKey == key {
		return s.upstream
	}
	old := s.upstream
	s.upstream = &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return s.externalProxy(r.Context(), r.URL), nil
		},
		DialContext:           s.dialRecorded,
		DialTLSContext:        s.dialTLSRecorded,
		TLSClientConfig:       s.tlsConfig("", !data.DisableHTTP2),
		ForceAttemptHTTP2:     !data.DisableHTTP2,
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	s.upKey = key
	if old != nil {
		go old.CloseIdleConnections()
	}
	return s.upstream
}

func (s *Server) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if rule := s.rules().DNSFor(host); rule != nil {
		port := portText
		if rule.Port > 0 {
			port = strconv.Itoa(rule.Port)
		}
		address = net.JoinHostPort(rule.IP, port)
	}
	d := &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, address)
}

func (s *Server) dialRecorded(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := s.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return wire.Client(c), nil
}

func (s *Server) dialTLSRecorded(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := s.dialTLS(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return wire.Client(c), nil
}

func (s *Server) dialTLS(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	raw, err := s.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	tc := tls.Client(raw, s.tlsConfig(host, !s.rules().DisableHTTP2))
	err = tc.HandshakeContext(ctx)
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(tc.ConnectionState(), err)
	}
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

func (s *Server) tlsConfig(host string, h2 bool) *tls.Config {
	data := s.rules()
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: data.InsecureTLS,
		RootCAs:            s.opts.RootCAs,
		MinVersion:         tls.VersionTLS12,
		KeyLogWriter:       s.keyLogWriter(),
		NextProtos:         []string{"http/1.1"},
	}
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	if cc := data.ClientCertFor(host); cc != nil {
		if cert, err := s.clientCertificate(cc); err == nil {
			cfg.Certificates = []tls.Certificate{*cert}
		} else {
			s.logf("client certificate for %s: %v", host, err)
		}
	}
	return cfg
}

type cachedCert struct {
	mod  time.Time
	cert *tls.Certificate
}

func (s *Server) clientCertificate(cc *rules.ClientCertificate) (*tls.Certificate, error) {
	return s.loadCert(cc.CertPath, cc.KeyPath, cc.P12Path, cc.PasswordRef)
}

func (s *Server) loadCert(certPath, keyPath, p12Path, ref string) (*tls.Certificate, error) {
	main := cmp.Or(p12Path, certPath)
	if main == "" {
		return nil, errors.New("no certificate file")
	}
	fi, err := os.Stat(main)
	if err != nil {
		return nil, err
	}
	key := certPath + "|" + keyPath + "|" + p12Path + "|" + ref
	if v, ok := s.certCache.Load(key); ok {
		if c := v.(*cachedCert); c.mod.Equal(fi.ModTime()) {
			return c.cert, nil
		}
	}
	var cert *tls.Certificate
	if p12Path != "" {
		password := ""
		if ref != "" {
			if password, err = s.secret(ref); err != nil {
				return nil, err
			}
		}
		cert, err = certs.LoadP12(p12Path, password)
	} else {
		cert, err = certs.LoadPEM(certPath, keyPath)
	}
	if err != nil {
		return nil, err
	}
	s.certCache.Store(key, &cachedCert{mod: fi.ModTime(), cert: cert})
	return cert, nil
}

func (s *Server) secret(ref string) (string, error) {
	if s.opts.Secret != nil {
		return s.opts.Secret(ref)
	}
	return certs.Keychain.Get(ref)
}

func (s *Server) leafFor(host string) (*tls.Certificate, error) {
	for _, sc := range s.rules().ServerCerts {
		if sc == nil || !sc.Enabled {
			continue
		}
		cert, err := s.loadCert(sc.CertPath, sc.KeyPath, sc.P12Path, sc.PasswordRef)
		if err != nil {
			s.logf("server certificate %s: %v", cmp.Or(sc.P12Path, sc.CertPath), err)
			continue
		}
		match := certs.Covers(cert, host)
		if len(sc.Hosts) > 0 {
			match = slices.ContainsFunc(sc.Hosts, func(h string) bool { return rules.HostMatch(h, host) })
		}
		if match {
			return cert, nil
		}
	}
	return s.opts.Certs.Leaf(host)
}

func (s *Server) dialTunnel(ctx context.Context, host string, port int) (net.Conn, string, error) {
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	target := joinHostPort(host, port)
	if p := s.externalProxy(ctx, &url.URL{Scheme: scheme, Host: target, Path: "/"}); p != nil {
		if p.Scheme == "socks5" {
			return dialSOCKS5(ctx, p, target)
		}
		return dialThroughProxy(ctx, p, target)
	}
	c, err := s.dial(ctx, "tcp", target)
	if err != nil {
		return nil, "", err
	}
	ip := ""
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ip = a.IP.String()
	}
	return c, ip, nil
}

func (s *Server) externalProxy(ctx context.Context, u *url.URL) *url.URL {
	up := s.rules().Upstream
	if !up.Enabled {
		return nil
	}
	host := u.Hostname()
	for _, b := range up.Bypass {
		if rules.HostMatch(b, host) {
			return nil
		}
	}
	if up.PACURL != "" {
		s.pacMu.Lock()
		if s.pac == nil || s.pac.URL != up.PACURL {
			s.pac = &pac.Resolver{URL: up.PACURL}
		}
		r := s.pac
		s.pacMu.Unlock()
		result, err := r.FindProxy(ctx, u.String())
		if err == nil {
			if proxies := pac.Proxies(result); len(proxies) > 0 {
				return proxies[0]
			}
			return nil
		}
		s.logf("%v", err)
	}
	return up.ProxyFor(u.Scheme, host)
}

func dialSOCKS5(ctx context.Context, p *url.URL, target string) (net.Conn, string, error) {
	addr := p.Host
	if p.Port() == "" {
		addr = net.JoinHostPort(p.Hostname(), "1080")
	}
	d := &net.Dialer{Timeout: 20 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("SOCKS proxy %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	fail := func(err error) (net.Conn, string, error) {
		_ = c.Close()
		return nil, "", fmt.Errorf("SOCKS proxy %s: %w", addr, err)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return fail(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		return fail(fmt.Errorf("it wants authentication ProxyGo does not have"))
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	port, _ := strconv.Atoi(portText)
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(append(req, 1), ip.To4()...)
	} else if ip != nil {
		req = append(append(req, 4), ip.To16()...)
	} else {
		if len(host) > 255 {
			return fail(fmt.Errorf("host name too long"))
		}
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return fail(err)
	}
	if head[1] != 0 {
		return fail(fmt.Errorf("connect refused, code %d", head[1]))
	}
	skip := map[byte]int{1: 4, 4: 16}[head[3]]
	if head[3] == 3 {
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return fail(err)
		}
		skip = int(n[0])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, "", nil
}

func dialThroughProxy(ctx context.Context, p *url.URL, target string) (net.Conn, string, error) {
	addr := p.Host
	if p.Port() == "" {
		addr = net.JoinHostPort(p.Hostname(), cmp.Or(map[string]string{"https": "443"}[p.Scheme], "8080"))
	}
	d := &net.Dialer{Timeout: 20 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("external proxy %s: %w", addr, err)
	}
	if p.Scheme == "https" {
		tc := tls.Client(c, &tls.Config{ServerName: p.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return nil, "", fmt.Errorf("external proxy %s: %w", addr, err)
		}
		c = tc
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u := p.User; u != nil {
		pass, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)) + "\r\n"
	}
	if _, err := c.Write([]byte(req + "\r\n")); err != nil {
		_ = c.Close()
		return nil, "", err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = c.Close()
		return nil, "", err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		return nil, "", fmt.Errorf("external proxy %s: %s", addr, resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	return &bufferedConn{Conn: c, r: br}, "", nil
}

type keyLogWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func (k *keyLogWriter) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.f == nil {
		f, err := os.OpenFile(k.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 0, err
		}
		k.f = f
	}
	return k.f.Write(p)
}

func (k *keyLogWriter) close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.f != nil {
		_ = k.f.Close()
		k.f = nil
	}
}

func (s *Server) keyLogWriter() io.Writer {
	path := s.rules().KeyLogPath
	s.klMu.Lock()
	defer s.klMu.Unlock()
	if s.keyLog != nil && s.keyLog.path != path {
		s.keyLog.close()
		s.keyLog = nil
	}
	if path == "" {
		return nil
	}
	if s.keyLog == nil {
		s.keyLog = &keyLogWriter{path: path}
	}
	return s.keyLog
}
