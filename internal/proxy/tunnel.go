package proxy

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/wire"
)

type tunnelInfo struct {
	host      string
	port      int
	client    flow.Client
	remote    string
	tls       bool
	tlsStart  float64
	tlsEnd    float64
	clientTLS *flow.TLSInfo
}

type tunnelKey struct{}

type tunnelServer struct {
	srv  *http.Server
	ln   *chanListener
	info sync.Map
	once sync.Once
}

func newTunnelServer(s *Server) *tunnelServer {
	ts := &tunnelServer{ln: newChanListener()}
	ts.srv = &http.Server{
		Handler:           http.HandlerFunc(s.serveTunneled),
		ReadHeaderTimeout: 60 * time.Second,
		IdleTimeout:       150 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			ctx = wire.WithConn(ctx, c)
			if v, ok := ts.info.Load(c); ok {
				return context.WithValue(ctx, tunnelKey{}, v)
			}
			return ctx
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				ts.info.Delete(c)
			}
		},
	}
	return ts
}

func (ts *tunnelServer) serve(c net.Conn, info *tunnelInfo) {
	ts.once.Do(func() { go func() { _ = ts.srv.Serve(ts.ln) }() })
	c = wire.Server(c)
	ts.info.Store(c, info)
	if !ts.ln.push(c) {
		ts.info.Delete(c)
		_ = c.Close()
	}
}

func (ts *tunnelServer) close() {
	_ = ts.ln.Close()
	_ = ts.srv.Close()
}

func (ts *tunnelServer) closeConns() {
	ts.info.Range(func(k, _ any) bool {
		if c, ok := k.(net.Conn); ok {
			_ = c.Close()
		}
		return true
	})
}

type chanListener struct {
	ch     chan net.Conn
	done   chan struct{}
	closed sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func (s *Server) serveTunneled(w http.ResponseWriter, r *http.Request) {
	info, _ := r.Context().Value(tunnelKey{}).(*tunnelInfo)
	if info == nil {
		http.Error(w, "ProxyGo: unknown tunnel", http.StatusInternalServerError)
		return
	}
	r.URL.Scheme = "http"
	if r.TLS != nil {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = cmp.Or(r.Host, joinHostPort(info.host, info.port))
	}
	if isCertHost(r.URL.Host) {
		s.servePage(w, r)
		return
	}
	s.forward(w, r, info)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

type target struct {
	host   string
	port   int
	client flow.Client
	remote string
	header http.Header
	sent   []flow.SentHeader
	proto  [2]int
	socks  bool
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, 443)
	if host == "" {
		http.Error(w, "ProxyGo: bad CONNECT target", http.StatusBadRequest)
		return
	}
	header, sent := requestHeader(r)
	t := &target{host: host, port: port, client: s.clientFor(r.RemoteAddr), remote: r.RemoteAddr, header: header, sent: sent, proto: [2]int{r.ProtoMajor, r.ProtoMinor}}
	blocked, name, action := s.rules().BlockedHost(host, port)
	if app := s.blockedApp(t.client); app != nil {
		blocked, name, action = true, appLabel(app), app.Action
	}
	if blocked {
		if action == rules.BlockHide {
			panic(http.ErrAbortHandler)
		}
		f := s.connectFlow(t)
		mark(f, "block", name)
		end := now()
		f.Timing.ResponseEndedAt = &end
		f.Response = &flow.Response{Status: &flow.Status{Code: http.StatusForbidden, Phrase: "Forbidden"}, Version: flow.Version{Major: 1, Minor: 1}, CreatedAt: end}
		s.publishFlow(f)
		http.Error(w, "Blocked by ProxyGo", http.StatusForbidden)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "ProxyGo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	reply := func(err error) error {
		if err != nil {
			body := "ProxyGo: could not connect to " + joinHostPort(host, port) + ": " + err.Error() + "\r\n"
			_, _ = fmt.Fprintf(brw, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		} else {
			_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		}
		return brw.Flush()
	}
	s.tunnel(&bufferedConn{Conn: conn, r: brw.Reader}, t, reply)
}

type sniffed int

const (
	sniffOther sniffed = iota
	sniffTLS
	sniffHTTP
)

func sniff(c *bufferedConn, timeout time.Duration) sniffed {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	b, err := c.r.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	switch {
	case err != nil || len(b) == 0:
		return sniffOther
	case b[0] == 0x16:
		return sniffTLS
	case b[0] >= 'A' && b[0] <= 'Z':
		return sniffHTTP
	}
	return sniffOther
}

func (s *Server) tunnel(c *bufferedConn, t *target, reply func(error) error) {
	data := s.rules()
	if s.opts.Certs != nil && data.ShouldMITM(t.host) {
		if reply(nil) != nil {
			_ = c.Close()
			return
		}
		switch sniff(c, 30*time.Second) {
		case sniffTLS:
			s.serveMITM(c, t)
		case sniffHTTP:
			s.tunnels.serve(c, &tunnelInfo{host: t.host, port: t.port, client: t.client, remote: t.remote})
		default:
			s.relay(c, t, nil)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	f := s.connectFlow(t)
	connStart := now()
	upstream, ip, err := s.dialTunnel(ctx, t.host, t.port)
	cancel()
	connEnd := now()
	f.Timing.UpstreamConnectStartedAt, f.Timing.UpstreamConnectEndedAt = &connStart, &connEnd
	if err != nil {
		f.Response = errorResponse(err)
		f.Timing.ResponseEndedAt = &connEnd
		s.publishFlow(f)
		_ = reply(err)
		_ = c.Close()
		return
	}
	f.Summary.ServerIPAddress = ip
	if reply(nil) != nil {
		_ = c.Close()
		_ = upstream.Close()
		return
	}
	if sniff(c, time.Second) == sniffHTTP {
		_ = upstream.Close()
		s.tunnels.serve(c, &tunnelInfo{host: t.host, port: t.port, client: t.client, remote: t.remote})
		return
	}
	s.relay(c, t, &relayed{f: f, upstream: upstream})
}

type relayed struct {
	f        *flow.Flow
	upstream net.Conn
}

func (s *Server) relay(c *bufferedConn, t *target, r *relayed) {
	if r == nil {
		f := s.connectFlow(t)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		upstream, ip, err := s.dialTunnel(ctx, t.host, t.port)
		cancel()
		if err != nil {
			f.Response = errorResponse(err)
			end := now()
			f.Timing.ResponseEndedAt = &end
			s.publishFlow(f)
			_ = c.Close()
			return
		}
		f.Summary.ServerIPAddress = ip
		r = &relayed{f: f, upstream: upstream}
	}
	f := r.f
	record := !s.paused.Load()
	if record {
		s.publishFlow(f)
	}
	sent, received := pipe(c, r.upstream)
	end := now()
	f.Timing.ResponseEndedAt = &end
	f.Response = &flow.Response{
		Status:    &flow.Status{Code: 200, Phrase: "Connection Established"},
		Version:   flow.Version{Major: 1, Minor: 1},
		CreatedAt: end,
	}
	mark(f, "tunnel", map[string]any{"sent": sent, "received": received})
	if record {
		s.publishFlow(f)
	}
}

func (s *Server) serveMITM(c *bufferedConn, t *target) {
	data := s.rules()
	protos := []string{"h2", "http/1.1"}
	if data.DisableHTTP2 {
		protos = []string{"http/1.1"}
	}
	start := now()
	var sni string
	var offered []string
	tlsConn := tls.Server(c, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni, offered = hello.ServerName, slices.Clone(hello.SupportedProtos)
			return s.leafFor(cmp.Or(hello.ServerName, t.host))
		},
		NextProtos:   protos,
		MinVersion:   tls.VersionTLS12,
		KeyLogWriter: s.keyLogWriter(),
	})
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		f := s.connectFlow(t)
		f.Timing.ClientTLSStartedAt = &start
		end := now()
		f.Timing.ResponseEndedAt = &end
		f.Response = &flow.Response{
			Status: &flow.Status{Code: 999, Phrase: "SSL Handshake Failed"},
			Error: flow.ResponseError{"sslHandshakeFailed": map[string]any{
				"message": handshakeHint(err),
			}},
			Version: flow.Version{Major: 1, Minor: 1},
		}
		f.TLS = &flow.TLSDetails{Client: &flow.TLSInfo{ServerName: sni, Offered: offered, Error: err.Error(), PinningLikely: pinningLikely(err)}}
		if pinningLikely(err) {
			mark(f, "pinningLikely", true)
		}
		s.publishFlow(f)
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	end := now()
	cs := tlsConn.ConnectionState()
	ci := flow.TLSInfoOf(&cs)
	ci.Offered = offered
	s.tunnels.serve(tlsConn, &tunnelInfo{host: t.host, port: t.port, client: t.client, remote: t.remote, tls: true, tlsStart: start, tlsEnd: end, clientTLS: ci})
}

func pinningLikely(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "bad certificate") || strings.Contains(msg, "unknown certificate") ||
		strings.Contains(msg, "certificate unknown") || errors.Is(err, io.EOF) || strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset")
}

func handshakeHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unknown certificate") || strings.Contains(msg, "bad certificate") || strings.Contains(msg, "certificate unknown"):
		return "The client rejected ProxyGo's certificate (" + msg + "). Install and trust the ProxyGo CA on the device, or remove the host from the SSL Proxying List if the app pins its certificate."
	case errors.Is(err, io.EOF) || strings.Contains(msg, "EOF"):
		return "The client closed the connection during the TLS handshake. It may not trust ProxyGo's certificate or may pin the server's certificate."
	}
	return "TLS handshake with the client failed: " + msg
}

func (s *Server) connectFlow(t *target) *flow.Flow {
	start := now()
	scheme := "https"
	if t.port == 80 {
		scheme = "http"
	}
	h := flow.NewHeaderOrdered(t.header, t.sent)
	authority := joinHostPort(t.host, t.port)
	prependHost(&h, authority)
	f := flow.New(flow.NewUniqueID())
	f.Timezone = timezoneText()
	f.IsSSL = scheme == "https"
	f.Client = t.client
	f.Summary = flow.Summary{ClientIPAddress: remoteHost(t.remote), ClientPort: remotePort(t.remote), ServerPort: t.port}
	f.Timing = flow.Timing{RequestStartedAt: &start}
	version := flow.Version{Major: max(t.proto[0], 1), Minor: t.proto[1]}
	method := http.MethodConnect
	if t.socks {
		mark(f, "socks", true)
	}
	f.Request = &flow.Request{
		Scheme:      scheme,
		Port:        t.port,
		IsSSL:       scheme == "https",
		Version:     version,
		FullPath:    fullURL(scheme, t.host, t.port, ""),
		URI:         authority,
		Header:      h,
		Host:        t.host,
		Method:      flow.Method{Name: method},
		HTTPVersion: version.HTTPVersion(),
	}
	return f
}

func prependHost(h *flow.Header, host string) {
	if host == "" || h.Get("Host") != "" {
		return
	}
	h.Entries = append([]flow.HeaderEntry{{Enabled: true, Key: flow.HeaderKey{Name: "Host", Lower: "host"}, Value: host}}, h.Entries...)
}

func (s *Server) publishFlow(f *flow.Flow) {
	if s.opts.Sink != nil && !s.paused.Load() {
		s.opts.Sink.Upsert(f.Clone())
	}
}

func pipe(client, server net.Conn) (sent, received int64) {
	var up, down atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		n, _ := io.Copy(server, client)
		up.Store(n)
		closeWrite(server)
	})
	wg.Go(func() {
		n, _ := io.Copy(client, server)
		down.Store(n)
		closeWrite(client)
	})
	wg.Wait()
	_ = client.Close()
	_ = server.Close()
	return up.Load(), down.Load()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.SetReadDeadline(time.Now())
}

func errorResponse(err error) *flow.Response {
	return &flow.Response{
		Status:  &flow.Status{Code: 999, Phrase: "Error"},
		Error:   flow.ResponseError{errorKind(err): map[string]any{"message": err.Error()}},
		Header:  flow.Header{},
		Version: flow.Version{Major: 1, Minor: 1},
	}
}

func errorKind(err error) string {
	msg := err.Error()
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok || strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:") {
		return "sslError"
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return "cannotFindHost"
	}
	if ne, ok := errors.AsType[net.Error](err); errors.Is(err, context.DeadlineExceeded) || ok && ne.Timeout() {
		return "timedOut"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "couldNotConnectToServer"
}
