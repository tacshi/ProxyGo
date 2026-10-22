package proxy

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygo/internal/certs"
	"proxygo/internal/clientinfo"
	"proxygo/internal/flow"
	"proxygo/internal/pac"
	"proxygo/internal/rules"
	"proxygo/internal/script"
	"proxygo/internal/wire"
)

const maxBodyCapture = 64 << 20

type Sink interface {
	Upsert(*flow.Flow)
	Update(id string, fn func(*flow.Flow))
}

type Options struct {
	Addr       string
	Network    string
	Certs      *certs.Manager
	Rules      *rules.Store
	Scripts    *script.Engine
	Clients    *clientinfo.Lookup
	Sink       Sink
	Log        func(string)
	Breakpoint func(ctx context.Context, p *Pause) (Message, bool)
	RootCAs    *x509.CertPool
	Secret     func(ref string) (string, error)
	AskDevice  func(ip string) bool
}

type Server struct {
	opts Options

	mu       sync.Mutex
	httpSrv  *http.Server
	listener net.Listener
	addr     string
	lastErr  atomic.Pointer[string]
	paused   atomic.Bool

	tunnels *tunnelServer
	socks   socksListener

	pacMu sync.Mutex
	pac   *pac.Resolver

	upMu      sync.Mutex
	upstream  *http.Transport
	upKey     string
	httpMode  string
	klMu      sync.Mutex
	keyLog    *keyLogWriter
	certCache sync.Map

	revMu      sync.Mutex
	revServers map[int]*reverseServer

	sockets  sync.Map
	composed sync.Map
	asked    sync.Map

	offRules func()
}

func New(opts Options) *Server {
	if opts.Rules == nil {
		opts.Rules = rules.Memory(rules.Data{})
	}
	s := &Server{opts: opts, revServers: map[int]*reverseServer{}}
	s.tunnels = newTunnelServer(s)
	return s
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return nil
	}
	if err := s.listenLocked(cmp.Or(s.opts.Addr, ":9090"), true); err != nil {
		return err
	}
	s.offRules = s.opts.Rules.OnChange(s.reconcile)
	go s.reconcile()
	return nil
}

func (s *Server) listenLocked(addr string, tryNext bool) error {
	network := s.network()
	ln, err := net.Listen(network, addr)
	if err != nil && tryNext {
		if host, portText, splitErr := net.SplitHostPort(addr); splitErr == nil {
			port, _ := strconv.Atoi(portText)
			for i := 1; i <= 4 && err != nil && port > 0; i++ {
				ln, err = net.Listen(network, net.JoinHostPort(host, strconv.Itoa(port+i)))
			}
		}
	}
	if err != nil {
		msg := err.Error()
		s.lastErr.Store(&msg)
		return err
	}
	s.lastErr.Store(nil)
	s.listener = ln
	s.addr = ln.Addr().String()
	s.httpSrv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       150 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext:       wire.WithConn,
	}
	go func(srv *http.Server, ln net.Listener) {
		if err := srv.Serve(wire.Listener(ln)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			msg := err.Error()
			s.lastErr.Store(&msg)
		}
	}(s.httpSrv, ln)
	s.logf("proxy listening on %s", s.addr)
	return nil
}

func (s *Server) SetAddr(addr string) error {
	s.mu.Lock()
	network := s.opts.Network
	s.mu.Unlock()
	return s.SetListen(addr, network)
}

func (s *Server) SetListen(addr, network string) error {
	s.mu.Lock()
	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
		_ = s.listener.Close()
		s.httpSrv, s.listener, s.addr = nil, nil, ""
	}
	s.opts.Addr, s.opts.Network = addr, network
	err := s.listenLocked(addr, false)
	s.mu.Unlock()
	if err == nil {
		go s.reconcile()
	}
	return err
}

func (s *Server) network() string { return cmp.Or(s.opts.Network, "tcp") }

func (s *Server) bindHost() (host, network string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host, _, _ = net.SplitHostPort(cmp.Or(s.opts.Addr, ":9090"))
	return host, s.network()
}

func (s *Server) Stop() {
	s.mu.Lock()
	srv, ln := s.httpSrv, s.listener
	s.httpSrv, s.listener, s.addr = nil, nil, ""
	off := s.offRules
	s.offRules = nil
	s.mu.Unlock()
	if off != nil {
		off()
	}
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		_ = srv.Close()
		_ = ln.Close()
	}
	s.tunnels.close()
	s.socks.stop()
	s.stopReverseProxies()
	s.upMu.Lock()
	if s.upstream != nil {
		s.upstream.CloseIdleConnections()
	}
	s.upMu.Unlock()
	s.klMu.Lock()
	if s.keyLog != nil {
		s.keyLog.close()
		s.keyLog = nil
	}
	s.klMu.Unlock()
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

func (s *Server) Port() int {
	_, portText, err := net.SplitHostPort(s.Addr())
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portText)
	return port
}

func (s *Server) SocksPort() int { return s.socks.port() }

func (s *Server) SetPaused(p bool) { s.paused.Store(p) }

func (s *Server) reconcile() {
	if s.Addr() == "" {
		return
	}
	data := s.rules()
	s.socks.reconcile(s, data.Socks)
	s.reconcileReverseProxies(data)
	if s.opts.Certs != nil {
		s.opts.Certs.SetLeafValidity(data.LeafValidity())
	}
	if s.opts.Scripts != nil {
		s.opts.Scripts.SetAllowEnv(data.Scripting.AllowEnv)
	}
	s.reconcileHTTPVersion(data)
}

func (s *Server) reconcileHTTPVersion(data *rules.Data) {
	mode := data.HTTPVersionMode()
	s.upMu.Lock()
	changed := s.httpMode != "" && s.httpMode != mode
	s.httpMode = mode
	up := s.upstream
	s.upMu.Unlock()
	if !changed {
		return
	}
	if up != nil {
		up.CloseIdleConnections()
	}
	s.tunnels.closeConns()
	s.sockets.Range(func(_, v any) bool {
		for _, side := range v.(*liveSocket).sides {
			_ = side.conn.Close()
		}
		return true
	})
}

func (s *Server) rules() *rules.Data { return s.opts.Rules.Current() }

func (s *Server) logf(format string, args ...any) {
	if s.opts.Log != nil {
		s.opts.Log(fmt.Sprintf(format, args...))
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r.RemoteAddr) {
		http.Error(w, "ProxyGo: this device is not allowed by Access Control", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	if r.URL.Host == "" || s.isSelf(r.URL.Host) || isCertHost(r.URL.Host) {
		s.servePage(w, r)
		return
	}
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	s.forward(w, r, nil)
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, info *tunnelInfo) {
	body, rest, err := readBody(r.Body)
	if err != nil {
		http.Error(w, "ProxyGo: "+err.Error(), http.StatusBadRequest)
		return
	}
	client := s.clientFor(r.RemoteAddr)
	if info != nil {
		client = info.client
	}
	s.exchange(r, body, rest, client, info, newHTTPSink(w, r))
}

func (s *Server) allowed(remoteAddr string) bool {
	ac := s.rules().Access
	ip := net.ParseIP(remoteHost(remoteAddr))
	if ac.Allowed(ip) {
		return true
	}
	if ac.Mode != rules.AccessAsk || s.opts.AskDevice == nil {
		return false
	}
	return s.ask(ip.String())
}

type deviceAnswer struct {
	done chan struct{}
	ok   bool
}

const askWait = 5 * time.Minute

func (s *Server) ask(ip string) bool {
	v, loaded := s.asked.LoadOrStore(ip, &deviceAnswer{done: make(chan struct{})})
	d := v.(*deviceAnswer)
	if !loaded {
		go func() {
			d.ok = s.opts.AskDevice(ip)
			close(d.done)
			if d.ok {
				s.asked.Delete(ip)
			}
		}()
	}
	select {
	case <-d.done:
		return d.ok
	case <-time.After(askWait):
		return false
	}
}

func (s *Server) isSelf(hostport string) bool {
	host, port := splitHostPort(hostport, 80)
	if port != s.Port() {
		return false
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())) {
		return true
	}
	if ip == nil {
		return false
	}
	addrs, _ := net.InterfaceAddrs()
	return slices.ContainsFunc(addrs, func(a net.Addr) bool {
		n, ok := a.(*net.IPNet)
		return ok && n.IP.Equal(ip)
	})
}

func (s *Server) clientFor(remoteAddr string) flow.Client {
	ip := net.ParseIP(remoteHost(remoteAddr))
	if ip != nil && !ip.IsLoopback() && !isLocalIP(ip) {
		return flow.Client{Name: ip.String(), PID: -1}
	}
	if s.opts.Clients == nil {
		return flow.Client{Name: "System", PID: -1}
	}
	info := s.opts.Clients.ForPort(remotePort(remoteAddr))
	if info.PID == os.Getpid() {
		info = clientinfo.Info{PID: os.Getpid(), Name: "ProxyGo", Path: executablePath()}
	}
	c := flow.Client{Name: cmp.Or(info.Name, "System"), PID: info.PID, Path: info.Path}
	if info.BundleID != "" {
		c.BundleIdentifier = new(info.BundleID)
	}
	return c
}

var localIPs = sync.OnceValue(func() []net.IP {
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP)
		}
	}
	return out
})

func isLocalIP(ip net.IP) bool {
	return slices.ContainsFunc(localIPs(), ip.Equal)
}

var executablePath = sync.OnceValue(func() string {
	p, _ := os.Executable()
	return p
})

func requestTarget(r *http.Request) string {
	if t := targetOf(r.RequestURI); validTarget(t) {
		return t
	}
	return r.URL.RequestURI()
}

func targetOf(raw string) string {
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	_, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return ""
	}
	i := strings.IndexAny(rest, "/?#")
	if i < 0 {
		return "/"
	}
	t, _, _ := strings.Cut(rest[i:], "#")
	if strings.HasPrefix(t, "?") || t == "" {
		t = "/" + t
	}
	return t
}

func validTarget(t string) bool {
	return strings.HasPrefix(t, "/") && !strings.ContainsFunc(t, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '#' })
}

func setTarget(u *url.URL, target string, absolute bool) bool {
	if !validTarget(target) {
		return false
	}
	p, q, hasQuery := strings.Cut(target, "?")
	switch {
	case absolute:
		u.Opaque = "//" + u.Host + p
	case strings.HasPrefix(p, "//"):
		return false
	default:
		u.Opaque = p
	}
	u.RawQuery, u.ForceQuery = q, hasQuery && q == ""
	return true
}

func splitHostPort(hostport string, defaultPort int) (string, int) {
	if hostport == "" {
		return "", defaultPort
	}
	host, portText, err := net.SplitHostPort(hostport)
	if err == nil {
		p, err := strconv.Atoi(portText)
		if err != nil || p <= 0 {
			p = defaultPort
		}
		return strings.Trim(host, "[]"), p
	}
	return strings.Trim(hostport, "[]"), defaultPort
}

func defaultPort(scheme string) int {
	if scheme == "https" || scheme == "wss" {
		return 443
	}
	return 80
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func fullURL(scheme, host string, port int, uri string) string {
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if port != defaultPort(scheme) {
		h = joinHostPort(host, port)
	}
	if uri == "" {
		uri = "/"
	}
	return scheme + "://" + h + uri
}

func remoteHost(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func remotePort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func timezoneText() string {
	_, offset := time.Now().Zone()
	sign := "+"
	if offset < 0 {
		sign, offset = "-", -offset
	}
	return fmt.Sprintf("GMT%s%d", sign, offset/3600)
}

func readBody(body io.ReadCloser) ([]byte, io.Reader, error) {
	if body == nil || body == http.NoBody {
		return nil, nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(body, maxBodyCapture))
	if err != nil {
		return nil, nil, err
	}
	if len(b) < maxBodyCapture {
		return b, nil, nil
	}
	return b, body, nil
}

func mark(f *flow.Flow, tool string, value any) {
	m, _ := f.ToolMetadata.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	m[tool] = value
	f.ToolMetadata = m
}
