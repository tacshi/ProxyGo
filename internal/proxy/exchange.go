package proxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/script"
	"proxygo/internal/wire"
)

type exchange struct {
	s      *Server
	ctx    context.Context
	sink   clientSink
	data   *rules.Data
	f      *flow.Flow
	record bool
	cond   *rules.NetworkCondition
	trace  traceTimes

	hostHeader   string
	preserveHost bool
	length       int64
	published    time.Time
	diag         flow.Header
	wsSession    *script.WebSocketSession
}

func (s *Server) exchange(r *http.Request, body []byte, rest io.Reader, client flow.Client, info *tunnelInfo, sink clientSink) *flow.Flow {
	x := &exchange{
		s:          s,
		ctx:        r.Context(),
		sink:       sink,
		data:       s.rules(),
		record:     !s.paused.Load(),
		hostHeader: r.Host,
		length:     r.ContentLength,
	}
	x.f = newFlow(r, body, rest != nil, client, info)
	x.run(r, body, rest)
	return x.f
}

func newFlow(r *http.Request, body []byte, truncated bool, client flow.Client, info *tunnelInfo) *flow.Flow {
	scheme := cmp.Or(r.URL.Scheme, "http")
	host, port := splitHostPort(r.URL.Host, defaultPort(scheme))
	start := now()
	f := flow.New(flow.NewUniqueID())
	f.Timezone = timezoneText()
	f.IsSSL = scheme == "https"
	f.IsIntercepted = info != nil && info.tls
	f.Client = client
	f.Summary = flow.Summary{ClientIPAddress: remoteHost(r.RemoteAddr), ClientPort: remotePort(r.RemoteAddr), ServerPort: port}
	f.Timing.RequestStartedAt = &start
	if info != nil && info.tls {
		f.Timing.ClientTLSStartedAt = new(info.tlsStart)
		f.Timing.ClientTLSEndedAt = new(info.tlsEnd)
		if info.clientTLS != nil {
			f.TLS = &flow.TLSDetails{Client: info.clientTLS.Clone()}
		}
	}
	header, sent := requestHeader(r)
	h := flow.NewHeaderOrdered(header, sent)
	if h.Get(":authority") == "" {
		prependHost(&h, r.Host)
	}
	ws := isWebSocket(r)
	display := scheme
	if ws {
		display = map[string]string{"https": "wss", "http": "ws"}[scheme]
	}
	version := flow.Version{Major: r.ProtoMajor, Minor: r.ProtoMinor}
	f.Request = &flow.Request{
		Scheme:             scheme,
		Port:               port,
		IsSSL:              scheme == "https",
		Version:            version,
		FullPath:           strings.Replace(fullURL(scheme, host, port, r.URL.RequestURI()), scheme+"://", display+"://", 1),
		BodyData:           body,
		URI:                r.URL.RequestURI(),
		Header:             h,
		Host:               host,
		IsWebSocketUpgrade: ws,
		Method:             flow.Method{Name: r.Method},
		HTTPVersion:        r.Proto,
	}
	if truncated {
		f.ConnectionRecord = &flow.ConnectionRecord{Exchange: flow.Exchange{Truncated: true}}
	}
	return f
}

func requestHeader(r *http.Request) (http.Header, []flow.SentHeader) {
	sent := wire.RequestHeaders(wire.ConnOf(r.Context()), r.Method, r.RequestURI)
	h := r.Header
	if r.Host != "" && h.Get("Host") == "" && slices.ContainsFunc(sent, func(f flow.SentHeader) bool { return strings.EqualFold(f.Name, "Host") }) {
		h = h.Clone()
		h.Set("Host", r.Host)
	}
	return h, sent
}

func headerNames(h flow.Header) []string {
	var out []string
	for _, e := range h.Entries {
		if e.Enabled && !strings.HasPrefix(e.Key.Name, ":") {
			out = append(out, e.Key.Name)
		}
	}
	return out
}

func (x *exchange) responseHeaders(out *http.Request, resp *http.Response) []flow.SentHeader {
	x.trace.mu.Lock()
	c := x.trace.conn
	x.trace.mu.Unlock()
	if c == nil || out == nil {
		return nil
	}
	return wire.ResponseHeaders(c, out.Method, out.URL.RequestURI(), resp.StatusCode)
}

func (x *exchange) serverTLS(cs *tls.ConnectionState) {
	if cs == nil {
		return
	}
	if x.f.TLS == nil {
		x.f.TLS = &flow.TLSDetails{}
	}
	x.f.TLS.Server = flow.TLSInfoOf(cs)
}

func (x *exchange) publish() {
	if !x.record || x.s.opts.Sink == nil {
		return
	}
	x.published = time.Now()
	x.s.opts.Sink.Upsert(x.f.Clone())
}

func (x *exchange) run(r *http.Request, body []byte, rest io.Reader) {
	s, f, data := x.s, x.f, x.data
	method, rawURL := r.Method, f.URL()
	op := f.GraphQLOperation()

	if app := s.blockedApp(f.Client); app != nil {
		if app.Action == rules.BlockHide {
			x.sink.abort()
			return
		}
		mark(f, "blockedApp", appLabel(app))
		x.respond(http.StatusForbidden, textHeader(), []byte("Blocked by ProxyGo: "+appLabel(app)+" is in Blocked Apps\n"))
		return
	}
	if blocked, name, action := data.Blocked(method, rawURL); blocked {
		if action == rules.BlockHide {
			x.sink.abort()
			return
		}
		mark(f, "block", name)
		x.respond(http.StatusForbidden, textHeader(), []byte("Blocked by ProxyGo: "+name+"\n"))
		return
	}
	if f.IsWebSocket() {
		x.webSocket(r, body)
		return
	}
	x.publish()

	req := &script.Request{
		Method: method,
		Scheme: f.Request.Scheme,
		Host:   f.Request.Host,
		Port:   f.Request.Port,
		Path:   r.URL.RequestURI(),
		Header: f.Request.Header.Clone(),
		Body:   body,
	}

	scripts := data.ScriptsFor(method, rawURL, op)
	if len(scripts) > 0 && s.opts.Scripts != nil {
		mark(f, "script", scriptNames(scripts))
		x.diagnose("Scripting", scriptNames(scripts))
		req.Comment, req.Color = f.Comment, f.Highlight
		aborted, err := s.opts.Scripts.RunRequest(scripts, f, req)
		if err != nil {
			mark(f, "scriptError", err.Error())
		}
		f.Comment, f.Highlight = req.Comment, req.Color
		if aborted {
			x.respond(http.StatusForbidden, textHeader(), []byte("Aborted by a ProxyGo script\n"))
			return
		}
	}

	if m := data.MapRemoteFor(req.Method, req.URL(), op); m != nil {
		x.mapRemote(m, req)
	}

	if bp := data.BreakpointFor(req.Method, req.URL(), op, false); bp != nil && s.opts.Breakpoint != nil {
		x.diagnose("Breakpoint", cmp.Or(bp.Name, bp.URL))
		msg, ok := x.pause(bp, false, Message{Method: req.Method, URL: req.URL(), Header: req.Header, Body: req.Body})
		switch {
		case msg.Drop:
			x.drop()
			return
		case !ok:
			x.respond(http.StatusForbidden, textHeader(), []byte("Aborted at a ProxyGo breakpoint\n"))
			return
		case msg.Respond:
			x.setRequest(req)
			mark(f, "breakpointResponse", msg.StatusCode)
			x.respond(cmp.Or(msg.StatusCode, http.StatusOK), msg.Header, msg.Body)
			return
		}
		if err := applyRequest(req, msg); err != nil {
			mark(f, "breakpointError", err.Error())
		}
	}
	x.setRequest(req)

	if len(scripts) > 0 && script.Mocks(scripts) {
		mark(f, "mockAPI", true)
		x.finish(req, &script.Response{StatusCode: http.StatusOK, Header: flow.Header{}}, scripts, op)
		return
	}

	if m := data.MapLocalFor(req.Method, req.URL(), op); m != nil {
		resp, err := mapLocal(m, req)
		if err != nil {
			resp = &script.Response{StatusCode: http.StatusNotFound, Header: textHeader(), Body: []byte(err.Error() + "\n")}
		}
		mark(f, "mapLocal", map[string]any{"name": cmp.Or(m.Name, m.URL), "path": m.Path})
		x.diagnose("Map-Local", cmp.Or(m.Name, m.URL))
		if m.DelayMS > 0 && !x.sleep(time.Duration(m.DelayMS)*time.Millisecond) {
			return
		}
		x.finish(req, resp, scripts, op)
		return
	}

	if c := data.ConditionFor(req.Method, req.URL()); c != nil {
		x.cond = c
		f.IsUnderNetworkCondition = true
		mark(f, "network", cmp.Or(c.Name, "Custom"))
		if c.PacketLoss > 0 && rand.Float64()*100 < c.PacketLoss {
			x.fail(fmt.Errorf("request dropped by Network Conditions (%s, %.0f%% loss)", cmp.Or(c.Name, "Custom"), c.PacketLoss))
			return
		}
		if c.LatencyMS > 0 && !x.sleep(time.Duration(c.LatencyMS)*time.Millisecond) {
			return
		}
	}
	if rule := data.DNSFor(req.Host); rule != nil {
		mark(f, "dns", rule.IP)
	}

	out, err := x.outbound(req, rest)
	if err != nil {
		x.fail(err)
		return
	}
	resp, err := s.transport().RoundTrip(out)
	x.applyTrace()
	if err != nil {
		x.fail(err)
		return
	}
	defer resp.Body.Close()
	x.serverTLS(resp.TLS)

	needsBody := slices.ContainsFunc(scripts, func(r *rules.ScriptRule) bool { return r.OnResponse })
	if bp := data.BreakpointFor(req.Method, req.URL(), op, true); bp != nil && s.opts.Breakpoint != nil {
		needsBody = true
	}
	if !needsBody {
		x.stream(resp)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyCapture))
	if err != nil && len(raw) == 0 {
		x.fail(err)
		return
	}
	hdr := flow.NewHeaderOrdered(resp.Header, x.responseHeaders(out, resp))
	body = raw
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		if decoded, ok := flow.DecodeBody(raw, enc); ok {
			body = decoded
			hdr.Del("Content-Encoding")
		}
	}
	hdr.Del("Content-Length")
	hdr.Del("Transfer-Encoding")
	x.f.Response = &flow.Response{Version: flow.Version{Major: resp.ProtoMajor, Minor: resp.ProtoMinor}, HTTPVersion: resp.Proto}
	x.finish(req, &script.Response{StatusCode: resp.StatusCode, Header: hdr, Body: body}, scripts, op)
}

func (x *exchange) finish(req *script.Request, resp *script.Response, scripts []*rules.ScriptRule, op string) {
	s, f := x.s, x.f
	x.fillResponse(resp)
	if len(scripts) > 0 && s.opts.Scripts != nil {
		if err := s.opts.Scripts.RunResponse(scripts, f, req, resp); err != nil {
			mark(f, "scriptError", err.Error())
		}
	}
	if bp := x.data.BreakpointFor(req.Method, req.URL(), op, true); bp != nil && s.opts.Breakpoint != nil {
		x.fillResponse(resp)
		x.diagnose("Breakpoint", cmp.Or(bp.Name, bp.URL))
		msg, ok := x.pause(bp, true, Message{Method: req.Method, URL: req.URL(), StatusCode: resp.StatusCode, Header: resp.Header, Body: resp.Body})
		if msg.Drop {
			x.drop()
			return
		}
		if !ok {
			x.respond(http.StatusForbidden, textHeader(), []byte("Aborted at a ProxyGo breakpoint\n"))
			return
		}
		resp.StatusCode = cmp.Or(msg.StatusCode, resp.StatusCode)
		resp.Header = msg.Header
		resp.Body = msg.Body
	}
	if x.data.NoCaching {
		noCacheResponse(&resp.Header)
	}
	x.respond(resp.StatusCode, resp.Header, resp.Body)
}

func (x *exchange) fillResponse(resp *script.Response) {
	version := flow.Version{Major: 1, Minor: 1}
	proto := "HTTP/1.1"
	if x.f.Response != nil && x.f.Response.Version.Major > 0 {
		version, proto = x.f.Response.Version, x.f.Response.HTTPVersion
	}
	x.f.Response = &flow.Response{
		Status:      &flow.Status{Code: resp.StatusCode, Phrase: http.StatusText(resp.StatusCode)},
		Header:      resp.Header.Clone(),
		BodyData:    bytes.Clone(resp.Body),
		CreatedAt:   now(),
		Version:     version,
		HTTPVersion: proto,
	}
}

func (x *exchange) respond(status int, header flow.Header, body []byte) {
	f := x.f
	if f.Timing.ResponseStartedAt == nil {
		f.Timing.ResponseStartedAt = new(now())
	}
	header = header.Clone()
	header.Del("Content-Length")
	header.Del("Transfer-Encoding")
	x.addDiagnostics(&header)
	h := header.HTTP()
	if bodyAllowed(f.MethodName(), status) {
		h.Set("Content-Length", strconv.Itoa(len(body)))
		header.Add("Content-Length", strconv.Itoa(len(body)))
	}
	version := flow.Version{Major: 1, Minor: 1}
	proto := "HTTP/1.1"
	if f.Response != nil && f.Response.Version.Major > 0 {
		version, proto = f.Response.Version, f.Response.HTTPVersion
	}
	f.Response = &flow.Response{
		Status:      &flow.Status{Code: status, Phrase: http.StatusText(status)},
		Header:      header,
		BodyData:    bytes.Clone(body),
		CreatedAt:   now(),
		Version:     version,
		HTTPVersion: proto,
	}
	x.sink.header(status, h, headerNames(header))
	if bodyAllowed(f.MethodName(), status) && len(body) > 0 {
		_, _ = x.writer().Write(body)
	}
	x.sink.flush()
	f.Timing.ResponseEndedAt = new(now())
	x.publish()
}

func (x *exchange) stream(resp *http.Response) {
	f := x.f
	if x.data.NoCaching {
		noCacheHTTPResponse(resp.Header)
	}
	if x.data.DiagnosticHeaders {
		for _, e := range x.diag.Entries {
			resp.Header.Add(e.Key.Name, e.Value)
		}
	}
	f.Response = &flow.Response{
		Status:      &flow.Status{Code: resp.StatusCode, Phrase: phrase(resp)},
		Header:      flow.NewHeaderOrdered(resp.Header, x.responseHeaders(resp.Request, resp)),
		CreatedAt:   now(),
		Version:     flow.Version{Major: resp.ProtoMajor, Minor: resp.ProtoMinor},
		HTTPVersion: resp.Proto,
	}
	x.publish()

	h := resp.Header.Clone()
	allowed := bodyAllowed(f.MethodName(), resp.StatusCode)
	h.Del("Content-Length")
	if resp.ContentLength >= 0 && allowed {
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	x.sink.header(resp.StatusCode, h, headerNames(f.Response.Header))
	if !allowed {
		x.sink.flush()
		f.Timing.ResponseEndedAt = new(now())
		x.publish()
		return
	}

	live := resp.ContentLength < 0 || strings.Contains(resp.Header.Get("Content-Type"), "event-stream")
	w := x.writer()
	var captured bytes.Buffer
	truncated := false
	buf := make([]byte, 32<<10)
	var readErr error
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if room := maxBodyCapture - captured.Len(); room > 0 {
				captured.Write(buf[:min(n, room)])
				truncated = truncated || n > room
			} else {
				truncated = true
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				readErr = werr
				break
			}
			x.sink.flush()
			if live && time.Since(x.published) > time.Second {
				f.Response.BodyData = bytes.Clone(captured.Bytes())
				x.publish()
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	f.Response.BodyData = captured.Bytes()
	if truncated {
		if f.ConnectionRecord == nil {
			f.ConnectionRecord = &flow.ConnectionRecord{}
		}
		f.ConnectionRecord.Exchange.Truncated = true
	}
	if readErr != nil && !errors.Is(readErr, context.Canceled) {
		mark(f, "streamError", readErr.Error())
	}
	f.Timing.ResponseEndedAt = new(now())
	x.publish()
}

func (x *exchange) writer() io.Writer {
	if x.cond != nil && x.cond.DownloadKBps > 0 {
		return &rateWriter{ctx: x.ctx, w: x.sink, flush: x.sink.flush, rate: x.cond.DownloadKBps * 1024, start: time.Now()}
	}
	return x.sink
}

func (x *exchange) drop() {
	x.f.Response = errorResponse(errors.New("the connection was dropped at a breakpoint"))
	x.f.Response.Error = flow.ResponseError{"cancelled": map[string]any{"message": "The connection was dropped at a breakpoint"}}
	x.f.Timing.ResponseEndedAt = new(now())
	x.publish()
	x.sink.abort()
}

func (x *exchange) diagnose(tool, rule string) {
	x.diag.Add("X-ProxyGo-"+tool, headerSafe(rule))
}

func (x *exchange) addDiagnostics(h *flow.Header) {
	if !x.data.DiagnosticHeaders {
		return
	}
	for _, e := range x.diag.Entries {
		h.Add(e.Key.Name, e.Value)
	}
}

func headerSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return shortText(strings.TrimSpace(s), 200)
}

func shortText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Server) blockedApp(c flow.Client) *rules.AppRule {
	id := ""
	if c.BundleIdentifier != nil {
		id = *c.BundleIdentifier
	}
	return s.rules().BlockedApp(id, c.Name)
}

func appLabel(r *rules.AppRule) string { return cmp.Or(r.AppName, r.BundleID) }

func (x *exchange) fail(err error) {
	f := x.f
	f.Response = errorResponse(err)
	f.Timing.ResponseEndedAt = new(now())
	x.publish()
	if x.ctx.Err() != nil {
		return
	}
	body := []byte("ProxyGo: " + err.Error() + "\n")
	h := http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "Content-Length": {strconv.Itoa(len(body))}}
	x.sink.header(http.StatusBadGateway, h, nil)
	_, _ = x.sink.Write(body)
	x.sink.flush()
}

func (x *exchange) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-x.ctx.Done():
		x.f.Response = errorResponse(context.Canceled)
		x.f.Timing.ResponseEndedAt = new(now())
		x.publish()
		return false
	}
}

func (x *exchange) pause(rule *rules.BreakpointRule, response bool, m Message) (Message, bool) {
	name := cmp.Or(rule.Name, rule.URL)
	mark(x.f, "breakpoint", name)
	mark(x.f, "paused", map[bool]string{false: "request", true: "response"}[response])
	x.publish()
	p := &Pause{ID: flow.NewUniqueID(), Response: response, Rule: name, Flow: x.f.Clone(), Message: m}
	p.Message.Header = m.Header.Clone()
	p.Message.Body = bytes.Clone(m.Body)
	msg, ok := x.s.opts.Breakpoint(x.ctx, p)
	if md, _ := x.f.ToolMetadata.(map[string]any); md != nil {
		delete(md, "paused")
	}
	if x.ctx.Err() != nil {
		return msg, false
	}
	return msg, ok
}

func (x *exchange) mapRemote(m *rules.MapRemoteRule, req *script.Request) {
	u, err := url.Parse(req.URL())
	if err != nil {
		return
	}
	nu, err := m.Rewrite(u)
	if err != nil {
		mark(x.f, "mapRemoteError", err.Error())
		return
	}
	setURL(req, nu)
	if m.PreserveHost {
		x.preserveHost = true
	} else {
		req.Header.Set("Host", nu.Host)
	}
	mark(x.f, "mapRemote", map[string]any{"name": cmp.Or(m.Name, m.URL), "url": nu.String()})
	x.diagnose("Map-Remote", cmp.Or(m.Name, m.URL))
}

func setURL(req *script.Request, u *url.URL) {
	req.Scheme = u.Scheme
	req.Host = u.Hostname()
	req.Port = defaultPort(u.Scheme)
	if p := u.Port(); p != "" {
		req.Port, _ = strconv.Atoi(p)
	}
	req.Path = u.RequestURI()
}

func applyRequest(req *script.Request, m Message) error {
	if m.Method != "" {
		req.Method = strings.ToUpper(strings.TrimSpace(m.Method))
	}
	if u := strings.TrimSpace(m.URL); u != "" && u != req.URL() {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("invalid URL %q", m.URL)
		}
		oldHost := req.Header.Get("Host")
		setURL(req, parsed)
		if m.Header.Get("Host") == oldHost {
			m.Header.Set("Host", parsed.Host)
		}
	}
	req.Header = m.Header
	req.Body = m.Body
	return nil
}

func (x *exchange) setRequest(req *script.Request) {
	r := x.f.Request
	if req.Header.Get("Content-Length") != "" && x.f.ConnectionRecord == nil {
		req.Header.Set("Content-Length", strconv.Itoa(len(req.Body)))
	}
	if !x.preserveHost {
		name := "Host"
		if req.Header.Get(":authority") != "" {
			name = ":authority"
		}
		if host := req.Header.Get(name); host == "" || host == x.hostHeader {
			req.Header.Set(name, hostPort(req.Scheme, req.Host, req.Port))
		}
	}
	r.Method = flow.Method{Name: req.Method}
	r.Scheme = req.Scheme
	r.Host = req.Host
	r.Port = req.Port
	r.IsSSL = req.Scheme == "https"
	r.URI = req.Path
	r.FullPath = req.URL()
	r.Header = req.Header.Clone()
	r.BodyData = bytes.Clone(req.Body)
	x.f.IsSSL = r.IsSSL
	x.f.Summary.ServerPort = req.Port
}

func hostPort(scheme, host string, port int) string {
	if port == defaultPort(scheme) || port == 0 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return joinHostPort(host, port)
}

func (x *exchange) outbound(req *script.Request, rest io.Reader) (*http.Request, error) {
	u, err := url.Parse(req.URL())
	if err != nil {
		return nil, err
	}
	var body io.Reader = bytes.NewReader(req.Body)
	length := int64(len(req.Body))
	if rest != nil {
		body, length = io.MultiReader(body, rest), x.length
	}
	if x.cond != nil && x.cond.UploadKBps > 0 {
		body = &rateReader{ctx: x.ctx, r: body, rate: x.cond.UploadKBps * 1024, start: time.Now()}
	}
	x.trace.set(func() { x.trace.plan = headerNames(req.Header) })
	ctx := httptrace.WithClientTrace(x.ctx, x.trace.hooks())
	out, err := http.NewRequestWithContext(ctx, req.Method, u.String(), body)
	if err != nil {
		return nil, err
	}
	out.ContentLength = length
	if length == 0 && rest == nil {
		out.Body = http.NoBody
	}
	out.Header = req.Header.HTTP()
	out.Host = cmp.Or(out.Header.Get("Host"), req.Header.Get(":authority"), u.Host)
	out.Header.Del("Host")
	removeHopByHop(out.Header)
	out.Header.Del("Expect")
	if _, ok := out.Header["User-Agent"]; !ok {
		out.Header["User-Agent"] = []string{""}
	}
	if x.data.NoCaching {
		for _, k := range []string{"If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since"} {
			out.Header.Del(k)
		}
		out.Header.Set("Cache-Control", "no-cache")
		out.Header.Set("Pragma", "no-cache")
	}
	return out, nil
}

func mapLocal(m *rules.MapLocalRule, req *script.Request) (*script.Response, error) {
	resp := &script.Response{StatusCode: cmp.Or(m.StatusCode, http.StatusOK)}
	var body []byte
	name := ""
	if m.Path == "" {
		body = []byte(m.Body)
	} else {
		p := expandHome(m.Path)
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("ProxyGo Map Local: %w", err)
		}
		if info.IsDir() {
			p = filepath.Join(p, filepath.FromSlash(dirRest(m.URL, req.Path)))
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				p = filepath.Join(p, "index.html")
			}
		}
		body, err = os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("ProxyGo Map Local: %w", err)
		}
		name = p
	}
	ct := m.ContentType
	if ct == "" && name != "" {
		ct = mime.TypeByExtension(filepath.Ext(name))
	}
	if ct == "" && len(body) > 0 {
		ct = http.DetectContentType(body)
		if jsontext.Value(body).IsValid() {
			ct = "application/json"
		}
	}
	if ct != "" {
		resp.Header.Set("Content-Type", ct)
	}
	for _, h := range m.Headers {
		if h.Name != "" {
			resp.Header.Set(h.Name, h.Value)
		}
	}
	resp.Body = body
	return resp, nil
}

func dirRest(pattern, reqPath string) string {
	reqPath, _, _ = strings.Cut(reqPath, "?")
	p := pattern
	if i := strings.Index(p, "://"); i >= 0 {
		p = p[i+3:]
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[i:]
	} else {
		p = "/"
	}
	if i := strings.IndexAny(p, "*?"); i >= 0 {
		p = p[:i]
	}
	rest := strings.TrimPrefix(reqPath, strings.TrimSuffix(p, "/"))
	return path.Clean("/" + rest)
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}

func textHeader() flow.Header {
	var h flow.Header
	h.Set("Content-Type", "text/plain; charset=utf-8")
	return h
}

func bodyAllowed(method string, status int) bool {
	return method != http.MethodHead && status != http.StatusNoContent && status != http.StatusNotModified && status >= 200
}

func phrase(resp *http.Response) string {
	if p := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode))); p != "" {
		return p
	}
	return http.StatusText(resp.StatusCode)
}

func scriptNames(list []*rules.ScriptRule) string {
	names := make([]string, len(list))
	for i, r := range list {
		names[i] = r.Name
	}
	return strings.Join(names, ", ")
}

func noCacheResponse(h *flow.Header) {
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Del("ETag")
	h.Del("Last-Modified")
}

func noCacheHTTPResponse(h http.Header) {
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Del("ETag")
	h.Del("Last-Modified")
}

func isWebSocket(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for part := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
				return true
			}
		}
	}
	return false
}

type traceTimes struct {
	mu                    sync.Mutex
	dnsStart, dnsEnd      float64
	connStart, connEnd    float64
	tlsStart, tlsEnd      float64
	wrote, firstByte      float64
	ip                    string
	dnsIP                 string
	reused, gotConnection bool
	conn                  net.Conn
	plan                  []string
}

func (t *traceTimes) set(fn func()) {
	t.mu.Lock()
	fn()
	t.mu.Unlock()
}

func (t *traceTimes) hooks() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { t.set(func() { t.dnsStart = now() }) },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			t.set(func() {
				t.dnsEnd = now()
				if len(info.Addrs) > 0 {
					t.dnsIP = info.Addrs[0].IP.String()
				}
			})
		},
		ConnectStart: func(string, string) {
			t.set(func() {
				if t.connStart == 0 {
					t.connStart = now()
				}
			})
		},
		ConnectDone:       func(string, string, error) { t.set(func() { t.connEnd = now() }) },
		TLSHandshakeStart: func() { t.set(func() { t.tlsStart = now() }) },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { t.set(func() { t.tlsEnd = now() }) },
		GotConn: func(info httptrace.GotConnInfo) {
			t.set(func() {
				t.gotConnection = true
				t.reused = info.Reused
				t.conn = info.Conn
				wire.PlanHead(info.Conn, t.plan)
				if info.Conn != nil {
					t.ip = remoteHost(info.Conn.RemoteAddr().String())
				}
			})
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { t.set(func() { t.wrote = now() }) },
		GotFirstResponseByte: func() { t.set(func() { t.firstByte = now() }) },
	}
}

func (x *exchange) applyTrace() {
	t := &x.trace
	t.mu.Lock()
	defer t.mu.Unlock()
	f := x.f
	at := func(v float64) *float64 {
		if v == 0 {
			return nil
		}
		return new(v)
	}
	f.Timing.UpstreamConnectStartedAt = at(t.connStart)
	f.Timing.UpstreamConnectEndedAt = at(t.connEnd)
	f.Timing.UpstreamTLSStartedAt = at(t.tlsStart)
	f.Timing.UpstreamTLSEndedAt = at(t.tlsEnd)
	f.Timing.RequestEndedAt = at(t.wrote)
	f.Timing.ResponseStartedAt = at(t.firstByte)
	if t.ip != "" {
		f.Summary.ServerIPAddress = t.ip
	}
	if t.dnsIP != "" {
		f.Summary.HostDNS = new(t.dnsIP)
	}
	if t.gotConnection {
		if f.ConnectionRecord == nil {
			f.ConnectionRecord = &flow.ConnectionRecord{}
		}
		f.ConnectionRecord.Exchange.Reused = t.reused
		f.ConnectionRecord.Exchange.RequestSent = t.wrote != 0
	}
	if t.dnsStart != 0 && t.dnsEnd != 0 {
		mark(f, "dnsLookup", (t.dnsEnd-t.dnsStart)*1000)
	}
}
