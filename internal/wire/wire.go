package wire

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"sync"

	"proxygo/internal/flow"
)

const maxHeads = 64

type Field = flow.SentHeader

type head struct {
	fields []Field
	method string
	target string
	status int
	stream uint32
}

type recorder struct {
	mu          sync.Mutex
	h2          bool
	in          parser
	out         parser
	reqs, resps []head
	methods     []string
	sent        map[uint32]head
	plan        []string
	pending     []byte
}

type parser interface{ feed(b []byte) }

func (r *recorder) addRequest(h head) { r.reqs = keep(r.reqs, h) }

func (r *recorder) addResponse(h head) { r.resps = keep(r.resps, h) }

func keep(list []head, h head) []head {
	if len(list) >= maxHeads {
		list = slices.Delete(list, 0, 1)
	}
	return append(list, h)
}

func (r *recorder) wrote(h head) {
	if !r.h2 {
		if len(r.methods) < maxHeads {
			r.methods = append(r.methods, h.method)
		}
		return
	}
	if r.sent == nil || len(r.sent) >= 4*maxHeads {
		r.sent = map[uint32]head{}
	}
	r.sent[h.stream] = h
}

func (r *recorder) method() string {
	if len(r.methods) == 0 {
		return ""
	}
	m := r.methods[0]
	r.methods = r.methods[1:]
	return m
}

type Conn struct {
	net.Conn
	rec *recorder
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.mu.Lock()
		c.rec.in.feed(p[:n])
		c.rec.mu.Unlock()
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	rec := c.rec
	rec.mu.Lock()
	if rec.plan != nil {
		rec.pending = append(rec.pending, p...)
		end := bytes.Index(rec.pending, []byte("\r\n\r\n"))
		if end < 0 && len(rec.pending) < maxHead {
			rec.mu.Unlock()
			return len(p), nil
		}
		out := rec.pending
		if end >= 0 {
			out = append(reorderHead(out[:end+4], rec.plan), out[end+4:]...)
		}
		rec.plan, rec.pending = nil, nil
		if rec.out != nil {
			rec.out.feed(out)
		}
		rec.mu.Unlock()
		if _, err := c.Conn.Write(out); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if rec.out != nil && len(p) > 0 {
		rec.out.feed(p)
	}
	rec.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type tlsConn struct {
	*Conn
	state interface{ ConnectionState() tls.ConnectionState }
}

func (c *tlsConn) ConnectionState() tls.ConnectionState { return c.state.ConnectionState() }

func (c *tlsConn) HandshakeContext(ctx context.Context) error {
	if h, ok := c.state.(interface {
		HandshakeContext(context.Context) error
	}); ok {
		return h.HandshakeContext(ctx)
	}
	return nil
}

func Server(c net.Conn) net.Conn {
	rec := &recorder{h2: negotiatedH2(c)}
	if rec.h2 {
		rec.in = newH2(rec, h2Requests)
	} else {
		rec.in = &h1{rec: rec, request: true, server: true}
	}
	return wrap(c, rec)
}

func Client(c net.Conn) net.Conn {
	rec := &recorder{h2: negotiatedH2(c)}
	if rec.h2 {
		rec.in = newH2(rec, h2Responses)
		rec.out = newH2(rec, h2Sent)
	} else {
		rec.in = &h1{rec: rec}
		rec.out = &h1{rec: rec, request: true}
	}
	return wrap(c, rec)
}

func negotiatedH2(c net.Conn) bool {
	s, ok := c.(interface{ ConnectionState() tls.ConnectionState })
	return ok && s.ConnectionState().NegotiatedProtocol == "h2"
}

func wrap(c net.Conn, rec *recorder) net.Conn {
	w := &Conn{Conn: c, rec: rec}
	if s, ok := c.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return &tlsConn{Conn: w, state: s}
	}
	return w
}

func recorderOf(c net.Conn) *recorder {
	switch c := c.(type) {
	case *Conn:
		return c.rec
	case *tlsConn:
		return c.rec
	}
	return nil
}

func PlanHead(c net.Conn, names []string) {
	rec := recorderOf(c)
	if rec == nil || rec.h2 || len(names) == 0 {
		return
	}
	rec.mu.Lock()
	rec.plan, rec.pending = slices.Clone(names), nil
	rec.mu.Unlock()
}

func reorderHead(head []byte, plan []string) []byte {
	lines := strings.Split(strings.TrimSuffix(string(head), "\r\n\r\n"), "\r\n")
	headers := lines[1:]
	used := make([]bool, len(headers))
	out := []string{lines[0]}
	for _, name := range plan {
		for i, line := range headers {
			if n, value, ok := strings.Cut(line, ":"); !used[i] && ok && strings.EqualFold(strings.TrimSpace(n), name) {
				out, used[i] = append(out, name+":"+value), true
				break
			}
		}
	}
	for i, line := range headers {
		if !used[i] {
			out = append(out, line)
		}
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n\r\n")
}

func Listener(ln net.Listener) net.Listener { return listener{ln} }

type listener struct{ net.Listener }

func (l listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c), nil
}

type connKey struct{}

func WithConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

func ConnOf(ctx context.Context) net.Conn {
	c, _ := ctx.Value(connKey{}).(net.Conn)
	return c
}

func RequestHeaders(c net.Conn, method, target string) []Field {
	rec := recorderOf(c)
	if rec == nil {
		return nil
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i, h := range rec.reqs {
		if h.method != method || h.target != target {
			continue
		}
		if rec.h2 {
			rec.reqs = slices.Delete(rec.reqs, i, i+1)
		} else {
			rec.reqs = rec.reqs[i+1:]
		}
		return h.fields
	}
	return nil
}

func ResponseHeaders(c net.Conn, method, target string, status int) []Field {
	rec := recorderOf(c)
	if rec == nil {
		return nil
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i, h := range rec.resps {
		if h.status != status {
			continue
		}
		if !rec.h2 {
			rec.resps = rec.resps[i+1:]
			return h.fields
		}
		if req, ok := rec.sent[h.stream]; ok && (req.method != method || req.target != target) {
			continue
		}
		rec.resps = slices.Delete(rec.resps, i, i+1)
		delete(rec.sent, h.stream)
		return h.fields
	}
	return nil
}
