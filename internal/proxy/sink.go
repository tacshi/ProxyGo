package proxy

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/textproto"
	"strings"

	"proxygo/internal/flow"
	"proxygo/internal/wire"
)

type Message struct {
	Method     string
	URL        string
	StatusCode int
	Header     flow.Header
	Body       []byte

	Drop    bool
	Respond bool
}

type Pause struct {
	ID       string
	Response bool
	Rule     string
	Flow     *flow.Flow
	Message  Message
}

type clientSink interface {
	header(status int, h http.Header, order []string)
	Write(p []byte) (int, error)
	flush()
	hijack() (net.Conn, *bufio.ReadWriter, error)
	abort()
}

type httpSink struct {
	w    http.ResponseWriter
	rc   *http.ResponseController
	conn net.Conn
}

func newHTTPSink(w http.ResponseWriter, r *http.Request) *httpSink {
	return &httpSink{w: w, rc: http.NewResponseController(w), conn: wire.ConnOf(r.Context())}
}

func (h *httpSink) header(status int, src http.Header, order []string) {
	dst := h.w.Header()
	for k, vs := range src {
		dst[k] = vs
	}
	removeHopByHop(dst)
	wire.PlanHead(h.conn, order)
	h.w.WriteHeader(status)
}

func (h *httpSink) Write(p []byte) (int, error) { return h.w.Write(p) }
func (h *httpSink) flush()                      { _ = h.rc.Flush() }
func (h *httpSink) hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.rc.Hijack()
}
func (h *httpSink) abort() { panic(http.ErrAbortHandler) }

type discardSink struct{ status int }

func (d *discardSink) header(status int, _ http.Header, _ []string) { d.status = status }
func (d *discardSink) Write(p []byte) (int, error)                  { return len(p), nil }
func (d *discardSink) flush()                                       {}
func (d *discardSink) hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("a replayed request cannot upgrade")
}
func (d *discardSink) abort() {}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for name := range strings.SplitSeq(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		delete(h, textproto.CanonicalMIMEHeaderKey(name))
	}
}
