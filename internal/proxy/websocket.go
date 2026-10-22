package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/script"
	"proxygo/internal/wire"
)

const (
	closeGrace          = 5 * time.Second
	maxWebSocketFrame   = 32 << 20
	maxWebSocketMessage = 4 << 20
	maxWebSocketHistory = 10000
)

func (x *exchange) webSocket(r *http.Request, body []byte) {
	f, s := x.f, x.s
	host, port := f.Request.Host, f.Request.Port
	ctx, cancel := context.WithTimeout(x.ctx, 30*time.Second)
	defer cancel()

	raw, ip, err := s.dialTunnel(ctx, host, port)
	if err != nil {
		x.fail(err)
		return
	}
	upstream := raw
	if f.Request.Scheme == "https" {
		cfg := s.tlsConfig(host, false)
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			x.fail(err)
			return
		}
		cs := tc.ConnectionState()
		x.serverTLS(&cs)
		upstream = tc
	}
	f.Summary.ServerIPAddress = ip
	upstream = wire.Client(upstream)
	defer upstream.Close()

	out := r.Clone(ctx)
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	for _, k := range []string{"Proxy-Connection", "Proxy-Authorization", "Keep-Alive"} {
		out.Header.Del(k)
	}
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	if len(body) == 0 {
		out.Body = nil
	}
	_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
	wire.PlanHead(upstream, headerNames(f.Request.Header))
	if err := out.Write(upstream); err != nil {
		x.fail(err)
		return
	}
	upBR := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upBR, out)
	if err != nil {
		x.fail(err)
		return
	}
	_ = upstream.SetDeadline(time.Time{})
	f.Timing.ResponseStartedAt = new(now())
	order := wire.ResponseHeaders(upstream, out.Method, out.URL.RequestURI(), resp.StatusCode)
	f.Response = &flow.Response{
		Status:      &flow.Status{Code: resp.StatusCode, Phrase: phrase(resp)},
		Header:      flow.NewHeaderOrdered(resp.Header, order),
		CreatedAt:   now(),
		Version:     flow.Version{Major: resp.ProtoMajor, Minor: resp.ProtoMinor},
		HTTPVersion: resp.Proto,
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyCapture))
		_ = resp.Body.Close()
		x.respond(resp.StatusCode, flow.NewHeaderOrdered(resp.Header, order), b)
		return
	}
	f.WebSocketMessageStorage = &flow.WebSocketStorage{Messages: []flow.WebSocketMessage{}}
	x.publish()

	if fs, ok := x.sink.(interface{ setFlow(*flow.Flow) }); ok {
		fs.setFlow(f.Clone())
	}
	client, clientRW, err := x.sink.hijack()
	if err != nil {
		mark(f, "websocketError", err.Error())
		f.Timing.ResponseEndedAt = new(now())
		x.publish()
		return
	}
	defer client.Close()
	live := &liveSocket{rec: &wsRecorder{x: x}}
	live.sides[toServer] = &wsSide{conn: upstream, mask: true}
	live.sides[toClient] = &wsSide{conn: client}
	rec := live.rec
	rec.onMessage = x.webSocketHook(r)
	live.sides[toClient].mu.Lock()
	s.sockets.Store(f.UniqueID, live)
	defer s.sockets.Delete(f.UniqueID)
	wire.PlanHead(client, headerNames(f.Response.Header))
	err = writeUpgrade(client, resp)
	live.sides[toClient].mu.Unlock()
	if err != nil {
		return
	}
	stop := func(c net.Conn, closed bool) {
		deadline := time.Now()
		if closed {
			deadline = deadline.Add(closeGrace)
		}
		_ = c.SetReadDeadline(deadline)
	}
	var wg sync.WaitGroup
	wg.Go(func() { stop(upstream, relayFrames(clientRW.Reader, live.sides[toServer], "client", rec)) })
	wg.Go(func() { stop(client, relayFrames(upBR, live.sides[toClient], "server", rec)) })
	wg.Wait()
	if x.wsSession != nil {
		x.wsSession.Close()
	}
	f.Timing.ResponseEndedAt = new(now())
	rec.mu.Lock()
	f.WebSocketMessageStorage.Messages = rec.messages
	rec.mu.Unlock()
	x.publish()
}

func writeUpgrade(w io.Writer, resp *http.Response) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, phrase(resp))
	_ = resp.Header.Write(&b)
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

type wsRecorder struct {
	x         *exchange
	mu        sync.Mutex
	messages  []flow.WebSocketMessage
	onMessage func(flow.WebSocketMessage)
}

func (r *wsRecorder) add(m flow.WebSocketMessage) {
	r.mu.Lock()
	if len(r.messages) >= maxWebSocketHistory {
		r.messages = r.messages[1:]
	}
	r.messages = append(r.messages, m)
	r.mu.Unlock()
	if r.onMessage != nil {
		r.onMessage(m)
	}
	if !r.x.record || r.x.s.opts.Sink == nil {
		return
	}
	r.x.s.opts.Sink.Update(r.x.f.UniqueID, func(stored *flow.Flow) {
		var msgs []flow.WebSocketMessage
		if stored.WebSocketMessageStorage != nil {
			msgs = stored.WebSocketMessageStorage.Messages
		}
		msgs = append(msgs, m)
		if len(msgs) > maxWebSocketHistory {
			msgs = msgs[len(msgs)-maxWebSocketHistory:]
		}
		stored.WebSocketMessageStorage = &flow.WebSocketStorage{Messages: msgs}
	})
}

func relayFrames(br *bufio.Reader, dst *wsSide, from string, rec *wsRecorder) bool {
	var assembled []byte
	assembledType := ""
	for {
		frame, err := readFrame(br)
		if err != nil {
			return false
		}
		if err := dst.relay(frame); err != nil {
			return false
		}
		switch frame.opcode {
		case 0x0:
			if len(assembled) < maxWebSocketMessage {
				assembled = append(assembled, frame.payload...)
			}
			if frame.fin && assembledType != "" {
				rec.add(message(from, assembledType, assembled, 0))
				assembled, assembledType = nil, ""
			}
		case 0x1, 0x2:
			typ := "text"
			if frame.opcode == 0x2 {
				typ = "binary"
			}
			if frame.fin {
				rec.add(message(from, typ, frame.payload, 0))
			} else {
				assembled, assembledType = append(assembled[:0], frame.payload...), typ
			}
		case 0x8:
			code := 0
			if len(frame.payload) >= 2 {
				code = int(binary.BigEndian.Uint16(frame.payload[:2]))
			}
			reason := []byte(nil)
			if len(frame.payload) > 2 {
				reason = frame.payload[2:]
			}
			rec.add(message(from, "close", reason, code))
			return true
		case 0x9:
			rec.add(message(from, "ping", frame.payload, 0))
		case 0xA:
			rec.add(message(from, "pong", frame.payload, 0))
		}
	}
}

func message(from, typ string, payload []byte, code int) flow.WebSocketMessage {
	if len(payload) > maxWebSocketMessage {
		payload = payload[:maxWebSocketMessage]
	}
	m := flow.WebSocketMessage{From: from, Type: typ, Time: now(), CloseCode: code}
	if typ == "binary" {
		m.RawData = bytes.Clone(payload)
	} else {
		m.Data = string(payload)
	}
	return m
}

type wsFrame struct {
	fin     bool
	opcode  byte
	payload []byte
	raw     []byte
}

func readFrame(br *bufio.Reader) (wsFrame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return wsFrame{}, err
	}
	fin := hdr[0]&0x80 != 0
	opcode := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7f)
	raw := append([]byte(nil), hdr[:]...)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return wsFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
		raw = append(raw, ext[:]...)
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return wsFrame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		raw = append(raw, ext[:]...)
	}
	if length > maxWebSocketFrame {
		return wsFrame{}, fmt.Errorf("websocket frame too large: %d bytes", length)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return wsFrame{}, err
		}
		raw = append(raw, mask[:]...)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(br, payload); err != nil {
		return wsFrame{}, err
	}
	raw = append(raw, payload...)
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return wsFrame{fin: fin, opcode: opcode, payload: payload, raw: raw}, nil
}

const (
	toServer = 0
	toClient = 1
)

type liveSocket struct {
	rec   *wsRecorder
	sides [2]*wsSide
}

type wsSide struct {
	mu      sync.Mutex
	conn    net.Conn
	mask    bool
	partial bool
}

func (w *wsSide) relay(f wsFrame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch f.opcode {
	case 0x0:
		w.partial = !f.fin
	case 0x1, 0x2:
		w.partial = !f.fin
	}
	_, err := w.conn.Write(f.raw)
	return err
}

var ErrWebSocketBusy = errors.New("a message is passing in parts: send again in a moment")

var ErrWebSocketClosed = errors.New("the WebSocket is not open")

func (w *wsSide) send(opcode byte, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.partial && opcode < 0x8 {
		return ErrWebSocketBusy
	}
	_, err := w.conn.Write(encodeFrame(opcode, payload, w.mask))
	return err
}

func encodeFrame(opcode byte, payload []byte, mask bool) []byte {
	b := []byte{0x80 | opcode}
	bit := byte(0)
	if mask {
		bit = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		b = append(b, bit|byte(n))
	case n <= 0xffff:
		b = append(b, bit|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, bit|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if !mask {
		return append(b, payload...)
	}
	var key [4]byte
	_, _ = rand.Read(key[:])
	b = append(b, key[:]...)
	for i, p := range payload {
		b = append(b, p^key[i%4])
	}
	return b
}

var wsOpcodes = map[string]byte{"text": 0x1, "binary": 0x2, "close": 0x8, "ping": 0x9, "pong": 0xA}

func (s *Server) SendWebSocket(flowID string, toServerSide bool, typ string, data []byte) error {
	v, ok := s.sockets.Load(flowID)
	if !ok {
		return ErrWebSocketClosed
	}
	live := v.(*liveSocket)
	opcode, ok := wsOpcodes[typ]
	if !ok {
		return fmt.Errorf("unknown WebSocket message type %q", typ)
	}
	payload, code := data, 0
	if typ == "close" {
		code = 1000
		payload = binary.BigEndian.AppendUint16(nil, uint16(code))
		payload = append(payload, data...)
	}
	side, from := live.sides[toClient], "server"
	if toServerSide {
		side, from = live.sides[toServer], "client"
	}
	if err := side.send(opcode, payload); err != nil {
		return err
	}
	m := message(from, typ, data, code)
	m.Injected = true
	live.rec.add(m)
	return nil
}

func (s *Server) WebSocketOpen(flowID string) bool {
	_, ok := s.sockets.Load(flowID)
	return ok
}

func (s *Server) OpenWebSocket(ctx context.Context, m Message) (*flow.Flow, error) {
	u, err := url.Parse(strings.TrimSpace(m.URL))
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
	default:
		return nil, errors.New("a WebSocket's URL starts with ws:// or wss://")
	}
	if u.Host == "" {
		return nil, errors.New("the URL has no host")
	}
	h := m.Header.Clone()
	h.Set("Upgrade", "websocket")
	h.Set("Connection", "Upgrade")
	h.Set("Sec-WebSocket-Version", "13")
	if h.Get("Sec-WebSocket-Key") == "" {
		var key [16]byte
		_, _ = rand.Read(key[:])
		h.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key[:]))
	}
	h.Del("Sec-WebSocket-Extensions")
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header = h.HTTP()
	req.Host = u.Host
	if hh := req.Header.Get("Host"); hh != "" {
		req.Host = hh
	}
	req.Header.Del("Host")
	req.RemoteAddr = "127.0.0.1:0"
	req.RequestURI = u.RequestURI()
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	near, far := net.Pipe()
	sink := &pipeSink{conn: far, hijacked: make(chan struct{})}
	done := make(chan *flow.Flow, 1)
	client := flow.Client{Name: "ProxyGo", PID: os.Getpid(), Path: executablePath()}
	go func() { done <- s.exchange(req, nil, nil, client, nil, sink) }()
	select {
	case f := <-done:
		_ = near.Close()
		return f, nil
	case <-sink.hijacked:
	case <-ctx.Done():
		_ = near.Close()
		return nil, ctx.Err()
	}
	br := bufio.NewReader(near)
	if _, err := http.ReadResponse(br, req); err != nil {
		_ = near.Close()
		return nil, err
	}
	f := sink.flow()
	cs := &composeSocket{s: s, id: f.UniqueID, near: near, done: done}
	s.composed.Store(cs.id, cs)
	go cs.drain(br)
	return f, nil
}

func (s *Server) Composed(flowID string) bool {
	_, ok := s.composed.Load(flowID)
	return ok
}

func (s *Server) CloseWebSocket(flowID string) {
	v, ok := s.composed.Load(flowID)
	if !ok {
		return
	}
	cs := v.(*composeSocket)
	if cs.closing.Swap(true) {
		return
	}
	_ = s.SendWebSocket(flowID, true, "close", nil)
	go func() {
		select {
		case <-cs.done:
		case <-time.After(closeGrace):
			_ = cs.near.Close()
		}
	}()
}

type composeSocket struct {
	s       *Server
	id      string
	near    net.Conn
	done    chan *flow.Flow
	closing atomic.Bool
}

func (cs *composeSocket) drain(br *bufio.Reader) {
	defer func() {
		_ = cs.near.Close()
		cs.s.composed.Delete(cs.id)
	}()
	for {
		f, err := readFrame(br)
		if err != nil {
			return
		}
		switch f.opcode {
		case 0x9:
			_ = cs.s.SendWebSocket(cs.id, true, "pong", f.payload)
		case 0x8:
			if !cs.closing.Swap(true) {
				_ = cs.s.SendWebSocket(cs.id, true, "close", nil)
			}
			return
		}
	}
}

type pipeSink struct {
	discardSink
	conn     net.Conn
	once     sync.Once
	hijacked chan struct{}
	mu       sync.Mutex
	f        *flow.Flow
}

func (p *pipeSink) hijack() (net.Conn, *bufio.ReadWriter, error) {
	p.once.Do(func() { close(p.hijacked) })
	return p.conn, bufio.NewReadWriter(bufio.NewReader(p.conn), bufio.NewWriter(p.conn)), nil
}

func (p *pipeSink) setFlow(f *flow.Flow) {
	p.mu.Lock()
	p.f = f
	p.mu.Unlock()
}

func (p *pipeSink) flow() *flow.Flow {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.f
}

func (x *exchange) webSocketHook(r *http.Request) func(flow.WebSocketMessage) {
	s, f := x.s, x.f
	if s.opts.Scripts == nil {
		return nil
	}
	list := x.data.ScriptsFor(f.MethodName(), f.URL(), f.GraphQLOperation())
	if len(list) == 0 {
		return nil
	}
	req := &script.Request{Method: f.MethodName(), Scheme: f.Request.Scheme, Host: f.Request.Host, Port: f.Request.Port,
		Path: r.URL.RequestURI(), Header: f.Request.Header.Clone()}
	var resp *script.Response
	if f.Response != nil {
		resp = &script.Response{StatusCode: f.StatusCode(), Header: f.Response.Header.Clone()}
	}
	session := s.opts.Scripts.NewWebSocketSession(list, f, req, resp)
	if session == nil {
		return nil
	}
	x.wsSession = session
	return session.Add
}
