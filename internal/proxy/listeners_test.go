package proxy

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- RFC 6455 computes the WebSocket accept key with SHA-1.
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/script"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing listens on %d", port)
}

func TestReverseProxy(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	port := freePort(t)
	e.update(func(d *rules.Data) {
		d.ReverseProxies = append(d.ReverseProxies, &rules.ReverseProxy{ID: "r", Enabled: true, ListenPort: port, Target: ts.URL + "/base"})
	})
	waitListening(t, port)
	resp, body := get(t, &http.Client{Timeout: 5 * time.Second}, "http://127.0.0.1:"+strconv.Itoa(port)+"/users?id=1")
	if resp.StatusCode != 200 || !strings.Contains(body, `"path":"/base/users?id=1"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	e.waitFlow(byPath("/base/users"))

	e.update(func(d *rules.Data) { d.ReverseProxies[0].Enabled = false })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(e.proxy.ReverseProxyPorts()) > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if len(e.proxy.ReverseProxyPorts()) != 0 {
		t.Fatal("disabled reverse proxy still listens")
	}
}

func socksDial(socksAddr, target string) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	_, _ = c.Write([]byte{5, 1, 0})
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil || greet[1] != 0 {
		_ = c.Close()
		return nil, err
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	_, _ = c.Write(req)
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		_ = c.Close()
		return nil, err
	}
	if reply[1] != 0 {
		_ = c.Close()
		return nil, &net.OpError{Op: "socks", Err: io.ErrUnexpectedEOF}
	}
	return c, nil
}

func TestSocks5(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(echoServer())
	defer ts.Close()
	port := freePort(t)
	e.update(func(d *rules.Data) { d.Socks = rules.Socks{Enabled: true, Port: port} })
	waitListening(t, port)
	if e.proxy.SocksPort() != port {
		t.Fatalf("SOCKS port %d", e.proxy.SocksPort())
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socksDial("127.0.0.1:"+strconv.Itoa(port), addr)
		},
	}}
	resp, body := get(t, c, ts.URL+"/via-socks")
	if resp.StatusCode != 200 || !strings.Contains(body, "/via-socks") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	e.waitFlow(byPath("/via-socks"))

	e.update(func(d *rules.Data) { d.Socks.Enabled = false })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && e.proxy.SocksPort() != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if e.proxy.SocksPort() != 0 {
		t.Fatal("SOCKS still on")
	}
}

func wsEcho(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- RFC 6455 computes the WebSocket accept key with SHA-1.
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	_ = brw.Flush()
	for {
		f, err := readFrame(brw.Reader)
		if err != nil {
			return
		}
		if f.opcode == 0x8 {
			_, _ = c.Write(frame(0x8, f.payload, false))
			return
		}
		_, _ = c.Write(frame(f.opcode, []byte("echo: "+string(f.payload)), false))
	}
}

func frame(opcode byte, payload []byte, masked bool) []byte {
	b := []byte{0x80 | opcode}
	n := len(payload)
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		b = append(b, maskBit|byte(n))
	default:
		b = append(b, maskBit|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	}
	if !masked {
		return append(b, payload...)
	}
	mask := [4]byte{1, 2, 3, 4}
	b = append(b, mask[:]...)
	for i, p := range payload {
		b = append(b, p^mask[i%4])
	}
	return b
}

func TestWebSocket(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(wsEcho))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	c, err := net.Dial("tcp", e.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET http://"+host+"/socket HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	_, _ = c.Write(frame(0x1, []byte("hello"), true))
	got, err := readFrame(br)
	if err != nil || string(got.payload) != "echo: hello" {
		t.Fatalf("echo %q %v", got.payload, err)
	}
	_, _ = c.Write(frame(0x8, []byte{0x03, 0xe8}, true))
	if got, err := readFrame(br); err != nil || got.opcode != 0x8 {
		t.Fatalf("the server's close did not come back: %v %v", got.opcode, err)
	}

	f := e.waitFlow(func(f *flow.Flow) bool {
		return f.IsWebSocket() && f.Response != nil && f.Timing.ResponseEndedAt != nil
	})
	if !strings.HasPrefix(f.URL(), "ws://") {
		t.Fatalf("URL %s", f.URL())
	}
	msgs := f.WebSocketMessageStorage.Messages
	if len(msgs) != 4 || msgs[0].From != "client" || msgs[0].Data != "hello" || msgs[1].From != "server" || msgs[1].Data != "echo: hello" ||
		msgs[2].Type != "close" || msgs[2].CloseCode != 1000 || msgs[3].From != "server" || msgs[3].Type != "close" {
		t.Fatalf("messages %+v", msgs)
	}
}

func TestWebSocketSendIntoLiveSocket(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(wsEcho))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	c, err := net.Dial("tcp", e.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET http://"+host+"/socket HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v", err)
	}
	f := e.waitFlow(func(f *flow.Flow) bool { return f.IsWebSocket() && f.StatusCode() == 101 })
	if !e.proxy.WebSocketOpen(f.UniqueID) {
		t.Fatal("the socket is not open")
	}
	if err := e.proxy.SendWebSocket(f.UniqueID, true, "text", []byte("from ProxyGo")); err != nil {
		t.Fatal(err)
	}
	if got, err := readFrame(br); err != nil || string(got.payload) != "echo: from ProxyGo" {
		t.Fatalf("echo %q %v", got.payload, err)
	}
	if err := e.proxy.SendWebSocket(f.UniqueID, false, "text", []byte("hi client")); err != nil {
		t.Fatal(err)
	}
	if got, err := readFrame(br); err != nil || string(got.payload) != "hi client" || got.raw[1]&0x80 != 0 {
		t.Fatalf("to the client %q %v, masked %v", got.payload, err, got.raw[1]&0x80 != 0)
	}
	_, _ = c.Write(frame(0x8, []byte{0x03, 0xe8}, true))
	f = e.waitFlow(func(f *flow.Flow) bool { return f.IsWebSocket() && f.Timing.ResponseEndedAt != nil })
	var injected int
	for _, m := range f.WebSocketMessageStorage.Messages {
		if m.Injected {
			injected++
		}
	}
	if injected != 2 {
		t.Errorf("messages %+v", f.WebSocketMessageStorage.Messages)
	}
	if err := e.proxy.SendWebSocket(f.UniqueID, true, "text", nil); err != ErrWebSocketClosed {
		t.Errorf("a closed socket: %v", err)
	}
}

func TestOpenWebSocket(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(wsEcho))
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := e.proxy.OpenWebSocket(ctx, Message{URL: "ws" + strings.TrimPrefix(ts.URL, "http") + "/chat"})
	if err != nil {
		t.Fatal(err)
	}
	if f.StatusCode() != 101 || !f.IsWebSocket() {
		t.Fatalf("%s", f.StatusLine())
	}
	if err := e.proxy.SendWebSocket(f.UniqueID, true, "text", []byte("ping?")); err != nil {
		t.Fatal(err)
	}
	e.waitFlow(func(g *flow.Flow) bool {
		if g.UniqueID != f.UniqueID || g.WebSocketMessageStorage == nil {
			return false
		}
		for _, m := range g.WebSocketMessageStorage.Messages {
			if m.From == "server" && m.Data == "echo: ping?" {
				return true
			}
		}
		return false
	})
	e.proxy.CloseWebSocket(f.UniqueID)
	done := e.waitFlow(func(g *flow.Flow) bool { return g.UniqueID == f.UniqueID && g.Timing.ResponseEndedAt != nil })
	if done.Client.Name != "ProxyGo" {
		t.Errorf("client %q", done.Client.Name)
	}

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) }))
	defer plain.Close()
	f, err = e.proxy.OpenWebSocket(ctx, Message{URL: "ws" + strings.TrimPrefix(plain.URL, "http")})
	if err != nil || f.StatusCode() != http.StatusForbidden {
		t.Fatalf("%v %s", err, f.StatusLine())
	}
}

func TestSocks5UDPAssociate(t *testing.T) {
	e := newEnv(t)
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	port := freePort(t)
	e.update(func(d *rules.Data) { d.Socks = rules.Socks{Enabled: true, Port: port} })
	waitListening(t, port)

	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var greet [2]byte
	_, _ = io.ReadFull(c, greet[:])
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("reply %v %v", reply, err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	u, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()
	_ = u.SetDeadline(time.Now().Add(5 * time.Second))
	target := echo.LocalAddr().(*net.UDPAddr)
	msg := []byte{0, 0, 0, 3, 9}
	msg = append(msg, "localhost"...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(target.Port))
	msg = append(msg, "query"...)
	if _, err := u.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	host, gotPort, payload, err := splitSOCKSUDP(buf[:n])
	if err != nil || string(payload) != "echo:query" || gotPort != target.Port || host != "127.0.0.1" {
		t.Fatalf("%q %d %q %v", host, gotPort, payload, err)
	}
	_, _ = u.Write(append([]byte{0, 0, 1}, msg[3:]...))
	_, _ = u.Write(msg)
	if n, err := u.Read(buf); err != nil || !strings.HasSuffix(string(buf[:n]), "echo:query") {
		t.Fatalf("after a fragment: %v", err)
	}
	_ = c.Close()
	time.Sleep(100 * time.Millisecond)
	_, _ = u.Write(msg)
	_ = u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := u.Read(buf); err == nil {
		t.Error("the association outlived its connection")
	}
}

func TestWebSocketScriptHook(t *testing.T) {
	engine := script.New()
	e := newEnv(t, func(o *Options) { o.Scripts = engine })
	ts := httptest.NewServer(http.HandlerFunc(wsEcho))
	defer ts.Close()
	e.update(func(d *rules.Data) {
		d.Scripts = []*rules.ScriptRule{{ID: "s", Enabled: true, Name: "ws", Matcher: rules.Matcher{URL: "*"}, OnRequest: true,
			Script: `function onWebsocket(context, url, request, response, message) { console.log(message.from + ":" + message.data); }`}}
	})
	host := strings.TrimPrefix(ts.URL, "http://")
	c, err := net.Dial("tcp", e.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET http://"+host+"/socket HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(c)
	_, _ = http.ReadResponse(br, nil)
	_, _ = c.Write(frame(0x1, []byte("hello"), true))
	_, _ = readFrame(br)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(engine.Logs()) < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	logs := engine.Logs()
	if len(logs) != 2 || logs[0].Text != "client:hello" || logs[1].Text != "server:echo: hello" {
		t.Errorf("logs %+v", logs)
	}
}
