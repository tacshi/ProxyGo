package wire

import (
	"bytes"
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type fakeConn struct {
	net.Conn
	in *bytes.Reader
}

func (c *fakeConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) { return len(p), nil }

type h2Conn struct{ *fakeConn }

func (h2Conn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: "h2"}
}

func readAll(c net.Conn) {
	buf := make([]byte, 7)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

func TestHTTP1Requests(t *testing.T) {
	raw := "GET /a HTTP/1.1\r\nHost: x\r\nuser-agent: curl\r\nAccept: */*\r\n\r\n" +
		"POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nX-Z: 1\r\n\r\n" +
		"1c\r\nGET /fake HTTP/1.1\r\nA: b\r\n\r\n\r\n0\r\nTrailer: t\r\n\r\n" +
		"PUT /c HTTP/1.1\r\nContent-Length: 30\r\nHost: x\r\nX-B: 1\r\nX-A: 2\r\nX-B: 3\r\n\r\n" +
		"GET /fake HTTP/1.1\r\nA: b\r\n\r\n\r\n" +
		"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n" +
		"\x16\x03\x01 not HTTP\r\n\r\n"
	c := Server(&fakeConn{in: bytes.NewReader([]byte(raw))})
	readAll(c)
	for _, tc := range []struct {
		method, target string
		want           []string
	}{
		{"GET", "/a", []string{"Host", "user-agent", "Accept"}},
		{"POST", "/b", []string{"Host", "Transfer-Encoding", "X-Z"}},
		{"GET", "/fake", nil},
		{"PUT", "/c", []string{"Content-Length", "Host", "X-B", "X-A", "X-B"}},
		{"CONNECT", "h:443", []string{"Host"}},
	} {
		if got := names(RequestHeaders(c, tc.method, tc.target)); !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: %q, want %q", tc.method, tc.target, got, tc.want)
		}
	}
}

func TestHTTP1Responses(t *testing.T) {
	raw := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 50\r\nServer: s\r\nDate: d\r\n\r\n" +
		"HTTP/1.1 404 Not Found\r\nZ: 1\r\ncontent-length: 2\r\nA: 2\r\n\r\nno"
	c := Client(&fakeConn{in: bytes.NewReader([]byte(raw))})
	_, _ = c.Write([]byte("HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET /x HTTP/1.1\r\nHost: x\r\n\r\n"))
	readAll(c)
	if got := names(ResponseHeaders(c, "HEAD", "/", 200)); !slices.Equal(got, []string{"Content-Length", "Server", "Date"}) {
		t.Errorf("HEAD: %q", got)
	}
	if got := names(ResponseHeaders(c, "GET", "/x", 404)); !slices.Equal(got, []string{"Z", "content-length", "A"}) {
		t.Errorf("GET: %q", got)
	}
}

func frames(t *testing.T, preface bool, blocks ...[]hpack.HeaderField) []byte {
	t.Helper()
	var out, block bytes.Buffer
	if preface {
		out.WriteString(clientPreface)
	}
	fr := http2.NewFramer(&out, nil)
	enc := hpack.NewEncoder(&block)
	for i, fields := range blocks {
		block.Reset()
		for _, f := range fields {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		stream := uint32(2*i + 1)
		b := block.Bytes()
		half := len(b) / 2
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: b[:half], PadLength: 3, Priority: http2.PriorityParam{Weight: 9}}); err != nil {
			t.Fatal(err)
		}
		if err := fr.WriteContinuation(stream, true, b[half:]); err != nil {
			t.Fatal(err)
		}
		if err := fr.WriteData(stream, true, []byte("body")); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func fields(kv ...string) []hpack.HeaderField {
	var out []hpack.HeaderField
	for i := 0; i < len(kv); i += 2 {
		out = append(out, hpack.HeaderField{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

func TestHTTP2Requests(t *testing.T) {
	raw := frames(t, true,
		fields(":method", "GET", ":path", "/a", ":authority", "x", "user-agent", "u", "accept", "*/*"),
		fields(":method", "POST", ":path", "/b", ":authority", "x", "accept", "*/*", "user-agent", "u", "x-z", "1"),
	)
	c := Server(h2Conn{&fakeConn{in: bytes.NewReader(raw)}})
	readAll(c)
	if got := names(RequestHeaders(c, "POST", "/b")); !slices.Equal(got, []string{":method", ":path", ":authority", "accept", "user-agent", "x-z"}) {
		t.Errorf("POST: %q", got)
	}
	if got := names(RequestHeaders(c, "GET", "/a")); !slices.Equal(got, []string{":method", ":path", ":authority", "user-agent", "accept"}) {
		t.Errorf("GET: %q", got)
	}
}

func TestHTTP2Responses(t *testing.T) {
	sent := frames(t, true,
		fields(":method", "GET", ":path", "/a", ":authority", "x"),
		fields(":method", "GET", ":path", "/b", ":authority", "x"),
	)
	raw := frames(t, false,
		fields(":status", "200", "server", "s", "content-type", "a"),
		fields(":status", "200", "content-type", "b", "server", "s"),
	)
	c := Client(h2Conn{&fakeConn{in: bytes.NewReader(raw)}})
	_, _ = c.Write(sent)
	readAll(c)
	if got := names(ResponseHeaders(c, "GET", "/b", 200)); !slices.Equal(got, []string{":status", "content-type", "server"}) {
		t.Errorf("/b: %q", got)
	}
	if got := names(ResponseHeaders(c, "GET", "/a", 200)); !slices.Equal(got, []string{":status", "server", "content-type"}) {
		t.Errorf("/a: %q", got)
	}
}

func TestUnwrappedConn(t *testing.T) {
	if RequestHeaders(&fakeConn{}, "GET", "/") != nil || ResponseHeaders(nil, "GET", "/", 200) != nil {
		t.Fatal("an unrecorded connection has an order")
	}
}

func names(fields []Field) []string {
	var out []string
	for _, f := range fields {
		out = append(out, f.Name)
	}
	return out
}

func TestValuesKept(t *testing.T) {
	c := Server(&fakeConn{in: bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive\r\nX-Pad:  spaced \r\n\r\n"))})
	readAll(c)
	got := RequestHeaders(c, "GET", "/")
	want := []Field{{Name: "Host", Value: "a.test"}, {Name: "Connection", Value: "keep-alive"}, {Name: "X-Pad", Value: "spaced"}}
	if !slices.Equal(got, want) {
		t.Fatalf("%q, want %q", got, want)
	}
}

type recordConn struct {
	fakeConn
	out bytes.Buffer
}

func (c *recordConn) Write(p []byte) (int, error) { return c.out.Write(p) }

func TestPlanHead(t *testing.T) {
	under := &recordConn{fakeConn: fakeConn{in: bytes.NewReader(nil)}}
	c := Server(under)
	PlanHead(c, []string{"server", "Content-Type", "x-a", "Set-Cookie", "x-b", "Set-Cookie"})
	for _, p := range []string{"HTTP/1.1 200 OK\r\nContent-Type: a\r\n", "Date: d\r\nServer: s\r\nSet-Cookie: 1\r\nSet-Cookie: 2\r\n", "X-A: 1\r\nX-B: 2\r\n\r\nbody"} {
		if n, err := c.Write([]byte(p)); err != nil || n != len(p) {
			t.Fatalf("write %d %v", n, err)
		}
	}
	want := "HTTP/1.1 200 OK\r\nserver: s\r\nContent-Type: a\r\nx-a: 1\r\nSet-Cookie: 1\r\nx-b: 2\r\nSet-Cookie: 2\r\nDate: d\r\n\r\nbody"
	if got := under.out.String(); got != want {
		t.Fatalf("wrote\n%q\nwant\n%q", got, want)
	}
	_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nB: 1\r\nA: 2\r\n\r\n"))
	if !strings.HasSuffix(under.out.String(), "B: 1\r\nA: 2\r\n\r\n") {
		t.Fatalf("second head changed: %q", under.out.String())
	}
}
