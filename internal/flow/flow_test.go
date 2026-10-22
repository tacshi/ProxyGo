package flow

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func sample() *Flow {
	f := New("ABCD1234")
	start, end := 100.0, 100.25
	f.Timing = Timing{RequestStartedAt: &start, ResponseEndedAt: &end}
	f.Request = &Request{
		Scheme: "https", Host: "api.example.com", Port: 443, IsSSL: true,
		FullPath: "https://api.example.com/v1/users?id=7&name=a%20b",
		URI:      "/v1/users?id=7&name=a%20b",
		Method:   Method{Name: "POST"},
		Version:  Version{Major: 2},
		Header: NewHeader(http.Header{
			"Content-Type": {"application/json"},
			"Cookie":       {"session=abc; theme=dark"},
		}),
		BodyData: Blob(`{"query":"query GetUser($id: ID!) { user(id: $id) { name } }","variables":{"id":7}}`),
	}
	f.Response = &Response{
		Status:  &Status{Code: 201, Phrase: "Created"},
		Version: Version{Major: 2},
		Header: NewHeader(http.Header{
			"Content-Type": {"application/json; charset=utf-8"},
			"Set-Cookie":   {"token=xyz; Path=/; HttpOnly"},
		}),
		BodyData: Blob(`{"ok":true}`),
	}
	f.ToolMetadata = map[string]any{"mapLocal": map[string]any{"name": "x"}}
	return f
}

func TestCloneSharesNothing(t *testing.T) {
	f := sample()
	c := f.Clone()
	c.Request.BodyData[0] = 'X'
	c.Request.Header.Entries[0].Value = "changed"
	c.Response.Status.Code = 500
	c.ToolMetadata.(map[string]any)["mapLocal"].(map[string]any)["name"] = "y"
	*c.Timing.RequestStartedAt = 0
	if f.Request.BodyData[0] != '{' || f.Request.Header.Entries[0].Value == "changed" {
		t.Fatal("request shared with clone")
	}
	if f.Response.Status.Code != 201 || *f.Timing.RequestStartedAt != 100 {
		t.Fatal("response or timing shared with clone")
	}
	if f.ToolMetadata.(map[string]any)["mapLocal"].(map[string]any)["name"] != "x" {
		t.Fatal("tool metadata shared with clone")
	}
	a, _ := json.Marshal(f)
	b, _ := json.Marshal(f.Clone())
	if !bytes.Equal(a, b) {
		t.Fatalf("clone differs:\n%s\n%s", a, b)
	}
}

func TestUserFieldsRoundTrip(t *testing.T) {
	f := sample()
	f.Comment, f.Highlight, f.Strikethrough, f.Saved = "check this", "red", true, true
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Flow
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Comment != "check this" || back.Highlight != "red" || !back.Strikethrough || !back.Saved {
		t.Fatalf("user fields lost: %+v", back)
	}
	plain, _ := json.Marshal(New("X"))
	for _, key := range []string{"comment", "highlight", "strikethrough", "saved"} {
		if bytes.Contains(plain, []byte(`"`+key+`"`)) {
			t.Errorf("%s written for a flow without it", key)
		}
	}
}

func TestGraphQLOperation(t *testing.T) {
	f := sample()
	if got := f.GraphQLOperation(); got != "GetUser" {
		t.Fatalf("operation %q", got)
	}
	if f.ContentCategory() != "GraphQL" {
		t.Fatalf("category %q", f.ContentCategory())
	}
	f.Request.BodyData = Blob(`{"operationName":"Named","query":"mutation X { a }"}`)
	if got := f.GraphQLOperation(); got != "Named" {
		t.Fatalf("operationName %q", got)
	}
	f.Request.BodyData = Blob(`[{"query":"{ viewer { id } }"}]`)
	if got := f.GraphQLOperation(); got != "query" {
		t.Fatalf("anonymous batch %q", got)
	}
	f.Request.BodyData = Blob(`{"name":"not graphql"}`)
	if got := f.GraphQLOperation(); got != "" {
		t.Fatalf("plain JSON %q", got)
	}
	g := New("G")
	g.Request = &Request{Method: Method{Name: "GET"}, FullPath: "https://x.dev/graphql?query=query%20Feed%20%7B%20a%20%7D"}
	if got := g.GraphQLOperation(); got != "Feed" {
		t.Fatalf("GET operation %q", got)
	}
}

func TestCategories(t *testing.T) {
	cases := []struct {
		ct, path, want string
	}{
		{"application/json", "/a", "JSON"},
		{"text/html; charset=utf-8", "/", "Document"},
		{"application/javascript", "/app", "JS"},
		{"", "/app.js?v=1", "JS"},
		{"text/css", "/s", "CSS"},
		{"image/png", "/i", "Media"},
		{"font/woff2", "/f", "Media"},
		{"application/xml", "/x", "XML"},
		{"application/x-www-form-urlencoded", "/f", "Form"},
		{"application/octet-stream", "/b", "Other"},
	}
	for _, tc := range cases {
		f := New("C")
		f.Request = &Request{Method: Method{Name: "GET"}, Scheme: "https", FullPath: "https://h" + tc.path}
		f.Response = &Response{Status: &Status{Code: 200}, Header: NewHeader(http.Header{"Content-Type": {tc.ct}})}
		if tc.ct == "" {
			f.Response.Header = Header{}
		}
		if got := f.ContentCategory(); got != tc.want {
			t.Errorf("%s %s: %s, want %s", tc.ct, tc.path, got, tc.want)
		}
	}
}

func TestVersionCookiesQuery(t *testing.T) {
	f := sample()
	if f.HTTPVersionLabel() != "h2" {
		t.Fatalf("version %s", f.HTTPVersionLabel())
	}
	if cs := f.Cookies(); len(cs) != 2 || cs[0].Name != "session" || cs[1].Value != "dark" {
		t.Fatalf("cookies %v", cs)
	}
	if cs := f.SetCookies(); len(cs) != 1 || cs[0].Name != "token" || !cs[0].HttpOnly {
		t.Fatalf("set-cookies %v", cs)
	}
	q := f.QueryItems()
	if len(q) != 2 || q[1] != [2]string{"name", "a b"} {
		t.Fatalf("query %v", q)
	}
	if f.StatusLine() != "201 Created" {
		t.Fatalf("status line %q", f.StatusLine())
	}
}

func TestErrorFlow(t *testing.T) {
	f := sample()
	f.Response = &Response{Status: &Status{Code: 999}, Error: ResponseError{"couldNotConnectToServer": map[string]any{"message": "dial tcp: refused"}}}
	if !f.IsError() || f.ErrorText() != "dial tcp: refused" {
		t.Fatalf("error %q", f.ErrorText())
	}
	if f.StatusLine() != "Error: dial tcp: refused" {
		t.Fatalf("status line %q", f.StatusLine())
	}
}

func TestDecodeBodies(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte("hello gzip"))
	_ = w.Close()
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	_, _ = bw.Write([]byte("hello brotli"))
	_ = bw.Close()
	zw, _ := zstd.NewWriter(nil)
	zs := zw.EncodeAll([]byte("hello zstd"), nil)
	for enc, data := range map[string][]byte{"gzip": gz.Bytes(), "br": br.Bytes(), "zstd": zs} {
		f := New("D")
		f.Response = &Response{Status: &Status{Code: 200}, Header: NewHeader(http.Header{"Content-Encoding": {enc}}), BodyData: data}
		if got := string(f.DecodedResponseBody()); got != "hello "+map[string]string{"gzip": "gzip", "br": "brotli", "zstd": "zstd"}[enc] {
			t.Errorf("%s: %q", enc, got)
		}
	}
}

func TestSizesIncludeHeaders(t *testing.T) {
	f := sample()
	body := len(f.Request.BodyData)
	if f.RequestSize() <= body {
		t.Fatalf("request size %d not above body %d", f.RequestSize(), body)
	}
	if f.ResponseSize() <= len(f.Response.BodyData) {
		t.Fatalf("response size %d", f.ResponseSize())
	}
	if f.Duration().Milliseconds() != 250 {
		t.Fatalf("duration %v", f.Duration())
	}
}

func TestBodySizes(t *testing.T) {
	f := sample()
	if got := f.RequestBodySize(); got != len(f.Request.BodyData) {
		t.Errorf("request body size %d, want %d", got, len(f.Request.BodyData))
	}
	if got := f.ResponseBodySize(); got != len(f.Response.BodyData) {
		t.Errorf("response body size %d, want %d", got, len(f.Response.BodyData))
	}
	get := New("G")
	get.Request = &Request{Header: NewHeader(http.Header{"Accept": {"*/*"}})}
	if get.RequestBodySize() != 0 || get.ResponseBodySize() != 0 {
		t.Errorf("bodiless sizes %d, %d", get.RequestBodySize(), get.ResponseBodySize())
	}
}

func TestNewHeaderOrdered(t *testing.T) {
	h := http.Header{"Set-Cookie": {"a=1", "b=2"}, "Content-Type": {"text/plain"}, "Date": {"d"}, "X-Extra": {"e"}}
	sent := []SentHeader{{Name: "set-cookie", Value: "a=1"}, {Name: "Content-Type", Value: "text/plain"}, {Name: "Connection", Value: "keep-alive"}, {Name: "set-cookie", Value: "b=2"}, {Name: "Date", Value: "d"}}
	got := NewHeaderOrdered(h, sent)
	var lines []string
	for _, e := range got.Entries {
		lines = append(lines, e.Key.Name+": "+e.Value)
	}
	want := []string{"set-cookie: a=1", "Content-Type: text/plain", "Connection: keep-alive", "set-cookie: b=2", "Date: d", "X-Extra: e"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if got.Get("Set-Cookie") != "a=1" {
		t.Fatal("lookups ignore the case")
	}
	if len(NewHeaderOrdered(h, nil).Entries) != 5 {
		t.Fatal("no order keeps every header")
	}
	h2 := NewHeaderOrdered(http.Header{"Accept": {"*/*"}}, []SentHeader{{Name: ":method", Value: "GET"}, {Name: ":authority", Value: "a.test"}, {Name: "accept", Value: "*/*"}})
	if h2.Get(":authority") != "a.test" || len(h2.Entries) != 3 {
		t.Fatalf("h2 headers %+v", h2.Entries)
	}
	if out := h2.HTTP(); len(out) != 1 || out.Get("Accept") != "*/*" {
		t.Fatalf("sent %v", out)
	}
}
