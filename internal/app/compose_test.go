package app

import (
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/curl"
	"proxygo/internal/proxy"
)

func TestComposeCurlAndForms(t *testing.T) {
	a, _ := testApp(t)
	cmd, err := curl.Parse(`curl -L --max-time 5 -X POST 'https://api.example.com/items' -H 'X-A: 1' -F name=ProxyGo -F 'note=hi there'`)
	if err != nil {
		t.Fatal(err)
	}
	a.composeCurl(cmd)
	st := &a.compose
	e := st.edit
	if !st.follow || st.timeout != 5 || e.method != "POST" || e.url != "https://api.example.com/items" {
		t.Fatalf("options %+v %q %q", st, e.method, e.url)
	}
	if e.kind != bodyMultipart || len(e.parts) != 2 || e.parts[1].value != "hi there" {
		t.Fatalf("parts %+v", e.parts)
	}
	e.addPart(partRow{on: true, name: "f", file: true, fileName: "a.txt", contentType: "text/plain", data: []byte("file body")})
	m := e.message()
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/form-data" {
		t.Fatalf("content type %q", m.Header.Get("Content-Type"))
	}
	r := multipart.NewReader(strings.NewReader(string(m.Body)), params["boundary"])
	var got []string
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		got = append(got, p.FormName()+"|"+p.FileName()+"|"+string(b))
	}
	if strings.Join(got, ",") != "name||ProxyGo,note||hi there,f|a.txt|file body" {
		t.Fatalf("parts sent %q", got)
	}

	e.setKind(bodyForm)
	m = e.message()
	if string(m.Body) != "name=ProxyGo&note=hi+there&f=a.txt" || m.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("form %q %q", m.Body, m.Header.Get("Content-Type"))
	}

	e2 := newComposeEditor(proxy.Message{Method: "POST", URL: "https://x", Header: m.Header, Body: m.Body})
	if e2.kind != bodyForm || len(e2.parts) != 3 {
		t.Fatalf("reopened %d %+v", e2.kind, e2.parts)
	}
	if b := newMessageEditor(proxy.Message{Header: m.Header, Body: m.Body}, false); b.kind != bodyText || string(b.message().Body) != string(m.Body) {
		t.Fatalf("breakpoint body %d", b.kind)
	}
}

func TestComposeFollowsRedirectsWhenAsked(t *testing.T) {
	a, _ := testApp(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusFound)
			return
		}
		io.WriteString(w, "arrived")
	}))
	t.Cleanup(ts.Close)
	a.proxy = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Rules: a.rules, Sink: a.store, Certs: a.certs})
	if err := a.proxy.Start(); err != nil {
		t.Fatal(err)
	}
	tt := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, "compose") }, 1100, 720)
	for _, follow := range []bool{false, true} {
		a.composeFrom(nil)
		a.compose.edit.url = ts.URL + "/old"
		a.compose.follow = follow
		a.compose.result = ""
		tt.Frame()
		mustClick(t, tt, "Send")
		deadline := time.Now().Add(5 * time.Second)
		for a.compose.result == "" && a.compose.err == "" && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
			tt.Frame()
		}
		f, _ := a.store.Lookup(a.compose.result)
		if f == nil {
			t.Fatalf("follow %v: %q", follow, a.compose.err)
		}
		want := map[bool]int{false: 302, true: 200}[follow]
		if f.StatusCode() != want {
			t.Fatalf("follow %v: status %d", follow, f.StatusCode())
		}
	}
	tt.Frame()
	for _, s := range []string{"Import from cURL…", "Follow Redirects", "Timeout"} {
		if !tt.HasText(s) {
			t.Fatalf("no %q", s)
		}
	}
}
