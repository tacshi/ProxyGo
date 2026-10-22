package app

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

func TestPrettyText(t *testing.T) {
	for _, c := range []struct {
		name, ct, body, want string
	}{
		{"json", "application/json", `{"a":[1,2]}`, "{\n  \"a\": [\n    1,\n    2\n  ]\n}"},
		{"xml", "application/xml", `<?xml version="1.0"?><rss><channel><title>Feed</title><item><title>One &amp; two</title></item><empty/></channel></rss>`,
			"<?xml version=\"1.0\"?>\n<rss>\n  <channel>\n    <title>Feed</title>\n    <item>\n      <title>One &amp; two</title>\n    </item>\n    <empty></empty>\n  </channel>\n</rss>"},
		{"prefixes and attributes", "text/xml", `<s:Envelope xmlns:s="urn:x"><s:Body a="1 &lt; 2"><!-- c --></s:Body></s:Envelope>`,
			"<s:Envelope xmlns:s=\"urn:x\">\n  <s:Body a=\"1 &lt; 2\">\n    <!-- c -->\n  </s:Body>\n</s:Envelope>"},
		{"broken xml stays", "application/xml", `<a><b></a>`, `<a><b></a>`},
		{"plain text stays", "text/plain", `<a><b/></a>`, `<a><b/></a>`},
	} {
		if got := prettyText([]byte(c.body), c.ct); got != c.want {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

func TestProtobufRuleDecodesOctetStream(t *testing.T) {
	a, tt, _ := loaded(t)
	proto := filepath.Join(t.TempDir(), "user.proto")
	if err := os.WriteFile(proto, []byte("syntax = \"proto3\";\npackage demo;\nmessage User { int32 id = 1; string name = 2; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.schemas.Import(proto); err != nil {
		t.Fatal(err)
	}
	f := fixtures()[0]
	f.UniqueID = "PB1"
	f.Request.FullPath, f.Request.URI = "https://api.example.com/user.bin", "/user.bin"
	f.Response.Header = flow.NewHeader(http.Header{"Content-Type": {"application/octet-stream"}})
	f.Response.BodyData = []byte{0x08, 7, 0x12, 3, 'A', 'd', 'a'}
	a.store.Upsert(f)
	a.rules.Update(func(d *rules.Data) {
		d.Protobuf = []*rules.ProtobufRule{{ID: "r", Enabled: true, Matcher: rules.Matcher{URL: "https://api.example.com/user.bin"}, ResponseType: "demo.User"}}
	})
	a.selectFlow("PB1")
	a.respTabName = "Body"
	tt.Frame()
	if !tt.HasText("Message type") || !tt.HasText("demo.User") {
		t.Fatalf("protobuf body: %v", tt.Texts())
	}
	if text, _ := a.protobufText(bodySource{f: f, response: true}, f.Response.BodyData, "application/octet-stream"); !strings.Contains(text, `"name": "Ada"`) {
		t.Fatalf("decoded: %s", text)
	}
}

func TestJSONFilterThatDoesNotFit(t *testing.T) {
	a, tt, _ := loaded(t)
	a.selectFlow("A1")
	a.respTabName = "Body"
	a.jsonQueryOf("res").expr = ".items[].sku"
	tt.Frame()
	if !slices.ContainsFunc(tt.Texts(), func(s string) bool { return strings.HasPrefix(s, "The filter does not fit this body") }) {
		t.Fatalf("no warning: %v", tt.Texts())
	}
	shown := false
	for k := range a.viewers {
		if strings.HasPrefix(k, "A1:res:") && strings.HasSuffix(k, ":Pretty") {
			shown = true
		}
	}
	if !shown {
		t.Fatal("the body is not shown under the warning")
	}
	if a.jsonQueryOf("composeres").expr != "" {
		t.Fatal("Compose shares the inspector's filter")
	}
}

func TestPrettyHTML(t *testing.T) {
	in := `<!doctype html><html lang=en><head><meta charset=utf-8><title>Example Domain</title><style>body{margin:0}</style></head><body><div><p>Hello &amp; welcome</p><br><a href="/x">Go</a></div><script src=/s.js></script></body></html>`
	want := `<!doctype html>
<html lang=en>
  <head>
    <meta charset=utf-8>
    <title>Example Domain</title>
    <style>body{margin:0}</style>
  </head>
  <body>
    <div>
      <p>Hello &amp; welcome</p>
      <br>
      <a href="/x">Go</a>
    </div>
    <script src=/s.js></script>
  </body>
</html>`
	if got := prettyText([]byte(in), "text/html; charset=utf-8"); got != want {
		t.Errorf("prettyText(html) =\n%s\nwant\n%s", got, want)
	}
}

func TestGraphQLText(t *testing.T) {
	body := `{"query":"query GetUser($id: ID!) { user(id: $id) { name } }","operationName":"GetUser","variables":{"id":"1"}}`
	got := graphQLText([]byte(body))
	want := "# Query\nquery GetUser($id: ID!) {\n  user(id: $id) {\n    name\n  }\n}\n\n# operationName\n\"GetUser\"\n\n# variables\n{\n  \"id\": \"1\"\n}"
	if got != want {
		t.Fatalf("graphQLText =\n%s\nwant\n%s", got, want)
	}
}

func TestPrettyGraphQL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"query GetUser($id: ID!) { user(id: $id) { name email } }",
			"query GetUser($id: ID!) {\n  user(id: $id) {\n    name\n    email\n  }\n}"},
		{`{ search(q: "a b, c") { ... on User { id } total @include(if: $x) } }`,
			"{\n  search(q: \"a b, c\") {\n    ... on User {\n      id\n    }\n    total @include(if: $x)\n  }\n}"},
		{"mutation { add(input: {name: \"x\"}) { id, alias: name } }",
			"mutation {\n  add(input: {name: \"x\"}) {\n    id\n    alias: name\n  }\n}"},
	} {
		if got := prettyGraphQL(tc.in); got != tc.want {
			t.Errorf("prettyGraphQL(%q) =\n%s\nwant\n%s", tc.in, got, tc.want)
		}
	}
}
