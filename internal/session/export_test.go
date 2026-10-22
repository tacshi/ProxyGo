package session

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"proxygo/internal/flow"
)

func TestWritePostman(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	flows := sampleFlows()
	form := flow.New("FORM")
	form.Request = &flow.Request{Scheme: "https", Host: "api.dev", Port: 443, FullPath: "https://api.dev/login", URI: "/login", Method: flow.Method{Name: "POST"},
		Header: flow.NewHeader(http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Content-Length": {"9"}}), BodyData: flow.Blob("a=1&b=x+y")}
	tunnel := flow.New("TUN")
	tunnel.Request = &flow.Request{Host: "x.dev", FullPath: "https://x.dev:443", Method: flow.Method{Name: "CONNECT"}}
	if err := WritePostman(path, "Test", append(flows, form, tunnel)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var c struct {
		Info struct{ Name, Schema string }
		Item []struct {
			Name    string
			Request struct {
				Method string
				Header []struct{ Key, Value string }
				Body   *struct {
					Mode       string
					Raw        string
					URLEncoded []struct{ Key, Value string }
				}
				URL struct {
					Raw   string
					Host  []string
					Path  []string
					Query []struct{ Key, Value string }
				}
			}
			Response []struct {
				Code int
				Body string
			}
		}
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.Info.Name != "Test" || !strings.Contains(c.Info.Schema, "v2.1.0") || len(c.Item) != 4 {
		t.Fatalf("%+v", c)
	}
	post := c.Item[1]
	if post.Request.Method != "POST" || post.Request.Body.Mode != "raw" || post.Request.Body.Raw != `{"name":"a"}` ||
		strings.Join(post.Request.URL.Host, ".") != "api.dev" || post.Request.URL.Query[0].Key != "page" {
		t.Errorf("%+v", post.Request)
	}
	if len(post.Response) != 1 || post.Response[0].Code != 201 || post.Response[0].Body != `{"id":1}` {
		t.Errorf("example %+v", post.Response)
	}
	if f := c.Item[3].Request; f.Body.Mode != "urlencoded" || f.Body.URLEncoded[1].Value != "x y" {
		t.Errorf("form %+v", f.Body)
	}
	for _, h := range c.Item[3].Request.Header {
		if h.Key == "Content-Length" {
			t.Error("Postman computes Content-Length")
		}
	}
}

func TestWriteOpenAPI(t *testing.T) {
	mk := func(method, rawURL string, status int, reqBody, respBody string) *flow.Flow {
		f := flow.New(flow.NewUniqueID())
		f.Request = &flow.Request{FullPath: rawURL, Method: flow.Method{Name: method}, Header: flow.NewHeader(http.Header{"Content-Type": {"application/json"}}), BodyData: flow.Blob(reqBody)}
		f.Response = &flow.Response{Status: &flow.Status{Code: status}, Header: flow.NewHeader(http.Header{"Content-Type": {"application/json; charset=utf-8"}}), BodyData: flow.Blob(respBody)}
		return f
	}
	flows := []*flow.Flow{
		mk("GET", "https://api.dev/users/1?expand=true", 200, "", `{"id":1,"name":"Ada","tags":["x"],"manager":null}`),
		mk("GET", "https://api.dev/users/2", 200, "", `{"id":2,"name":"Linus","score":1.5}`),
		mk("GET", "https://api.dev/users/3", 404, "", `{"error":"no"}`),
		mk("POST", "https://api.dev/users", 201, `{"name":"Grace"}`, `{"id":3}`),
	}
	path := filepath.Join(t.TempDir(), "api.yaml")
	if err := WriteOpenAPI(path, "API", flows); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), "openapi: 3.0.3\n") {
		t.Errorf("keys keep their order:\n%s", b)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	if len(paths) != 2 || paths["/users/{id}"] == nil || paths["/users"] == nil {
		t.Fatalf("paths %v", paths)
	}
	item := paths["/users/{id}"].(map[string]any)
	get := item["get"].(map[string]any)
	resp := get["responses"].(map[string]any)
	if resp["200"] == nil || resp["404"] == nil {
		t.Errorf("responses %v", resp)
	}
	sch := resp["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	props := sch["properties"].(map[string]any)
	if props["id"].(map[string]any)["type"] != "integer" || props["score"].(map[string]any)["type"] != "number" ||
		props["tags"].(map[string]any)["items"].(map[string]any)["type"] != "string" || props["manager"].(map[string]any)["nullable"] != true {
		t.Errorf("schema %v", sch)
	}
	if req := sch["required"].([]any); len(req) != 2 {
		t.Errorf("required: in every sample, %v", req)
	}
	params := get["parameters"].([]any)
	if q := params[0].(map[string]any); q["name"] != "expand" || q["required"] != nil {
		t.Errorf("query %v", q)
	}
	if p := item["parameters"].([]any)[0].(map[string]any); p["in"] != "path" || p["schema"].(map[string]any)["type"] != "integer" {
		t.Errorf("path parameter %v", p)
	}
	if doc["servers"].([]any)[0].(map[string]any)["url"] != "https://api.dev" {
		t.Errorf("servers %v", doc["servers"])
	}

	html := filepath.Join(t.TempDir(), "api.html")
	if err := WriteOpenAPIHTML(html, "API <x>", flows); err != nil {
		t.Fatal(err)
	}
	page, _ := os.ReadFile(html)
	if !strings.Contains(string(page), `"openapi":"3.0.3"`) || !strings.Contains(string(page), "API &lt;x&gt;") || !strings.Contains(string(page), "swagger-ui-bundle.js") {
		t.Errorf("page:\n%s", page)
	}
}

func TestRawHTTP(t *testing.T) {
	f := sampleFlows()[1]
	f.Request.Header.Add("Content-Encoding", "identity")
	raw := string(RawHTTP(f))
	want := []string{"POST /users?page=2 HTTP/1.1\r\n", "Host: api.dev\r\n", "Content-Length: 12\r\n\r\n{\"name\":\"a\"}", "HTTP/1.1 201 Created\r\n", "Content-Length: 8\r\n\r\n{\"id\":1}"}
	for _, w := range want {
		if !strings.Contains(raw, w) {
			t.Errorf("missing %q in\n%s", w, raw)
		}
	}
	if strings.Contains(raw, "Content-Encoding") {
		t.Error("the body is written decoded")
	}
	path := filepath.Join(t.TempDir(), "raw.txt")
	if err := WriteRaw(path, sampleFlows()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), "### ") != 3 {
		t.Errorf("raw export:\n%s", b)
	}
}

func TestReadCharlesSession(t *testing.T) {
	orig := CharlesApp
	defer func() { CharlesApp = orig }()
	CharlesApp = func() string { return "" }
	if _, err := Open(filepath.Join(t.TempDir(), "s.chls")); err != ErrNoCharles {
		t.Errorf("without Charles: %v", err)
	}

	app := filepath.Join(t.TempDir(), "Charles.app")
	bin := filepath.Join(app, "Contents", "MacOS")
	os.MkdirAll(bin, 0o755)
	har := filepath.Join(t.TempDir(), "fixture.har")
	if err := WriteHAR(har, sampleFlows()); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n[ \"$1\" = convert ] || exit 2\ncp '" + har + "' \"$3\"\n"
	os.WriteFile(filepath.Join(bin, "Charles"), []byte(script), 0o755)
	CharlesApp = func() string { return app }
	b, err := Open(filepath.Join(t.TempDir(), "s.chls"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Flows) != 3 || b.Flows[0].Client.Name != "Charles" {
		t.Errorf("%d flows", len(b.Flows))
	}
	os.WriteFile(filepath.Join(bin, "Charles"), []byte("#!/bin/sh\necho 'bad file' >&2\nexit 1\n"), 0o755)
	if _, err := Open(filepath.Join(t.TempDir(), "s.chlsx")); err == nil || !strings.Contains(err.Error(), "bad file") {
		t.Errorf("a failed conversion: %v", err)
	}
}
