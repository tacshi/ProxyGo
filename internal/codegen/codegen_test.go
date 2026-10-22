package codegen

import (
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"proxygo/internal/flow"
)

func sample() Request {
	return Request{
		Method: "post",
		URL:    "https://api.dev/v1/items?q=it's",
		Header: flow.NewHeader(http.Header{
			"Host":            {"api.dev"},
			"Content-Type":    {"application/json"},
			"Authorization":   {`Bearer "tok"`},
			"Accept-Encoding": {"gzip"},
			"Content-Length":  {"20"},
		}),
		Body: []byte("{\"name\":\"O'Neil\",\n\"tab\":\"\t\"}"),
	}
}

func TestEveryLanguage(t *testing.T) {
	for _, l := range Languages {
		out := l.Generate(sample())
		url := "api.dev/v1/items"
		if l.Name == "Swift (Moya)" {
			url = `"/v1/items"`
		}
		if !strings.Contains(out, url) {
			t.Errorf("%s: no URL:\n%s", l.Name, out)
		}
		record := l.Name == "HAR"
		if !record && (strings.Contains(out, "Content-Length") || strings.Contains(strings.ToLower(out), "\"host\": \"")) {
			t.Errorf("%s: kept a header the client sets:\n%s", l.Name, out)
		}
		if !strings.Contains(out, "Authorization") {
			t.Errorf("%s: dropped a header:\n%s", l.Name, out)
		}
	}
	if Named("nope")(sample()) != Curl(sample()) {
		t.Fatal("unknown language should fall back to cURL")
	}
}

func TestGeneratedCodeParses(t *testing.T) {
	src := Go(sample())
	if _, err := parser.ParseFile(token.NewFileSet(), "main.go", src, 0); err != nil {
		t.Fatalf("Go: %v\n%s", err, src)
	}
	check := func(tool string, args ...string) {
		if _, err := exec.LookPath(tool); err != nil {
			return
		}
		if out, err := exec.Command(tool, args...).CombinedOutput(); err != nil { // #nosec G204 -- the toolchain checks the generated code.
			t.Errorf("%s: %v\n%s", tool, err, out)
		}
	}
	dir := t.TempDir()
	py := filepath.Join(dir, "a.py")
	_ = os.WriteFile(py, []byte(Python(sample())), 0o600)
	check("python3", "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read())", py)
	js := filepath.Join(dir, "a.mjs")
	_ = os.WriteFile(js, []byte(Fetch(sample())), 0o600)
	check("node", "--check", js)
	sh := filepath.Join(dir, "a.sh")
	_ = os.WriteFile(sh, []byte(Curl(sample())+"\n"+HTTPie(sample())), 0o600)
	check("bash", "-n", sh)
	rb := filepath.Join(dir, "a.rb")
	_ = os.WriteFile(rb, []byte(Ruby(sample())), 0o600)
	check("ruby", "-c", rb)
	for name, gen := range map[string]func(Request) string{"node.js": NodeHTTP, "jquery.js": JQuery, "axios.js": Axios} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(gen(sample())), 0o600)
		check("node", "--check", p)
	}
	for name, gen := range map[string]func(Request) string{"urlsession.swift": Swift, "alamofire.swift": Alamofire, "moya.swift": Moya} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(gen(sample())), 0o600)
		check("swiftc", "-parse", p)
	}
	objc := filepath.Join(dir, "a.m")
	_ = os.WriteFile(objc, []byte(ObjC(sample())), 0o600)
	check("clang", "-fsyntax-only", "-fobjc-arc", "-framework", "Foundation", objc)
	if out, err := exec.Command("javac", "-version").CombinedOutput(); err == nil && strings.Contains(string(out), "javac") {
		jdir := filepath.Join(dir, "java")
		_ = os.MkdirAll(jdir, 0o750)
		_ = os.WriteFile(filepath.Join(jdir, "Main.java"), []byte(Java(sample())), 0o600)
		check("javac", "-d", jdir, filepath.Join(jdir, "Main.java"))
	}
	rs := filepath.Join(dir, "a.rs")
	_ = os.WriteFile(rs, []byte(Rust(sample())), 0o600)
	check("rustfmt", "--edition", "2021", "--emit", "stdout", rs)
	dart := filepath.Join(dir, "a.dart")
	_ = os.WriteFile(dart, []byte(Dart(sample())), 0o600)
	check("dart", "format", "--output=none", dart)
	for name, gen := range map[string]func(Request) string{"har": HAR, "postman": Postman} {
		var v any
		if err := json.Unmarshal([]byte(gen(sample())), &v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCurlRunsAgainstItsOwnQuoting(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	cmd := strings.Replace(Curl(sample()), "curl", "printf '%s\\n'", 1)
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput() // #nosec G204 -- bash runs the generated curl command with printf in place of curl.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `{"name":"O'Neil",`) || !strings.Contains(string(out), `Authorization: Bearer "tok"`) {
		t.Fatalf("shell saw:\n%s", out)
	}
}

func TestBinaryBody(t *testing.T) {
	r := Request{Method: "PUT", URL: "http://x.dev/u", Body: []byte{0, 1, 2, 0xff}}
	if !strings.Contains(Curl(r), "--data-binary @body.bin") {
		t.Fatal(Curl(r))
	}
	if strings.Contains(Python(r), "data =") {
		t.Fatal("binary body written as text")
	}
}

func TestOf(t *testing.T) {
	f := flow.New("X")
	f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, FullPath: "https://a.dev/", Header: flow.NewHeader(http.Header{"Accept": {"*/*"}})}
	r := Of(f)
	if r.Method != "GET" || r.URL != "https://a.dev/" || Curl(r) != "curl 'https://a.dev/' \\\n  -H 'Accept: */*'" {
		t.Fatalf("%q", Curl(r))
	}
}

func TestGeneratedCodeRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles and runs programs")
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s %s|%s|%s|%s", r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("X-Note"), b)
	}))
	defer ts.Close()
	body := `{"query":"query GetUser($id: ID!) { user(id: $id) { name } }","note":"#{x} #$y \"q\" it's\ttab\nline ü"}`
	req := Request{
		Method: "PUT",
		URL:    ts.URL + "/v1/items?q=a%20b",
		Header: flow.NewHeader(http.Header{
			"Content-Type":  {"application/json"},
			"Authorization": {`Bearer "tok" $HOME`},
			"X-Note":        {"#{1} it's"},
		}),
		Body: []byte(body),
	}
	want := `PUT /v1/items?q=a%20b|Bearer "tok" $HOME|#{1} it's|` + body
	dir := t.TempDir()
	run := func(lang, tool, file, code string, args ...string) {
		t.Helper()
		if _, err := exec.LookPath(tool); err != nil {
			t.Logf("%s: no %s", lang, tool)
			return
		}
		path := filepath.Join(dir, file)
		if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(tool, append(args, path)...) // #nosec G204 -- the toolchain checks the generated code.
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), want) {
			t.Errorf("%s: %v\n%s\n--- code:\n%s", lang, err, out, code)
		}
	}
	run("cURL", "bash", "curl.sh", Curl(req))
	run("fetch", "node", "fetch.mjs", Fetch(req))
	run("Go", "go", "main.go", Go(req), "run")
	run("Ruby", "ruby", "net.rb", Ruby(req))
	run("Swift", "swift", "main.swift", Swift(req))
}

func TestGeneratedCodeEscapes(t *testing.T) {
	req := Request{Method: "POST", URL: "https://api.dev/$x", Header: flow.NewHeader(http.Header{"X-A": {"$b #{c}"}}), Body: []byte(`{"q":"$id #{d} #@e"}`)}
	if k, _, _ := strings.Cut(Kotlin(req), ".build()"); strings.Contains(strings.ReplaceAll(k, `\$`, ""), "$") {
		t.Errorf("Kotlin leaves a $ to its templates:\n%s", k)
	}
	if r := Ruby(req); strings.Contains(strings.ReplaceAll(r, `\#`, ""), "#{") || strings.Contains(strings.ReplaceAll(r, `\#`, ""), "#@") {
		t.Errorf("Ruby leaves #{ to its interpolation:\n%s", r)
	}
	if _, err := exec.LookPath("node"); err == nil {
		path := filepath.Join(t.TempDir(), "axios.js")
		_ = os.WriteFile(path, []byte(Axios(req)), 0o600)
		if out, err := exec.Command("node", "--check", path).CombinedOutput(); err != nil { // #nosec G204 -- node checks the generated code.
			t.Errorf("axios: %v\n%s", err, out)
		}
		if a := Axios(req); strings.Contains(a, "require(") && !strings.Contains(a, "async") {
			t.Errorf("axios awaits at the top of a CommonJS script:\n%s", a)
		}
	}
}
