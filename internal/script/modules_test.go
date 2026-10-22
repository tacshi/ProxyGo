package script

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

func runScript(t *testing.T, e *Engine, src string) (string, []LogLine) {
	t.Helper()
	req := request()
	_, err := e.RunRequest([]*rules.ScriptRule{rule(src)}, flow.New("F"), req)
	if err != nil {
		t.Fatalf("%v\n%s", err, src)
	}
	return req.Comment, e.Logs()
}

func TestRequire(t *testing.T) {
	root := t.TempDir()
	e := New()
	e.SetRoot(root)
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		_ = os.WriteFile(p, []byte(content), 0o600)
	}
	write("users/token.json", `{"token":"abc"}`)
	write("users/greet.js", `const util = require("./util.js"); exports.greet = (n) => util.prefix + n;`)
	write("users/util.js", `module.exports = { prefix: "hi " };`)
	write("libs/math.js", `exports.double = (n) => n * 2;`)
	write("node_modules/dayjs-like/package.json", `{"name":"dayjs-like","main":"lib/main.js"}`)
	write("node_modules/dayjs-like/lib/main.js", `module.exports = function () { return "today"; };`)
	write("node_modules/esm-only/package.json", `{"type":"module","main":"index.js"}`)
	write("node_modules/esm-only/index.js", `export default 1;`)
	write("users/esm.js", `export const x = 1;`)
	_ = os.WriteFile(filepath.Join(t.TempDir(), "secret.js"), []byte("exports.s = 1"), 0o600)

	comment, _ := runScript(t, e, `function onRequest(c, u, request) {
		const { token } = require("@users/token.json");
		const { greet } = require("@users/greet.js");
		const { double } = require("@libs/math.js");
		const day = require("dayjs-like");
		const { md5 } = require("@addons/MD5.js");
		request.comment = [token, greet("ada"), double(21), day(), md5("a"), require("@users/token.json") === require("@users/token.json")].join("|");
		return request;
	}`)
	if comment != "abc|hi ada|42|today|0cc175b9c0f1b6a831c399e269772661|true" {
		t.Errorf("comment %q", comment)
	}

	for name, want := range map[string]string{
		"fs":                      "Node.js's own module",
		"@users/../../etc/passwd": "outside the scripts folder",
		"../../escape.js":         "outside the scripts folder",
		"esm-only":                "ES module",
		"@users/esm.js":           "ES modules",
		"left-pad":                "npm install",
		"@addons/Nope.js":         "no addon",
		"@users/missing.js":       "cannot find",
		"./a/../../../b.js":       "outside the scripts folder",
	} {
		req := request()
		_, err := e.RunRequest([]*rules.ScriptRule{rule(`function onRequest(c, u, r) { require(` + quoteJS(name) + `); return r; }`)}, flow.New("F"), req)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("require(%q): %v, want %q", name, err, want)
		}
	}
}

func quoteJS(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

func TestBuiltinAddons(t *testing.T) {
	e := New()
	cases := map[string]string{
		`require("@addons/Base64.js").base64Encode("héllo")`:      "aMOpbGxv",
		`require("@addons/Base64.js").base64Decode("aMOpbGxv")`:   "héllo",
		`require("@addons/Base64.js").btoa("hi")`:                 "aGk=",
		`require("@addons/SHA1.js").sha1("a")`:                    "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
		`require("@addons/SHA256.js").sha256("a")`:                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		`require("@addons/SHA512.js").sha512("a").slice(0, 16)`:   "1f40fc92da241694",
		`require("@addons/CryptoJS.js").HmacSHA256("msg", "key")`: "2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628",
		`(function(){ const c = require("@addons/CryptoJS.js"); return c.decryptAES(c.encryptAES("secret text", "pw"), "pw"); })()`: "secret text",
		`require("@addons/CryptoJS.js").decryptAES("U2FsdGVkX18ZUVvShFSES21qHsQEqZXMxQ9zgHy+bu0=", "Secret Passphrase")`:            "Message",
		`(function(){ const p = require("@addons/Pako.js"); return p.ungzip(p.gzip("zip me")) + p.inflate(p.deflate("!")); })()`:    "zip me!",
		`require("@addons/JWTDecode.js").jwtDecode("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZGEifQ.c2ln").payload.sub`:                     "ada",
		`require("@addons/FormatJSON.js").formatJSON('{"a":1}')`:                                                                    "{\n  \"a\": 1\n}",
		`require("@addons/MinifyJSON.js").minifyJSON('{ "a" : 1 }')`:                                                                `{"a":1}`,
		`String(require("@addons/JSONValidator.js").validateJSON("{"))`:                                                             "false",
		`require("@addons/MinifyXML.js").minifiXML("<a>\n  <b>x</b>\n</a>")`:                                                        "<a><b>x</b></a>",
		`require("@addons/FormatXML.js").formatXML("<a><b>x</b></a>")`:                                                              "<a>\n  <b>x</b>\n</a>",
		`require("@addons/MinifyCSS.js").minifyCSS("a:hover { color : red ; } /* c */")`:                                            "a:hover{color:red}",
		`require("@addons/FormatCSS.js").formatCSS("a:hover{color:red;margin:0}")`:                                                  "a:hover {\n  color: red;\n  margin: 0;\n}\n",
		`require("@addons/CamelCase.js").camelCase("Foo bar_bazQux")`:                                                               "fooBarBazQux",
		`require("@addons/SnakeCase.js").snakeCase("fooBar Baz")`:                                                                   "foo_bar_baz",
		`require("@addons/KebabCase.js").kebabCase("fooBar Baz")`:                                                                   "foo-bar-baz",
		`require("@addons/StartCase.js").startCase("foo_barBaz")`:                                                                   "Foo Bar Baz",
		`require("@addons/Hex2rgb.js").hexToRGB("#ff8800")`:                                                                         "255,136,0",
		`require("@addons/JsonToQuery.js").jsonToQuery({a: 1, b: {c: "x y"}})`:                                                      "a=1&b%5Bc%5D=x%20y",
		`JSON.stringify(require("@addons/QueryToJson.js").queryToJSON("?a=1&a=2&b=x+y"))`:                                           `{"a":["1","2"],"b":"x y"}`,
		`String(require("@addons/DateToTimestamp.js").dateToTimestamp("2020-01-01T00:00:00Z"))`:                                     "1577836800000",
		`require("@addons/DateToUTC.js").dateToUTC(0)`:                                                                              "Thu, 01 Jan 1970 00:00:00 GMT",
		`require("@addons/UUID.js").uuidv4().length + ""`:                                                                           "36",
		`require("@addons/HelloWorld.js").sayHello("Go")`:                                                                           "Hello, Go!",
		`require("@addons/EncodeURI.js").encodeURI("a b")`:                                                                          "a%20b",
		`require("@addons/DecodeURI.js").decodeURI("a%20b")`:                                                                        "a b",
		`require("@addons/BeautifyJSON.js").beautifyJSON({a: [1]})`:                                                                 "{\n  \"a\": [\n    1\n  ]\n}",
		`require("@addons/UglifyJSON.js").uglifyJSON('{ "a": 1 }')`:                                                                 `{"a":1}`,
	}
	for expr, want := range cases {
		comment, _ := runScript(t, e, `function onRequest(c, u, r) { r.comment = `+expr+`; return r; }`)
		if comment != want {
			t.Errorf("%s = %q, want %q", expr, comment, want)
		}
	}
	if len(Addons()) < 30 {
		t.Errorf("addons %v", Addons())
	}
}

func TestEnvironment(t *testing.T) {
	orig := loadEnv
	defer func() { loadEnv = orig }()
	loads := 0
	loadEnv = func() map[string]string {
		loads++
		return map[string]string{"API_TOKEN": "t" + string(rune('0'+loads)), "not-an-identifier": "x"}
	}
	e := New()
	src := `function onRequest(c, u, r) { r.comment = typeof $API_TOKEN === "undefined" ? "none" : $API_TOKEN; return r; }`
	if comment, _ := runScript(t, e, src); comment != "none" {
		t.Errorf("without permission: %q", comment)
	}
	e.SetAllowEnv(true)
	if comment, _ := runScript(t, e, src); comment != "t1" {
		t.Errorf("allowed: %q", comment)
	}
	if comment, _ := runScript(t, e, `function onRequest(c, u, r) { _reloadEnv(); r.comment = $API_TOKEN; return r; }`); comment != "t2" {
		t.Errorf("reloaded: %q", comment)
	}
}

func TestWebSocketHook(t *testing.T) {
	e := New()
	r := rule(`
	let n = 0;
	function onWebsocket(context, url, request, response, message) {
		n++;
		console.log(n, url, response.statusCode, message.from, message.type, message.data, message.rawData ? message.rawData.length : -1);
		sharedState.seen = n;
	}`)
	plain := rule(`function onRequest(c, u, r) { return r; }`)
	f := flow.New("WS")
	req := &Request{Method: "GET", Scheme: "https", Host: "chat.dev", Port: 443, Path: "/socket"}
	s := e.NewWebSocketSession([]*rules.ScriptRule{plain, r}, f, req, &Response{StatusCode: 101})
	if s == nil {
		t.Fatal("no session")
	}
	if e.NewWebSocketSession([]*rules.ScriptRule{plain}, f, req, nil) != nil {
		t.Error("a session without hooks")
	}
	s.Add(flow.WebSocketMessage{From: "client", Type: "text", Data: "hi"})
	s.Add(flow.WebSocketMessage{From: "server", Type: "binary", RawData: flow.Blob{1, 2, 3}})
	s.Close()
	s.Add(flow.WebSocketMessage{From: "client", Type: "text", Data: "after close"})
	select {
	case <-s.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the hooks did not finish")
	}
	logs := e.Logs()
	if len(logs) != 2 || logs[0].Text != "1 https://chat.dev/socket 101 client text hi -1" || logs[1].Text != "2 https://chat.dev/socket 101 server binary <3 bytes of binary> 3" {
		t.Errorf("logs %+v", logs)
	}
}
