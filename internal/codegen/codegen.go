package codegen

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"proxygo/internal/flow"
)

type Request struct {
	Method string
	URL    string
	Header flow.Header
	Body   []byte
}

func Of(f *flow.Flow) Request {
	if f == nil || f.Request == nil {
		return Request{Method: "GET"}
	}
	return Request{Method: f.MethodName(), URL: f.URL(), Header: f.Request.Header, Body: f.DecodedRequestBody()}
}

type Language struct {
	Name     string
	Generate func(Request) string
}

var Languages = []Language{
	{"cURL", Curl},
	{"HTTPie", HTTPie},
	{"Dart (http)", Dart},
	{"Go (net/http)", Go},
	{"HAR", HAR},
	{"Java (HttpClient)", Java},
	{"JavaScript (fetch)", Fetch},
	{"JavaScript (jQuery)", JQuery},
	{"Kotlin (OkHttp)", Kotlin},
	{"Node.js (axios)", Axios},
	{"Node.js (http)", NodeHTTP},
	{"Objective-C (NSURLSession)", ObjC},
	{"PHP (cURL)", PHP},
	{"PHP (Guzzle)", Guzzle},
	{"Postman Collection v2.1", Postman},
	{"Python (requests)", Python},
	{"Ruby (Net::HTTP)", Ruby},
	{"Rust (reqwest)", Rust},
	{"Swift (Alamofire)", Alamofire},
	{"Swift (Moya)", Moya},
	{"Swift (URLSession)", Swift},
}

func Extension(name string) string {
	switch name {
	case "cURL", "HTTPie":
		return "sh"
	case "Dart (http)":
		return "dart"
	case "Go (net/http)":
		return "go"
	case "HAR":
		return "har"
	case "Java (HttpClient)":
		return "java"
	case "JavaScript (fetch)", "JavaScript (jQuery)", "Node.js (axios)", "Node.js (http)":
		return "js"
	case "Kotlin (OkHttp)":
		return "kt"
	case "Objective-C (NSURLSession)":
		return "m"
	case "PHP (cURL)", "PHP (Guzzle)":
		return "php"
	case "Postman Collection v2.1":
		return "postman_collection.json"
	case "Python (requests)":
		return "py"
	case "Ruby (Net::HTTP)":
		return "rb"
	case "Rust (reqwest)":
		return "rs"
	case "Swift (Alamofire)", "Swift (Moya)", "Swift (URLSession)":
		return "swift"
	}
	return "txt"
}

func Named(name string) func(Request) string {
	if i := slices.IndexFunc(Languages, func(l Language) bool { return l.Name == name }); i >= 0 {
		return Languages[i].Generate
	}
	return Curl
}

var skipped = []string{"host", "content-length", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "upgrade", "accept-encoding"}

func (r Request) headers() [][2]string {
	var out [][2]string
	for _, e := range r.Header.Entries {
		if !e.Enabled || slices.Contains(skipped, strings.ToLower(e.Key.Name)) || strings.HasPrefix(e.Key.Name, ":") {
			continue
		}
		out = append(out, [2]string{e.Key.Name, e.Value})
	}
	return out
}

func (r Request) method() string {
	if r.Method == "" {
		return "GET"
	}
	return strings.ToUpper(r.Method)
}

func (r Request) textBody() (string, bool) {
	if len(r.Body) == 0 {
		return "", true
	}
	if !utf8.Valid(r.Body) || strings.ContainsRune(string(r.Body), 0) {
		return "", false
	}
	return string(r.Body), true
}

func (r Request) compressed() bool {
	return r.Header.Get("Accept-Encoding") != ""
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func quoted(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func rubyQuoted(s string) string { return strings.ReplaceAll(quoted(s), "#", `\#`) }

func kotlinQuoted(s string) string { return strings.ReplaceAll(quoted(s), "$", `\$`) }

func Curl(r Request) string {
	var b strings.Builder
	b.WriteString("curl")
	if m := r.method(); m != "GET" || len(r.Body) > 0 && m != "POST" {
		b.WriteString(" -X " + m)
	}
	b.WriteString(" " + shellQuote(r.URL))
	for _, h := range r.headers() {
		b.WriteString(" \\\n  -H " + shellQuote(h[0]+": "+h[1]))
	}
	if body, ok := r.textBody(); !ok {
		fmt.Fprintf(&b, " \\\n  --data-binary @body.bin # %d bytes of binary data", len(r.Body))
	} else if body != "" {
		b.WriteString(" \\\n  --data-raw " + shellQuote(body))
	}
	if r.compressed() {
		b.WriteString(" \\\n  --compressed")
	}
	return b.String()
}

func HTTPie(r Request) string {
	var b strings.Builder
	body, ok := r.textBody()
	if ok && body != "" {
		b.WriteString("printf %s " + shellQuote(body) + " | ")
	}
	b.WriteString("http " + r.method() + " " + shellQuote(r.URL))
	for _, h := range r.headers() {
		b.WriteString(" \\\n  " + shellQuote(h[0]+":"+h[1]))
	}
	if !ok {
		b.WriteString(" < body.bin")
	}
	return b.String()
}

func Fetch(r Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "const response = await fetch(%s, {\n  method: %s,\n", quoted(r.URL), quoted(r.method()))
	if hs := r.headers(); len(hs) > 0 {
		b.WriteString("  headers: {\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "    %s: %s,\n", quoted(h[0]), quoted(h[1]))
		}
		b.WriteString("  },\n")
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "  body: %s,\n", quoted(body))
	}
	b.WriteString("});\nconsole.log(response.status, await response.text());")
	return b.String()
}

func Axios(r Request) string {
	var b strings.Builder
	b.WriteString("const axios = require(\"axios\");\n\n(async () => {\n")
	fmt.Fprintf(&b, "  const response = await axios({\n    method: %s,\n    url: %s,\n", quoted(strings.ToLower(r.method())), quoted(r.URL))
	if hs := r.headers(); len(hs) > 0 {
		b.WriteString("    headers: {\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "      %s: %s,\n", quoted(h[0]), quoted(h[1]))
		}
		b.WriteString("    },\n")
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "    data: %s,\n", quoted(body))
	}
	b.WriteString("  });\n  console.log(response.status, response.data);\n})();")
	return b.String()
}

func Python(r Request) string {
	var b strings.Builder
	b.WriteString("import requests\n\n")
	fmt.Fprintf(&b, "url = %s\n", quoted(r.URL))
	hs := r.headers()
	if len(hs) > 0 {
		b.WriteString("headers = {\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "    %s: %s,\n", quoted(h[0]), quoted(h[1]))
		}
		b.WriteString("}\n")
	}
	body, ok := r.textBody()
	if ok && body != "" {
		fmt.Fprintf(&b, "data = %s\n", quoted(body))
	}
	fmt.Fprintf(&b, "\nresponse = requests.request(%s, url", quoted(r.method()))
	if len(hs) > 0 {
		b.WriteString(", headers=headers")
	}
	if ok && body != "" {
		b.WriteString(", data=data.encode()")
	}
	b.WriteString(")\nprint(response.status_code, response.text)")
	return b.String()
}

func Go(r Request) string {
	var b strings.Builder
	body, ok := r.textBody()
	b.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"io\"\n\t\"net/http\"\n")
	if ok && body != "" {
		b.WriteString("\t\"strings\"\n")
	}
	b.WriteString(")\n\nfunc main() {\n")
	bodyExpr := "nil"
	if ok && body != "" {
		bodyExpr = "strings.NewReader(" + strconv.Quote(body) + ")"
	}
	fmt.Fprintf(&b, "\treq, err := http.NewRequest(%s, %s, %s)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n", strconv.Quote(r.method()), strconv.Quote(r.URL), bodyExpr)
	for _, h := range r.headers() {
		fmt.Fprintf(&b, "\treq.Header.Set(%s, %s)\n", strconv.Quote(h[0]), strconv.Quote(h[1]))
	}
	b.WriteString("\tresp, err := http.DefaultClient.Do(req)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n\tdefer resp.Body.Close()\n\tdata, _ := io.ReadAll(resp.Body)\n\tfmt.Println(resp.Status, string(data))\n}")
	return b.String()
}

func Swift(r Request) string {
	var b strings.Builder
	b.WriteString("import Foundation\n\n")
	fmt.Fprintf(&b, "var request = URLRequest(url: URL(string: %s)!)\nrequest.httpMethod = %s\n", swiftQuoted(r.URL), swiftQuoted(r.method()))
	for _, h := range r.headers() {
		fmt.Fprintf(&b, "request.setValue(%s, forHTTPHeaderField: %s)\n", swiftQuoted(h[1]), swiftQuoted(h[0]))
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "request.httpBody = Data(%s.utf8)\n", swiftQuoted(body))
	}
	b.WriteString("\nlet (data, response) = try await URLSession.shared.data(for: request)\nprint((response as? HTTPURLResponse)?.statusCode ?? 0, String(decoding: data, as: UTF8.self))")
	return b.String()
}

func Kotlin(r Request) string {
	var b strings.Builder
	b.WriteString("import okhttp3.MediaType.Companion.toMediaType\nimport okhttp3.OkHttpClient\nimport okhttp3.Request\nimport okhttp3.RequestBody.Companion.toRequestBody\n\n")
	body, ok := r.textBody()
	bodyExpr := "null"
	if ok && body != "" {
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "text/plain"
		}
		bodyExpr = fmt.Sprintf("%s.toRequestBody(%s.toMediaType())", kotlinQuoted(body), kotlinQuoted(ct))
	}
	fmt.Fprintf(&b, "val request = Request.Builder()\n  .url(%s)\n  .method(%s, %s)\n", kotlinQuoted(r.URL), quoted(r.method()), bodyExpr)
	for _, h := range r.headers() {
		fmt.Fprintf(&b, "  .addHeader(%s, %s)\n", kotlinQuoted(h[0]), kotlinQuoted(h[1]))
	}
	b.WriteString("  .build()\n\nOkHttpClient().newCall(request).execute().use { response ->\n  println(\"${response.code} ${response.body?.string()}\")\n}")
	return b.String()
}

func Ruby(r Request) string {
	var b strings.Builder
	b.WriteString("require \"net/http\"\nrequire \"uri\"\n\n")
	fmt.Fprintf(&b, "uri = URI(%s)\n", rubyQuoted(r.URL))
	fmt.Fprintf(&b, "request = Net::HTTPGenericRequest.new(%s, %v, true, uri)\n", quoted(r.method()), len(r.Body) > 0)
	for _, h := range r.headers() {
		fmt.Fprintf(&b, "request[%s] = %s\n", rubyQuoted(h[0]), rubyQuoted(h[1]))
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "request.body = %s\n", rubyQuoted(body))
	}
	b.WriteString("\nresponse = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == \"https\") { |http| http.request(request) }\nputs response.code, response.body")
	return b.String()
}

func PHP(r Request) string {
	var b strings.Builder
	single := func(s string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
	}
	b.WriteString("<?php\n\n$curl = curl_init();\n")
	fmt.Fprintf(&b, "curl_setopt_array($curl, [\n  CURLOPT_URL => %s,\n  CURLOPT_RETURNTRANSFER => true,\n  CURLOPT_CUSTOMREQUEST => %s,\n", single(r.URL), single(r.method()))
	if hs := r.headers(); len(hs) > 0 {
		b.WriteString("  CURLOPT_HTTPHEADER => [\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "    %s,\n", single(h[0]+": "+h[1]))
		}
		b.WriteString("  ],\n")
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "  CURLOPT_POSTFIELDS => %s,\n", single(body))
	}
	b.WriteString("]);\n$response = curl_exec($curl);\ncurl_close($curl);\necho $response;")
	return b.String()
}
