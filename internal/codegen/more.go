package codegen

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"proxygo/internal/flow"
	"proxygo/internal/session"
)

func escaped(s string, esc func(r rune) string) string {
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
			if r < 0x20 || r == 0x7f {
				b.WriteString(esc(r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func swiftQuoted(s string) string {
	return escaped(s, func(r rune) string { return fmt.Sprintf(`\u{%x}`, r) })
}

func rustQuoted(s string) string {
	return escaped(s, func(r rune) string { return fmt.Sprintf(`\u{%x}`, r) })
}

func dartQuoted(s string) string { return strings.ReplaceAll(quoted(s), "$", `\$`) }

func objcQuoted(s string) string { return "@" + quoted(s) }

func phpSingle(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

func Dart(r Request) string {
	var b strings.Builder
	b.WriteString("import 'package:http/http.dart' as http;\n\nFuture<void> main() async {\n")
	fmt.Fprintf(&b, "  final request = http.Request(%s, Uri.parse(%s));\n", dartQuoted(r.method()), dartQuoted(r.URL))
	if hs := r.headers(); len(hs) > 0 {
		b.WriteString("  request.headers.addAll({\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "    %s: %s,\n", dartQuoted(h[0]), dartQuoted(h[1]))
		}
		b.WriteString("  });\n")
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "  request.body = %s;\n", dartQuoted(body))
	}
	b.WriteString("\n  final response = await http.Client().send(request);\n  print('${response.statusCode} ${await response.stream.bytesToString()}');\n}\n")
	return b.String()
}

func Java(r Request) string {
	var b strings.Builder
	b.WriteString("import java.net.URI;\nimport java.net.http.HttpClient;\nimport java.net.http.HttpRequest;\nimport java.net.http.HttpResponse;\n\n")
	b.WriteString("public class Main {\n  public static void main(String[] args) throws Exception {\n")
	fmt.Fprintf(&b, "    HttpRequest request = HttpRequest.newBuilder()\n        .uri(URI.create(%s))\n", quoted(r.URL))
	for _, h := range r.headers() {
		if strings.EqualFold(h[0], "expect") {
			continue
		}
		fmt.Fprintf(&b, "        .header(%s, %s)\n", quoted(h[0]), quoted(h[1]))
	}
	publisher := "HttpRequest.BodyPublishers.noBody()"
	if body, ok := r.textBody(); ok && body != "" {
		publisher = "HttpRequest.BodyPublishers.ofString(" + quoted(body) + ")"
	}
	fmt.Fprintf(&b, "        .method(%s, %s)\n        .build();\n", quoted(r.method()), publisher)
	b.WriteString("    HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());\n")
	b.WriteString("    System.out.println(response.statusCode() + \" \" + response.body());\n  }\n}\n")
	return b.String()
}

func JQuery(r Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$.ajax({\n  url: %s,\n  method: %s,\n", quoted(r.URL), quoted(r.method()))
	if hs := r.headers(); len(hs) > 0 {
		b.WriteString("  headers: {\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "    %s: %s,\n", quoted(h[0]), quoted(h[1]))
		}
		b.WriteString("  },\n")
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "  data: %s,\n  processData: false,\n", quoted(body))
		if ct := r.Header.Get("Content-Type"); ct != "" {
			fmt.Fprintf(&b, "  contentType: %s,\n", quoted(ct))
		}
	}
	b.WriteString("}).always(function (data, status, xhr) {\n  console.log(status, data);\n});\n")
	return b.String()
}

func NodeHTTP(r Request) string {
	mod := "http"
	if strings.HasPrefix(strings.ToLower(r.URL), "https:") {
		mod = "https"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "const %s = require(%s);\n\n", mod, quoted(mod))
	fmt.Fprintf(&b, "const req = %s.request(%s, {\n  method: %s,\n", mod, quoted(r.URL), quoted(r.method()))
	if hs := r.headers(); len(hs) > 0 {
		b.WriteString("  headers: {\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "    %s: %s,\n", quoted(h[0]), quoted(h[1]))
		}
		b.WriteString("  },\n")
	}
	b.WriteString("}, (res) => {\n  let data = \"\";\n  res.setEncoding(\"utf8\");\n  res.on(\"data\", (chunk) => (data += chunk));\n  res.on(\"end\", () => console.log(res.statusCode, data));\n});\n")
	b.WriteString("req.on(\"error\", console.error);\n")
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "req.write(%s);\n", quoted(body))
	}
	b.WriteString("req.end();\n")
	return b.String()
}

func ObjC(r Request) string {
	var b strings.Builder
	b.WriteString("#import <Foundation/Foundation.h>\n\nint main(int argc, const char *argv[]) {\n  @autoreleasepool {\n")
	fmt.Fprintf(&b, "    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:%s]];\n", objcQuoted(r.URL))
	fmt.Fprintf(&b, "    request.HTTPMethod = %s;\n", objcQuoted(r.method()))
	for _, h := range r.headers() {
		fmt.Fprintf(&b, "    [request setValue:%s forHTTPHeaderField:%s];\n", objcQuoted(h[1]), objcQuoted(h[0]))
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "    request.HTTPBody = [%s dataUsingEncoding:NSUTF8StringEncoding];\n", objcQuoted(body))
	}
	b.WriteString(`    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
      if (error) {
        NSLog(@"%@", error);
      } else {
        NSLog(@"%ld %@", (long)((NSHTTPURLResponse *)response).statusCode,
              [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
      }
      dispatch_semaphore_signal(done);
    }];
    [task resume];
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
  }
  return 0;
}
`)
	return b.String()
}

func Guzzle(r Request) string {
	var b strings.Builder
	b.WriteString("<?php\n\nrequire 'vendor/autoload.php';\n\nuse GuzzleHttp\\Client;\n\n$client = new Client();\n")
	fmt.Fprintf(&b, "$response = $client->request(%s, %s, [\n", phpSingle(r.method()), phpSingle(r.URL))
	if hs := r.headers(); len(hs) > 0 {
		b.WriteString("    'headers' => [\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "        %s => %s,\n", phpSingle(h[0]), phpSingle(h[1]))
		}
		b.WriteString("    ],\n")
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "    'body' => %s,\n", phpSingle(body))
	}
	b.WriteString("    'http_errors' => false,\n]);\n\necho $response->getStatusCode(), ' ', $response->getBody();\n")
	return b.String()
}

func Rust(r Request) string {
	var b strings.Builder
	b.WriteString("#[tokio::main]\nasync fn main() -> Result<(), Box<dyn std::error::Error>> {\n")
	method := "reqwest::Method::" + r.method()
	switch r.method() {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "TRACE":
	default:
		method = "reqwest::Method::from_bytes(" + rustQuoted(r.method()) + ".as_bytes())?"
	}
	fmt.Fprintf(&b, "    let response = reqwest::Client::new()\n        .request(%s, %s)\n", method, rustQuoted(r.URL))
	for _, h := range r.headers() {
		fmt.Fprintf(&b, "        .header(%s, %s)\n", rustQuoted(h[0]), rustQuoted(h[1]))
	}
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, "        .body(%s)\n", rustQuoted(body))
	}
	b.WriteString("        .send()\n        .await?;\n    println!(\"{} {}\", response.status(), response.text().await?);\n    Ok(())\n}\n")
	return b.String()
}

func Alamofire(r Request) string {
	var b strings.Builder
	b.WriteString("import Alamofire\n\n")
	hs := r.headers()
	if len(hs) > 0 {
		b.WriteString("let headers: HTTPHeaders = [\n")
		for _, h := range hs {
			fmt.Fprintf(&b, "    %s: %s,\n", swiftQuoted(h[0]), swiftQuoted(h[1]))
		}
		b.WriteString("]\n")
	} else {
		b.WriteString("let headers: HTTPHeaders = [:]\n")
	}
	fmt.Fprintf(&b, "AF.request(%s, method: HTTPMethod(rawValue: %s), headers: headers", swiftQuoted(r.URL), swiftQuoted(r.method()))
	if body, ok := r.textBody(); ok && body != "" {
		fmt.Fprintf(&b, ") { $0.httpBody = Data(%s.utf8) }", swiftQuoted(body))
	} else {
		b.WriteString(")")
	}
	b.WriteString("\n.responseString { response in\n    debugPrint(response)\n}\n")
	return b.String()
}

func Moya(r Request) string {
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		u = &url.URL{Scheme: "https", Host: "example.com"}
	}
	base := u.Scheme + "://" + u.Host
	path := u.Path
	q := u.Query()
	var b strings.Builder
	b.WriteString("import Foundation\nimport Moya\n\nenum API {\n    case request\n}\n\nextension API: TargetType {\n")
	fmt.Fprintf(&b, "    var baseURL: URL { URL(string: %s)! }\n", swiftQuoted(base))
	fmt.Fprintf(&b, "    var path: String { %s }\n", swiftQuoted(path))
	fmt.Fprintf(&b, "    var method: Moya.Method { Moya.Method(rawValue: %s) }\n", swiftQuoted(r.method()))
	params := ""
	if len(q) > 0 {
		var kv []string
		for _, k := range slices.Sorted(func(yield func(string) bool) {
			for k := range q {
				if !yield(k) {
					return
				}
			}
		}) {
			kv = append(kv, swiftQuoted(k)+": "+swiftQuoted(q.Get(k)))
		}
		params = "[" + strings.Join(kv, ", ") + "]"
	}
	body, ok := r.textBody()
	hasBody := ok && body != ""
	switch {
	case hasBody && params != "":
		fmt.Fprintf(&b, "    var task: Task { .requestCompositeData(bodyData: Data(%s.utf8), urlParameters: %s) }\n", swiftQuoted(body), params)
	case hasBody:
		fmt.Fprintf(&b, "    var task: Task { .requestData(Data(%s.utf8)) }\n", swiftQuoted(body))
	case params != "":
		fmt.Fprintf(&b, "    var task: Task { .requestParameters(parameters: %s, encoding: URLEncoding.queryString) }\n", params)
	default:
		b.WriteString("    var task: Task { .requestPlain }\n")
	}
	if hs := r.headers(); len(hs) > 0 {
		var kv []string
		for _, h := range hs {
			kv = append(kv, swiftQuoted(h[0])+": "+swiftQuoted(h[1]))
		}
		fmt.Fprintf(&b, "    var headers: [String: String]? { [%s] }\n", strings.Join(kv, ", "))
	} else {
		b.WriteString("    var headers: [String: String]? { nil }\n")
	}
	b.WriteString("}\n\nlet provider = MoyaProvider<API>()\nprovider.request(.request) { result in\n    switch result {\n    case let .success(response):\n        print(response.statusCode, String(decoding: response.data, as: UTF8.self))\n    case let .failure(error):\n        print(error)\n    }\n}\n")
	return b.String()
}

func (r Request) asFlow() *flow.Flow {
	f := flow.New(flow.NewUniqueID())
	u, _ := url.Parse(r.URL)
	host, scheme := "", "https"
	if u != nil {
		host, scheme = u.Hostname(), u.Scheme
	}
	f.Request = &flow.Request{Scheme: scheme, Host: host, FullPath: r.URL, Method: flow.Method{Name: r.method()}, Header: r.Header.Clone(), BodyData: r.Body}
	if u != nil {
		f.Request.URI = u.RequestURI()
	}
	f.IsSSL = scheme == "https"
	return f
}

func HAR(r Request) string { return session.HARJSON(r.asFlow()) }

func Postman(r Request) string { return session.PostmanJSON(r.asFlow()) }

func Markdown(flows []*flow.Flow) string {
	var b strings.Builder
	cell := func(s string) string { return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s) }
	b.WriteString("| Method | URL | Status | Duration |\n| --- | --- | --- | --- |\n")
	for _, f := range flows {
		dur := ""
		if d := f.Duration(); d > 0 {
			dur = d.Round(1e6).String()
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", cell(f.MethodName()), cell(f.URL()), cell(f.StatusLine()), dur)
	}
	if len(flows) != 1 {
		return b.String()
	}
	f := flows[0]
	section := func(title string, h flow.Header, body []byte, ct string) {
		fmt.Fprintf(&b, "\n**%s**\n\n```http\n", title)
		for _, e := range h.Entries {
			if e.Enabled {
				fmt.Fprintf(&b, "%s: %s\n", e.Key.Name, e.Value)
			}
		}
		b.WriteString("```\n")
		if len(body) > 0 && len(body) <= 16<<10 && utf8.Valid(body) {
			lang := ""
			if strings.Contains(ct, "json") {
				lang = "json"
			}
			fmt.Fprintf(&b, "\n```%s\n%s\n```\n", lang, strings.TrimRight(string(body), "\n"))
		}
	}
	section("Request", f.Request.Header, f.DecodedRequestBody(), f.Request.Header.Get("Content-Type"))
	if f.Response != nil && !f.IsError() {
		section("Response "+fmt.Sprint(f.StatusCode())+" "+http.StatusText(f.StatusCode()), f.Response.Header, f.DecodedResponseBody(), f.Response.Header.Get("Content-Type"))
	}
	return b.String()
}
