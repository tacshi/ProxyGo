package script

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

func rule(src string) *rules.ScriptRule {
	return &rules.ScriptRule{ID: rules.NewID(), Enabled: true, Name: "test", Matcher: rules.Matcher{URL: "*"}, Script: src, OnRequest: true, OnResponse: true}
}

func request() *Request {
	return &Request{
		Method: "POST", Scheme: "https", Host: "api.dev", Port: 443, Path: "/v1/items?page=1",
		Header: flow.NewHeader(http.Header{"Content-Type": {"application/json"}, "Cookie": {"a=1"}}),
		Body:   []byte(`{"name":"old","count":1}`),
	}
}

func TestRequestHook(t *testing.T) {
	e := New()
	r := rule(`async function onRequest(context, url, request) {
		console.log("url", url, {n: 1});
		request.method = "put";
		request.headers["X-Debug"] = "1";
		delete request.headers["Cookie"];
		request.queries["page"] = "2";
		request.body.name = "new";
		request.comment = "scripted";
		return request;
	}`)
	req := request()
	aborted, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), req)
	if err != nil || aborted {
		t.Fatalf("err %v aborted %v", err, aborted)
	}
	if req.Method != "PUT" {
		t.Errorf("method %q", req.Method)
	}
	if req.Header.Get("X-Debug") != "1" || req.Header.Get("Cookie") != "" {
		t.Errorf("headers %+v", req.Header)
	}
	if req.Path != "/v1/items?page=2" {
		t.Errorf("path %q", req.Path)
	}
	if !strings.Contains(string(req.Body), `"name":"new"`) {
		t.Errorf("body %s", req.Body)
	}
	if req.Comment != "scripted" {
		t.Errorf("comment %q", req.Comment)
	}
	logs := e.Logs()
	if len(logs) != 1 || logs[0].Text != `url https://api.dev/v1/items?page=1 {"n":1}` {
		t.Fatalf("logs %+v", logs)
	}
}

func TestResponseHookAndMock(t *testing.T) {
	e := New()
	r := rule(`function onResponse(context, url, request, response) {
		response.statusCode = 418;
		response.headers["Content-Type"] = "application/json";
		response.body = { mocked: true, path: request.path };
		return response;
	}`)
	resp := &Response{StatusCode: 200, Header: flow.NewHeader(http.Header{"Content-Type": {"text/plain"}}), Body: []byte("hi")}
	if err := e.RunResponse([]*rules.ScriptRule{r}, flow.New("F"), request(), resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 418 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("response %+v", resp)
	}
	if string(resp.Body) != `{"mocked":true,"path":"/v1/items?page=1"}` {
		t.Fatalf("body %s", resp.Body)
	}
	r.MockResponse = true
	if !Mocks([]*rules.ScriptRule{r}) {
		t.Fatal("mock rule not reported")
	}
}

func TestAbortAndErrors(t *testing.T) {
	e := New()
	aborted, err := e.RunRequest([]*rules.ScriptRule{rule(`function onRequest(ctx, url, req) { ctx.abort(); return req; }`)}, flow.New("F"), request())
	if err != nil || !aborted {
		t.Fatalf("abort: %v %v", aborted, err)
	}
	_, err = e.RunRequest([]*rules.ScriptRule{rule(`async function onRequest() { throw new Error("boom"); }`)}, flow.New("F"), request())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("rejection not reported: %v", err)
	}
	if err := Check("bad", "function ("); err == nil {
		t.Fatal("syntax error not reported")
	}
	if err := Check("template", Template); err != nil {
		t.Fatalf("template does not compile: %v", err)
	}
	logs := e.Logs()
	if len(logs) == 0 || logs[len(logs)-1].Level != "error" {
		t.Fatalf("error not logged: %+v", logs)
	}
	e.ClearLogs()
	if len(e.Logs()) != 0 {
		t.Fatal("logs not cleared")
	}
}

func TestSharedStateAndFiles(t *testing.T) {
	e := New()
	dir := t.TempDir()
	file := filepath.Join(dir, "body.json")
	if err := os.WriteFile(file, []byte(`{"from":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := rule(`function onRequest(ctx, url, req) {
		sharedState.n = (sharedState.n || 0) + 1;
		req.headers["X-Count"] = String(sharedState.n);
		req.headers["X-B64"] = btoa("hi");
		return req;
	}
	function onResponse(ctx, url, req, res) {
		res.bodyFilePath = "` + file + `";
		return res;
	}`)
	var req *Request
	for range 3 {
		req = request()
		if _, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), req); err != nil {
			t.Fatal(err)
		}
	}
	if req.Header.Get("X-Count") != "3" || req.Header.Get("X-B64") != "aGk=" {
		t.Fatalf("headers %+v", req.Header)
	}
	resp := &Response{StatusCode: 200}
	if err := e.RunResponse([]*rules.ScriptRule{r}, flow.New("F"), req, resp); err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != `{"from":"file"}` {
		t.Fatalf("body %s", resp.Body)
	}
}

func TestFormBody(t *testing.T) {
	e := New()
	req := request()
	req.Header = flow.NewHeader(http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	req.Body = []byte("user=a&pass=b")
	r := rule(`function onRequest(ctx, url, req) { req.body.user = "z"; return req; }`)
	if _, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), req); err != nil {
		t.Fatal(err)
	}
	if string(req.Body) != "user=z&pass=b" {
		t.Fatalf("form body %s", req.Body)
	}
}

func TestHeadersAnyCase(t *testing.T) {
	e := New()
	req := request()
	req.Header = flow.NewHeaderOrdered(http.Header{"Content-Type": {"application/json"}, "X-Trace": {"t"}}, []flow.SentHeader{{Name: "x-trace", Value: "t"}, {Name: "content-type", Value: "application/json"}})
	r := rule(`function onRequest(context, url, request) {
		request.headers["Content-Type"] = "text/plain";
		request.headers["X-Seen"] = request.headers["X-TRACE"] + "," + ("x-trace" in request.headers);
		return request;
	}`)
	if _, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), req); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, h := range req.Header.Entries {
		lines = append(lines, h.Key.Name+": "+h.Value)
	}
	if got, want := strings.Join(lines, "\n"), "x-trace: t\ncontent-type: text/plain\nX-Seen: t,true"; got != want {
		t.Fatalf("headers\n%s\nwant\n%s", got, want)
	}
}

func TestUntouchedBodyKeepsBytes(t *testing.T) {
	e := New()
	body := `{"z":1.0,"a":9007199254740993,"html":"<b>&</b>","2":"x","1":"y"}`
	r := rule(`function onRequest(context, url, request) {
		request.headers["X-Seen"] = "1";
		return request;
	}
	function onResponse(context, url, request, response) {
		response.statusCode = 201;
		return response;
	}`)
	req := request()
	req.Body = []byte(body)
	if _, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), req); err != nil {
		t.Fatal(err)
	}
	if string(req.Body) != body || req.Header.Get("X-Seen") != "1" {
		t.Fatalf("request body %s", req.Body)
	}
	resp := &Response{StatusCode: 200, Header: flow.NewHeader(http.Header{"Content-Type": {"application/json"}}), Body: []byte(body)}
	if err := e.RunResponse([]*rules.ScriptRule{r}, flow.New("F"), request(), resp); err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != body || resp.StatusCode != 201 {
		t.Fatalf("response %d %s", resp.StatusCode, resp.Body)
	}
}

func TestChangedJSONBodyKeepsKeyOrder(t *testing.T) {
	e := New()
	r := rule(`function onRequest(context, url, request) {
		request.body.name = "<new>";
		return request;
	}`)
	req := request()
	req.Body = []byte(`{"z":1,"name":"old","a":2}`)
	if _, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), req); err != nil {
		t.Fatal(err)
	}
	if string(req.Body) != `{"z":1,"name":"<new>","a":2}` {
		t.Fatalf("body %s", req.Body)
	}
}

func TestFormBodyAndQueryOrder(t *testing.T) {
	e := New()
	req := request()
	req.Path = "/f?z=1&a=2&z=3"
	req.Header = flow.NewHeader(http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	req.Body = []byte("z=1&tag=a&tag=b&a=x+y")
	untouched := rule(`function onRequest(context, url, request) { return request; }`)
	if _, err := e.RunRequest([]*rules.ScriptRule{untouched}, flow.New("F"), req); err != nil {
		t.Fatal(err)
	}
	if string(req.Body) != "z=1&tag=a&tag=b&a=x+y" || req.Path != "/f?z=1&a=2&z=3" {
		t.Fatalf("untouched %q %q", req.Path, req.Body)
	}
	changed := rule(`function onRequest(context, url, request) {
		request.body.a = "new";
		request.queries.a = "3";
		return request;
	}`)
	if _, err := e.RunRequest([]*rules.ScriptRule{changed}, flow.New("F"), req); err != nil {
		t.Fatal(err)
	}
	if string(req.Body) != "z=1&tag=a&tag=b&a=new" || req.Path != "/f?z=1&z=3&a=3" {
		t.Fatalf("changed %q %q", req.Path, req.Body)
	}
}

func TestIPv6RequestURL(t *testing.T) {
	r := &Request{Scheme: "http", Host: "::1", Port: 8080, Path: "/x"}
	if got := r.URL(); got != "http://[::1]:8080/x" {
		t.Fatalf("url %q", got)
	}
	r.Port = 80
	if got := r.URL(); got != "http://[::1]/x" {
		t.Fatalf("url %q", got)
	}
}
