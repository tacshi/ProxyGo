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
	if string(req.Body) != "pass=b&user=z" {
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
