package script

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

type Request struct {
	Method  string
	Scheme  string
	Host    string
	Port    int
	Path    string
	Header  flow.Header
	Body    []byte
	Comment string
	Color   string
}

func (r *Request) URL() string {
	host := r.Host
	if (r.Scheme == "https" && r.Port != 443 && r.Port != 0) || (r.Scheme == "http" && r.Port != 80 && r.Port != 0) {
		host += ":" + strconv.Itoa(r.Port)
	}
	path := r.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return r.Scheme + "://" + host + path
}

type Response struct {
	StatusCode int
	Header     flow.Header
	Body       []byte
}

type LogLine struct {
	Time   time.Time
	Script string
	Level  string
	Text   string
}

type Engine struct {
	mu       sync.Mutex
	sharedMu sync.Mutex
	programs map[string]*goja.Program
	shared   map[string]any
	logs     []LogLine
	version  uint64

	root     string
	modules  map[string]compiledModule
	allowEnv bool
	env      map[string]string
}

func New() *Engine {
	return &Engine{programs: map[string]*goja.Program{}, shared: map[string]any{}}
}

func (e *Engine) Logs() []LogLine {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]LogLine(nil), e.logs...)
}

func (e *Engine) LogVersion() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.version
}

func (e *Engine) ClearLogs() {
	e.mu.Lock()
	e.logs = nil
	e.version++
	e.mu.Unlock()
}

func (e *Engine) addLog(script, level, s string) {
	e.mu.Lock()
	e.logs = append(e.logs, LogLine{Time: time.Now(), Script: script, Level: level, Text: s})
	if len(e.logs) > 1000 {
		e.logs = e.logs[len(e.logs)-1000:]
	}
	e.version++
	e.mu.Unlock()
}

func Check(name, src string) error {
	_, err := goja.Compile(name+".js", src, true)
	return err
}

func (e *Engine) program(rule *rules.ScriptRule) (*goja.Program, error) {
	key := rule.ID + ":" + hash(rule.Script)
	e.mu.Lock()
	p := e.programs[key]
	e.mu.Unlock()
	if p != nil {
		return p, nil
	}
	p, err := goja.Compile(rule.Name+".js", rule.Script, true)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if len(e.programs) > 200 {
		clear(e.programs)
	}
	e.programs[key] = p
	e.mu.Unlock()
	return p, nil
}

func hash(s string) string {
	var h uint64 = 1469598103934665603
	for i := range len(s) {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return strconv.FormatUint(h, 16)
}

func (e *Engine) RunRequest(list []*rules.ScriptRule, f *flow.Flow, req *Request) (bool, error) {
	for _, rule := range list {
		if !rule.OnRequest || rule.MockResponse {
			continue
		}
		aborted, err := e.run(rule, "onRequest", f, req, nil)
		if err != nil {
			e.addLog(rule.Name, "error", err.Error())
			return false, fmt.Errorf("%s: %w", rule.Name, err)
		}
		if aborted {
			return true, nil
		}
	}
	return false, nil
}

func (e *Engine) RunResponse(list []*rules.ScriptRule, f *flow.Flow, req *Request, resp *Response) error {
	for _, rule := range list {
		if !rule.OnResponse && !rule.MockResponse {
			continue
		}
		if _, err := e.run(rule, "onResponse", f, req, resp); err != nil {
			e.addLog(rule.Name, "error", err.Error())
			return fmt.Errorf("%s: %w", rule.Name, err)
		}
	}
	return nil
}

func Mocks(list []*rules.ScriptRule) bool {
	for _, r := range list {
		if r.MockResponse {
			return true
		}
	}
	return false
}

func (e *Engine) run(rule *rules.ScriptRule, hook string, f *flow.Flow, req *Request, resp *Response) (aborted bool, err error) {
	prog, err := e.program(rule)
	if err != nil {
		return false, err
	}
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	timer := time.AfterFunc(30*time.Second, func() { vm.Interrupt("script timed out after 30 s") })
	defer timer.Stop()

	lease := e.installRuntime(vm, rule.Name)
	defer lease.release()
	if _, err := vm.RunProgram(prog); err != nil {
		return false, err
	}
	fnVal := vm.Get(hook)
	if fnVal == nil || goja.IsUndefined(fnVal) || goja.IsNull(fnVal) {
		return false, nil
	}
	fn, ok := goja.AssertFunction(fnVal)
	if !ok {
		return false, fmt.Errorf("%s is not a function", hook)
	}

	abortFlag := false
	ctx := vm.NewObject()
	_ = ctx.Set("scriptName", rule.Name)
	_ = ctx.Set("matchingRule", rule.URL)
	_ = ctx.Set("matchingMethod", rule.Method)
	_ = ctx.Set("isEnableOnRequest", rule.OnRequest)
	_ = ctx.Set("isEnableOnResponse", rule.OnResponse)
	_ = ctx.Set("isMockResponse", rule.MockResponse)
	_ = ctx.Set("flow", flowInfo(f))
	_ = ctx.Set("abort", func() { abortFlag = true })
	_ = vm.Set("$abort", func() { abortFlag = true })

	reqObj := requestValue(vm, req)
	args := []goja.Value{ctx, vm.ToValue(req.URL()), reqObj}
	var respObj *goja.Object
	if resp != nil {
		respObj = responseValue(vm, resp)
		args = append(args, respObj)
	}
	result, err := fn(goja.Undefined(), args...)
	if err != nil {
		return false, err
	}
	if p, ok := result.Export().(*goja.Promise); ok {
		switch p.State() {
		case goja.PromiseStateRejected:
			return false, fmt.Errorf("%v", p.Result())
		case goja.PromiseStatePending:
			return false, fmt.Errorf("%s did not finish", hook)
		}
		result = p.Result()
	}
	if abortFlag {
		return true, nil
	}
	if hook == "onRequest" {
		obj := reqObj
		if o, ok := result.(*goja.Object); ok && result != nil && !goja.IsUndefined(result) && !goja.IsNull(result) {
			obj = o
		}
		absorbRequest(vm, obj, req)
		return false, nil
	}
	obj := respObj
	if o, ok := result.(*goja.Object); ok && o.Get("statusCode") != nil {
		obj = o
	}
	absorbResponse(vm, obj, resp)
	return false, nil
}

func flowInfo(f *flow.Flow) map[string]any {
	if f == nil {
		return map[string]any{}
	}
	var pid any
	if f.Client.PID > 0 {
		pid = f.Client.PID
	}
	return map[string]any{
		"id":              f.UniqueID,
		"clientName":      f.Client.Name,
		"clientPath":      f.Client.Path,
		"clientPid":       pid,
		"clientIpAddress": f.Summary.ClientIPAddress,
		"clientPort":      f.Summary.ClientPort,
		"serverIpAddress": f.Summary.ServerIPAddress,
		"serverPort":      f.Summary.ServerPort,
	}
}

func headerObject(vm *goja.Runtime, h flow.Header) *goja.Object {
	o := &headerMap{values: map[string]goja.Value{}}
	for _, e := range h.Entries {
		if !e.Enabled {
			continue
		}
		if prev := o.Get(e.Key.Name); prev != nil {
			o.Set(e.Key.Name, vm.ToValue(prev.String()+", "+e.Value))
			continue
		}
		o.Set(e.Key.Name, vm.ToValue(e.Value))
	}
	return vm.NewDynamicObject(o)
}

type headerMap struct {
	names  []string
	values map[string]goja.Value
}

func (m *headerMap) Get(key string) goja.Value { return m.values[strings.ToLower(key)] }

func (m *headerMap) Set(key string, val goja.Value) bool {
	lower := strings.ToLower(key)
	if _, ok := m.values[lower]; !ok {
		m.names = append(m.names, key)
	}
	m.values[lower] = val
	return true
}

func (m *headerMap) Has(key string) bool {
	_, ok := m.values[strings.ToLower(key)]
	return ok
}

func (m *headerMap) Delete(key string) bool {
	lower := strings.ToLower(key)
	delete(m.values, lower)
	m.names = slices.DeleteFunc(m.names, func(n string) bool { return strings.ToLower(n) == lower })
	return true
}

func (m *headerMap) Keys() []string { return slices.Clone(m.names) }

func requestValue(vm *goja.Runtime, req *Request) *goja.Object {
	o := vm.NewObject()
	_ = o.Set("method", req.Method)
	_ = o.Set("scheme", req.Scheme)
	_ = o.Set("host", req.Host)
	_ = o.Set("port", req.Port)
	_ = o.Set("path", req.Path)
	_ = o.Set("headers", headerObject(vm, req.Header))
	queries := vm.NewObject()
	if _, q, ok := strings.Cut(req.Path, "?"); ok {
		values, _ := url.ParseQuery(q)
		for k, vs := range values {
			if len(vs) == 1 {
				_ = queries.Set(k, vs[0])
			} else {
				_ = queries.Set(k, vs)
			}
		}
	}
	_ = o.Set("queries", queries)
	_ = o.Set("body", bodyValue(vm, req.Body, req.Header.Get("Content-Type")))
	_ = o.Set("rawBody", string(req.Body))
	_ = o.Set("comment", req.Comment)
	_ = o.Set("color", req.Color)
	return o
}

func responseValue(vm *goja.Runtime, resp *Response) *goja.Object {
	o := vm.NewObject()
	_ = o.Set("statusCode", resp.StatusCode)
	_ = o.Set("statusPhrase", http.StatusText(resp.StatusCode))
	_ = o.Set("httpVersion", "HTTP/1.1")
	_ = o.Set("headers", headerObject(vm, resp.Header))
	_ = o.Set("body", bodyValue(vm, resp.Body, resp.Header.Get("Content-Type")))
	_ = o.Set("rawBody", string(resp.Body))
	return o
}

func bodyValue(vm *goja.Runtime, body []byte, contentType string) goja.Value {
	if len(body) == 0 {
		return vm.ToValue("")
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json") || (ct == "" && json.Valid(body)):
		if parse, ok := goja.AssertFunction(vm.Get("JSON").ToObject(vm).Get("parse")); ok {
			if v, err := parse(goja.Undefined(), vm.ToValue(string(body))); err == nil {
				return v
			}
		}
	case strings.Contains(ct, "x-www-form-urlencoded"):
		values, err := url.ParseQuery(string(body))
		if err == nil {
			o := vm.NewObject()
			for k, vs := range values {
				if len(vs) > 0 {
					_ = o.Set(k, vs[0])
				}
			}
			return o
		}
	}
	return vm.ToValue(string(body))
}

func exported(o *goja.Object, key string) (any, bool) {
	v := o.Get(key)
	if v == nil || goja.IsUndefined(v) {
		return nil, false
	}
	if goja.IsNull(v) {
		return nil, true
	}
	return v.Export(), true
}

func absorbHeaders(o *goja.Object) (flow.Header, bool) {
	v := o.Get("headers")
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return flow.Header{}, false
	}
	ho, ok := v.(*goja.Object)
	if !ok {
		return flow.Header{}, false
	}
	var h flow.Header
	for _, k := range ho.Keys() {
		val := ho.Get(k)
		if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
			continue
		}
		if arr, ok := val.Export().([]any); ok {
			for _, x := range arr {
				h.Add(k, fmt.Sprint(x))
			}
			continue
		}
		h.Add(k, val.String())
	}
	return h, true
}

func absorbBody(o *goja.Object, contentType string) ([]byte, bool) {
	v, ok := exported(o, "body")
	if !ok {
		return nil, false
	}
	switch b := v.(type) {
	case nil:
		return []byte{}, true
	case string:
		return []byte(b), true
	case []byte:
		return b, true
	case goja.ArrayBuffer:
		return bytes.Clone(b.Bytes()), true
	case map[string]any:
		if strings.Contains(strings.ToLower(contentType), "x-www-form-urlencoded") {
			values := url.Values{}
			for k, x := range b {
				values.Set(k, fmt.Sprint(x))
			}
			return []byte(values.Encode()), true
		}
		out, _ := json.Marshal(b)
		return out, true
	default:
		out, _ := json.Marshal(b)
		return out, true
	}
}

func absorbRequest(vm *goja.Runtime, o *goja.Object, req *Request) {
	str := func(key string, dst *string) {
		if v, ok := exported(o, key); ok && v != nil {
			if s := fmt.Sprint(v); s != "" || key == "comment" || key == "color" {
				*dst = s
			}
		}
	}
	str("method", &req.Method)
	str("scheme", &req.Scheme)
	str("host", &req.Host)
	str("path", &req.Path)
	str("comment", &req.Comment)
	str("color", &req.Color)
	req.Method = strings.ToUpper(req.Method)
	if v, ok := exported(o, "port"); ok {
		switch p := v.(type) {
		case int64:
			req.Port = int(p)
		case float64:
			req.Port = int(p)
		case string:
			if n, err := strconv.Atoi(p); err == nil {
				req.Port = n
			}
		}
	}
	if v := o.Get("queries"); v != nil {
		if qo, ok := v.(*goja.Object); ok {
			values := url.Values{}
			for _, k := range qo.Keys() {
				x := qo.Get(k).Export()
				if arr, ok := x.([]any); ok {
					for _, e := range arr {
						values.Add(k, fmt.Sprint(e))
					}
				} else if x != nil {
					values.Set(k, fmt.Sprint(x))
				}
			}
			path, q, _ := strings.Cut(req.Path, "?")
			old, _ := url.ParseQuery(q)
			if values.Encode() != old.Encode() {
				req.Path = path
				if len(values) > 0 {
					req.Path += "?" + values.Encode()
				}
			}
		}
	}
	if h, ok := absorbHeaders(o); ok {
		req.Header = h
	}
	if body, ok := absorbBody(o, req.Header.Get("Content-Type")); ok {
		req.Body = body
	}
}

func absorbResponse(vm *goja.Runtime, o *goja.Object, resp *Response) {
	if v, ok := exported(o, "statusCode"); ok {
		switch c := v.(type) {
		case int64:
			resp.StatusCode = int(c)
		case float64:
			resp.StatusCode = int(c)
		}
	}
	if h, ok := absorbHeaders(o); ok {
		resp.Header = h
	}
	if path, ok := exported(o, "bodyFilePath"); ok && path != nil && fmt.Sprint(path) != "" {
		if b, err := os.ReadFile(expandHome(fmt.Sprint(path))); err == nil {
			resp.Body = b
			return
		}
	}
	if body, ok := absorbBody(o, resp.Header.Get("Content-Type")); ok {
		resp.Body = body
	}
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return home + "/" + rest
		}
	}
	return p
}

func (e *Engine) installRuntime(vm *goja.Runtime, name string) *sharedLease {
	installNatives(vm)
	_ = vm.Set("require", e.requireFunc(vm)(""))
	setEnv := func(env map[string]string) {
		for k, v := range env {
			if identifier.MatchString(k) {
				_ = vm.Set("$"+k, v)
			}
		}
	}
	if env, ok := e.environment(); ok {
		setEnv(env)
	}
	_ = vm.Set("_reloadEnv", func() {
		if _, ok := e.environment(); !ok {
			e.addLog(name, "warn", "Scripts may not read the environment: allow it in Scripting › Environment Variables.")
			return
		}
		setEnv(e.ReloadEnv())
	})
	logger := func(level string) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			parts := make([]string, len(call.Arguments))
			for i, a := range call.Arguments {
				if o, ok := a.(*goja.Object); ok && o.ClassName() != "Function" && o.ClassName() != "Error" {
					if b, err := json.Marshal(o.Export()); err == nil {
						parts[i] = string(b)
						continue
					}
				}
				parts[i] = a.String()
			}
			e.addLog(name, level, strings.Join(parts, " "))
			return goja.Undefined()
		}
	}
	console := vm.NewObject()
	_ = console.Set("log", logger("log"))
	_ = console.Set("info", logger("info"))
	_ = console.Set("debug", logger("debug"))
	_ = console.Set("warn", logger("warn"))
	_ = console.Set("error", logger("error"))
	_ = vm.Set("console", console)

	lease := &sharedLease{mu: &e.sharedMu}
	_ = vm.Set("sharedState", vm.NewDynamicObject(&sharedMap{vm: vm, l: lease, m: e.shared}))
	_ = vm.Set("sleep", func(ms int) {
		lease.release()
		time.Sleep(time.Duration(min(ms, 30000)) * time.Millisecond)
	})
	_ = vm.Set("readFromFile", func(path string) (string, error) {
		b, err := os.ReadFile(expandHome(path))
		return string(b), err
	})
	_ = vm.Set("writeToFile", func(content, path string) error {
		return os.WriteFile(expandHome(path), []byte(content), 0o644) // #nosec G306 -- a script writes the files its author asks for, like any program the user runs.
	})
	_ = vm.Set("btoa", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) })
	_ = vm.Set("atob", func(s string) (string, error) {
		b, err := base64.StdEncoding.DecodeString(s)
		return string(b), err
	})
	httpObj := vm.NewObject()
	_ = httpObj.Set("get", func(u string) (any, error) {
		lease.release()
		return httpJSON(http.MethodGet, u, nil)
	})
	_ = httpObj.Set("post", func(u string, body any) (any, error) {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		lease.release()
		return httpJSON(http.MethodPost, u, b)
	})
	_ = vm.Set("$http", httpObj)
	return lease
}

func httpJSON(method, u string, body []byte) (any, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var out any
	if json.Unmarshal(data, &out) == nil {
		return out, nil
	}
	return string(data), nil
}

var Snippets = []struct{ Name, Code string }{
	{"Change a header", `  request.headers["X-Debug"] = "1";`},
	{"Remove a header", `  delete request.headers["Cookie"];`},
	{"Add a query parameter", `  request.queries["debug"] = "true";`},
	{"Change the JSON body", `  request.body["name"] = "ProxyGo";`},
	{"Redirect to another host", "  request.host = \"localhost\";\n  request.port = 3000;\n  request.scheme = \"http\";"},
	{"Mock the response body", "  response.headers[\"Content-Type\"] = \"application/json\";\n  response.body = { mocked: true };"},
	{"Change the status code", `  response.statusCode = 500;`},
	{"Serve a local file", `  response.bodyFilePath = "~/Desktop/response.json";`},
	{"Log the URL", `  console.log(url);`},
	{"Keep a value between requests", "  sharedState.count = (sharedState.count || 0) + 1;\n  console.log(\"seen\", sharedState.count);"},
	{"Abort the request", `  context.abort();`},
}

const Template = `/// Runs before the request is sent to the server.
async function onRequest(context, url, request) {
  // console.log(request);
  // request.headers["X-New-Header"] = "ProxyGo";
  return request;
}

/// Runs before the response is sent to the client.
async function onResponse(context, url, request, response) {
  // response.headers["Content-Type"] = "application/json";
  // response.body = { mocked: true };
  return response;
}
`
