package mcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"proxygo/internal/control"
	"proxygo/internal/control/hosttest"
	"proxygo/internal/flow"
)

func connect(t *testing.T, s *Server) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	c, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func callTool(t *testing.T, c *mcp.ClientSession, name string, args any, wantErr bool) string {
	t.Helper()
	res, err := c.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, content := range res.Content {
		if tc, ok := content.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	if res.IsError != wantErr {
		t.Fatalf("%s: error %v, want %v: %s", name, res.IsError, wantErr, b.String())
	}
	return b.String()
}

func sampleFlow() *flow.Flow {
	f := flow.New("F1")
	start, end := 1700000000.0, 1700000000.25
	f.Timing = flow.Timing{RequestStartedAt: &start, ResponseEndedAt: &end}
	f.Client = flow.Client{Name: "Safari", PID: 42}
	f.Request = &flow.Request{Scheme: "https", Host: "api.dev", Port: 443, FullPath: "https://api.dev/login?api_key=k1&page=2", URI: "/login?api_key=k1&page=2",
		Method: flow.Method{Name: "POST"}, Header: flow.NewHeader(http.Header{"Authorization": {"Bearer secret-token"}, "Content-Type": {"application/json"}, "Cookie": {"s=1"}}),
		BodyData: flow.Blob(`{"user":"ada","password":"hunter2","usage":{"total_tokens":12}}`)}
	f.Response = &flow.Response{Status: &flow.Status{Code: 200, Phrase: "OK"}, Header: flow.NewHeader(http.Header{"Set-Cookie": {"t=2"}, "Content-Type": {"application/json"}}),
		BodyData: flow.Blob(`{"access_token":"abc","name":"Ada"}`)}
	return f
}

func TestTools(t *testing.T) {
	h, err := hosttest.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h.S.Upsert(sampleFlow())
	s := New(h, t.TempDir())
	c := connect(t, s)

	tools, err := c.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"get_flows", "get_flow_detail", "filter_flows", "create_map_local", "create_breakpoint", "clear_session", "send_compose_http", "list_rules", "toggle_tool"} {
		if !names[want] {
			t.Errorf("no tool %s", want)
		}
	}

	list := callTool(t, c, "get_flows", map[string]any{}, false)
	if !strings.Contains(list, `"id": "F1"`) || strings.Contains(list, "k1") || !strings.Contains(list, "page=2") {
		t.Errorf("get_flows redacts the query's secrets:\n%s", list)
	}
	detail := callTool(t, c, "get_flow_detail", map[string]any{"flow_id": "F1"}, false)
	for _, leak := range []string{"secret-token", "hunter2", `"s=1"`, `"t=2"`, "abc", "k1"} {
		if strings.Contains(detail, leak) {
			t.Errorf("get_flow_detail leaks %q:\n%s", leak, detail)
		}
	}
	for _, want := range []string{"Bearer <redacted>", `\"total_tokens\":12`, `"redacted": true`, `\"name\":\"Ada\"`} {
		if !strings.Contains(detail, want) {
			t.Errorf("get_flow_detail lacks %q:\n%s", want, detail)
		}
	}
	s.Redact = func() bool { return false }
	if d := callTool(t, c, "get_flow_detail", map[string]any{"flow_id": "F1"}, false); !strings.Contains(d, "secret-token") {
		t.Error("with redaction off, credentials show")
	}
	s.Redact = func() bool { return true }
	callTool(t, c, "get_flow_detail", map[string]any{"flow_id": "nope"}, true)

	if got := callTool(t, c, "filter_flows", map[string]any{"filters": []map[string]string{{"key": "statusCode", "value": "200", "matching": "equals"}, {"key": "host", "value": "api"}}}, false); !strings.Contains(got, `"matched": 1`) {
		t.Errorf("filter %s", got)
	}
	if got := callTool(t, c, "filter_flows", map[string]any{"filters": []map[string]string{{"key": "statusCode", "value": "404"}}}, false); !strings.Contains(got, `"matched": 0`) {
		t.Errorf("filter %s", got)
	}
	callTool(t, c, "filter_flows", map[string]any{"filters": []map[string]string{{"key": "nope", "value": "x"}}}, true)
	if curl := callTool(t, c, "export_flow_curl", map[string]any{"flow_id": "F1"}, false); !strings.HasPrefix(curl, "curl") || strings.Contains(curl, "secret-token") {
		t.Errorf("curl %s", curl)
	}

	callTool(t, c, "create_map_local", map[string]any{"url": "https://api.dev/users", "body": `[]`, "status_code": 201}, false)
	callTool(t, c, "create_breakpoint", map[string]any{"url": "https://api.dev/*", "phase": "request"}, false)
	callTool(t, c, "create_breakpoint", map[string]any{"url": "https://api.dev/*", "phase": "sometimes"}, true)
	callTool(t, c, "create_blacklist", map[string]any{"url": "ads.dev", "action": "block_and_hide"}, false)
	callTool(t, c, "create_scripting_rule", map[string]any{"url": "*", "script_content": "function onRequest( {"}, true)
	callTool(t, c, "create_map_local", map[string]any{"url": ""}, true)
	d := h.R.Current()
	if len(d.MapLocal) != 1 || d.MapLocal[0].StatusCode != 201 || len(d.Breakpoints) != 1 || len(d.Block) != 1 || d.Block[0].Action != "hide" {
		t.Fatalf("rules %+v", d)
	}
	rulesText := callTool(t, c, "list_rules", map[string]any{"rule_type": "map_local"}, false)
	if !strings.Contains(rulesText, d.MapLocal[0].ID) {
		t.Errorf("list_rules %s", rulesText)
	}
	callTool(t, c, "toggle_rule", map[string]any{"rule_type": "map_local", "id": d.MapLocal[0].ID, "enabled": false}, false)
	callTool(t, c, "delete_rule", map[string]any{"rule_type": "breakpoint", "id": d.Breakpoints[0].ID}, false)
	callTool(t, c, "toggle_tool", map[string]any{"tool": "scripting", "enabled": false}, false)
	callTool(t, c, "enable_ssl_proxying", map[string]any{"domain": "https://api.dev/x"}, false)
	d = h.R.Current()
	if d.MapLocal[0].Enabled || len(d.Breakpoints) != 0 || d.ToolOn("scripting") || !d.ShouldMITM("api.dev") {
		t.Errorf("after the changes %+v", d)
	}
	callTool(t, c, "clear_session", map[string]any{}, false)
	if h.S.Len() != 0 {
		t.Error("clear_session")
	}
}

func TestComposeTools(t *testing.T) {
	h, err := hosttest.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(r.Method + " " + r.Header.Get("X-Test")))
	}))
	defer ts.Close()
	c := connect(t, New(h, t.TempDir()))
	out := callTool(t, c, "create_compose_http", map[string]any{"url": ts.URL + "/x", "method": "post", "headers": map[string]string{"X-Test": "1"}}, false)
	var draft struct {
		ID string `json:"compose_id"`
	}
	json.Unmarshal([]byte(out), &draft)
	callTool(t, c, "update_compose_http", map[string]any{"compose_id": draft.ID, "headers": map[string]string{"X-Test": "2"}}, false)
	sent := callTool(t, c, "send_compose_http", map[string]any{"compose_id": draft.ID}, false)
	if !strings.Contains(sent, `"body": "POST 2"`) {
		t.Errorf("sent %s", sent)
	}
	callTool(t, c, "create_compose_http", map[string]any{"url": "ftp://x"}, true)
	callTool(t, c, "send_compose_http", map[string]any{"compose_id": "nope"}, true)
}

func TestSocketAndHTTP(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pgm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	h, _ := hosttest.New(t.TempDir())
	s := New(h, dir)
	if err := s.Start(true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(HandshakePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var hs Handshake
	json.Unmarshal(b, &hs)
	if fi, _ := os.Stat(HandshakePath(dir)); fi.Mode().Perm() != 0o600 || !strings.HasPrefix(hs.URL, "http://127.0.0.1:") || len(hs.Token) != 64 {
		t.Fatalf("handshake %+v", hs)
	}
	req, _ := http.NewRequest(http.MethodPost, hs.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("without the token: %v %v", resp, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	httpClient := &http.Client{Transport: bearer{hs.Token}}
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: hs.URL, HTTPClient: httpClient}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st := callTool(t, cs, "get_proxy_status", map[string]any{}, false); !strings.Contains(st, `"version": "test"`) {
		t.Errorf("status %s", st)
	}
	cs.Close()

	conn, err := net.Dial("unix", control.MCPSocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	us, err := client.Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := callTool(t, us, "get_version", map[string]any{}, false); !strings.Contains(v, "test") {
		t.Errorf("version %s", v)
	}
	s.Stop()
	if _, err := os.Stat(HandshakePath(dir)); !os.IsNotExist(err) {
		t.Error("the handshake file outlived the server")
	}
	if _, err := os.Stat(control.MCPSocketPath(dir)); !os.IsNotExist(err) {
		t.Error("the socket outlived the server")
	}
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
