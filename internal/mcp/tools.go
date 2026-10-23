package mcp

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"proxygo/internal/codegen"
	"proxygo/internal/control"
	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/store"
)

type FlowSummary struct {
	ID           string   `json:"id"`
	Number       string   `json:"number"`
	Method       string   `json:"method"`
	URL          string   `json:"url"`
	Status       int      `json:"status,omitempty"`
	StatusText   string   `json:"statusText"`
	DurationMS   float64  `json:"durationMs,omitempty"`
	RequestSize  int      `json:"requestSize"`
	ResponseSize int      `json:"responseSize"`
	ContentType  string   `json:"contentType,omitempty"`
	Client       string   `json:"client,omitempty"`
	ClientPID    int      `json:"clientPid,omitempty"`
	HTTPVersion  string   `json:"requestHttpVersion,omitempty"`
	StartedAt    string   `json:"startedAt,omitempty"`
	Error        string   `json:"error,omitempty"`
	Comment      string   `json:"comment,omitempty"`
	Color        string   `json:"color,omitempty"`
	Tools        []string `json:"tools,omitempty"`
	WebSocket    bool     `json:"websocket,omitempty"`
	Encrypted    bool     `json:"encryptedTunnel,omitempty"`
}

func (s *Server) summary(f *flow.Flow) FlowSummary {
	u := f.URL()
	if s.Redact() {
		u, _ = redactURL(u)
	}
	out := FlowSummary{
		ID: f.UniqueID, Number: f.ID, Method: f.MethodName(), URL: u, Status: f.StatusCode(), StatusText: f.StatusLine(),
		DurationMS: float64(f.Duration().Microseconds()) / 1000, RequestSize: f.RequestSize(), ResponseSize: f.ResponseSize(),
		ContentType: f.MIME(), Client: f.Client.Name, HTTPVersion: f.HTTPVersionLabel(), Error: f.ErrorText(),
		Comment: f.Comment, Color: f.Highlight, WebSocket: f.IsWebSocket(), Encrypted: f.IsTunnel(),
	}
	if f.Client.PID > 0 {
		out.ClientPID = f.Client.PID
	}
	if t := f.RequestTime(); !t.IsZero() {
		out.StartedAt = t.UTC().Format(time.RFC3339Nano)
	}
	if m, ok := f.ToolMetadata.(map[string]any); ok {
		for k := range m {
			out.Tools = append(out.Tools, k)
		}
		sort.Strings(out.Tools)
	}
	return out
}

type Message struct {
	Headers      [][2]string `json:"headers"`
	Body         string      `json:"body,omitempty"`
	BodyEncoding string      `json:"bodyEncoding,omitempty"`
	BodySize     int         `json:"bodySize"`
	Truncated    bool        `json:"bodyTruncated,omitempty"`
	Status       int         `json:"status,omitempty"`
}

type FlowDetail struct {
	FlowSummary
	Query    [][2]string       `json:"query,omitempty"`
	Request  Message           `json:"request"`
	Response *Message          `json:"response,omitempty"`
	Timing   map[string]any    `json:"timing,omitempty"`
	TLS      *flow.TLSDetails  `json:"tls,omitempty"`
	Server   string            `json:"serverAddress,omitempty"`
	Redacted bool              `json:"redacted"`
	Messages int               `json:"websocketMessages,omitempty"`
	Metadata map[string]any    `json:"toolMetadata,omitempty"`
	Extra    map[string]string `json:"notes,omitempty"`
}

func (s *Server) message(h flow.Header, body []byte, ct string, limit int, binary bool, redacted *bool) Message {
	if s.Redact() {
		var changed bool
		h, changed = redactHeader(h)
		*redacted = *redacted || changed
		body, changed = redactBody(body, ct)
		*redacted = *redacted || changed
	}
	m := Message{BodySize: len(body), Headers: [][2]string{}}
	for _, e := range h.Entries {
		if e.Enabled {
			m.Headers = append(m.Headers, [2]string{e.Key.Name, e.Value})
		}
	}
	if len(body) > limit {
		// Cut before a character the limit would split, so a text body
		// still reads as text.
		cut := limit
		for i := 0; i < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(body[cut]); i++ {
			cut--
		}
		if !utf8.RuneStart(body[cut]) {
			cut = limit
		}
		body, m.Truncated = body[:cut], true
	}
	switch {
	case len(body) == 0:
	case utf8.Valid(body):
		m.Body = string(body)
	case binary:
		m.Body, m.BodyEncoding = base64.StdEncoding.EncodeToString(body), "base64"
	default:
		m.Body = fmt.Sprintf("<%d bytes of binary data: ask with include_binary to get them in base64>", m.BodySize)
	}
	return m
}

func (s *Server) detail(f *flow.Flow, limit int, binary bool) FlowDetail {
	d := FlowDetail{FlowSummary: s.summary(f), TLS: f.TLS, Server: f.Summary.ServerIPAddress}
	for _, q := range f.QueryItems() {
		if s.Redact() && sensitiveKey.MatchString(q[0]) {
			q[1], d.Redacted = redacted, true
		}
		d.Query = append(d.Query, q)
	}
	d.Request = s.message(f.Request.Header, f.DecodedRequestBody(), f.Request.Header.Get("Content-Type"), limit, binary, &d.Redacted)
	if f.Response != nil && f.Response.Status != nil && !f.IsError() {
		m := s.message(f.Response.Header, f.DecodedResponseBody(), f.Response.Header.Get("Content-Type"), limit, binary, &d.Redacted)
		m.Status = f.StatusCode()
		d.Response = &m
	}
	d.Timing = timing(f)
	if f.WebSocketMessageStorage != nil {
		d.Messages = len(f.WebSocketMessageStorage.Messages)
	}
	if m, ok := f.ToolMetadata.(map[string]any); ok {
		d.Metadata = m
	}
	if f.ConnectionRecord != nil && f.ConnectionRecord.Exchange.Truncated {
		d.Extra = map[string]string{"truncated": "ProxyGo kept only the start of a body larger than 64 MB"}
	}
	return d
}

func timing(f *flow.Flow) map[string]any {
	t := f.Timing
	if t.RequestStartedAt == nil {
		return nil
	}
	start := *t.RequestStartedAt
	out := map[string]any{"startedAt": time.Unix(0, int64(start*1e9)).UTC().Format(time.RFC3339Nano)}
	phase := func(name string, a, b *float64) {
		if a != nil && b != nil && *b >= *a {
			out[name] = map[string]float64{"startMs": (*a - start) * 1000, "durationMs": (*b - *a) * 1000}
		}
	}
	phase("clientTLS", t.ClientTLSStartedAt, t.ClientTLSEndedAt)
	phase("connect", t.UpstreamConnectStartedAt, t.UpstreamConnectEndedAt)
	phase("serverTLS", t.UpstreamTLSStartedAt, t.UpstreamTLSEndedAt)
	phase("requestSent", t.RequestStartedAt, t.RequestEndedAt)
	phase("waiting", t.RequestEndedAt, t.ResponseStartedAt)
	phase("download", t.ResponseStartedAt, t.ResponseEndedAt)
	if d := f.Duration(); d > 0 {
		out["totalMs"] = float64(d.Microseconds()) / 1000
	}
	out["reusedConnection"] = f.ConnectionRecord != nil && f.ConnectionRecord.Exchange.Reused
	return out
}

func (s *Server) flow(id string) (*flow.Flow, error) {
	if f, ok := s.host.Store().Lookup(id); ok {
		return f, nil
	}
	for _, f := range s.host.Store().Snapshot() {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, errNotFound
}

type (
	noInput   struct{}
	flowInput struct {
		FlowID string `json:"flow_id" jsonschema:"a flow's id, from get_flows"`
	}
	getFlowsInput struct {
		Limit      int    `json:"limit,omitempty" jsonschema:"how many flows, newest first: 50 when left out, 500 at most"`
		HostFilter string `json:"host_filter,omitempty" jsonschema:"only flows to this host, or its subdomains"`
		Offset     int    `json:"offset,omitempty" jsonschema:"flows to skip, newest first, to page"`
	}
	filterInput struct {
		Filters     []filterParam `json:"filters" jsonschema:"conditions on the flows"`
		Combination string        `json:"combination,omitempty" jsonschema:"AND (every condition, the default) or OR (any)"`
		Limit       int           `json:"limit,omitempty" jsonschema:"how many flows, newest first: 50 when left out"`
	}
	filterParam struct {
		Key      string `json:"key" jsonschema:"url, host, path, query, method, statusCode, client, contentType, requestHeader, responseHeader, requestBody, responseBody, graphql, comment, duration (ms) or responseSize (bytes)"`
		Value    string `json:"value" jsonschema:"what to compare with"`
		Matching string `json:"matching,omitempty" jsonschema:"contains (the default), notContains, equals, notEquals, startsWith, endsWith, regex, greaterThan or lessThan"`
	}
	detailInput struct {
		FlowID        string `json:"flow_id" jsonschema:"a flow's id, from get_flows"`
		MaxBodyBytes  int    `json:"max_body_bytes,omitempty" jsonschema:"bytes of each body to return: 65536 when left out, 1048576 at most"`
		IncludeBinary bool   `json:"include_binary,omitempty" jsonschema:"return binary bodies in base64"`
	}
	timingInput struct {
		FlowIDs []string `json:"flow_ids,omitempty" jsonschema:"the flows; the rows selected in ProxyGo when left out"`
	}
	wsMessagesInput struct {
		FlowID          string `json:"flow_id" jsonschema:"a WebSocket flow's id"`
		Direction       string `json:"direction,omitempty" jsonschema:"client or server; both when left out"`
		IncludePingPong bool   `json:"include_ping_pong,omitempty" jsonschema:"include ping and pong frames"`
		Limit           int    `json:"limit,omitempty" jsonschema:"the last N messages: 100 when left out"`
	}
	codeInput struct {
		FlowID   string `json:"flow_id" jsonschema:"a flow's id"`
		Language string `json:"language,omitempty" jsonschema:"one of the languages of ProxyGo's code generator, as cURL, Python (requests), Go (net/http), Swift (URLSession): cURL when left out"`
	}
	exportInput struct {
		Path    string   `json:"path" jsonschema:"an absolute path for the file, which must not exist"`
		Format  string   `json:"format,omitempty" jsonschema:"har (the default), proxygosession, postman, openapi, csv or raw"`
		FlowIDs []string `json:"flow_ids,omitempty" jsonschema:"the flows; every flow when left out"`
	}
	ruleTypeInput struct {
		RuleType string `json:"rule_type,omitempty" jsonschema:"map_local, map_remote, breakpoint, blacklist, allow_list, scripting, network_condition, dns_spoofing, reverse_proxy, ssl_proxying or protobuf; every type when left out"`
	}
	ruleInput struct {
		RuleType string `json:"rule_type" jsonschema:"the rule's type, as list_rules names it"`
		ID       string `json:"id" jsonschema:"the rule's id, from list_rules"`
	}
	toggleRuleInput struct {
		RuleType string `json:"rule_type" jsonschema:"the rule's type, as list_rules names it"`
		ID       string `json:"id" jsonschema:"the rule's id, from list_rules"`
		Enabled  bool   `json:"enabled" jsonschema:"on or off"`
	}
	toggleToolInput struct {
		Tool    string `json:"tool" jsonschema:"map_local, map_remote, breakpoint, scripting, blacklist, allow_list, network_condition, dns_spoofing, reverse_proxy, ssl_proxying or no_caching"`
		Enabled bool   `json:"enabled" jsonschema:"on or off"`
	}
	enabledInput struct {
		Enabled bool `json:"enabled" jsonschema:"on or off"`
	}
	domainInput struct {
		Domain string `json:"domain" jsonschema:"a host, as api.example.com, or a wildcard, as *.example.com"`
	}
	httpModeInput struct {
		Mode string `json:"mode" jsonschema:"http1_only or prefer_http2"`
	}
	matcherInput struct {
		URL    string `json:"url" jsonschema:"the URL to match: * matches anything, ? one character; a URL without a scheme matches http and https"`
		Method string `json:"method,omitempty" jsonschema:"an HTTP method; any when left out"`
		Regex  bool   `json:"regex,omitempty" jsonschema:"url is a regular expression"`
		Name   string `json:"name,omitempty" jsonschema:"the rule's name"`
	}
	mapLocalInput struct {
		matcherInput
		StatusCode  int               `json:"status_code,omitempty" jsonschema:"the response's status: 200 when left out"`
		Body        string            `json:"body,omitempty" jsonschema:"the response's body"`
		Headers     map[string]string `json:"headers,omitempty" jsonschema:"the response's headers"`
		ContentType string            `json:"content_type,omitempty" jsonschema:"the response's content type, found from the body when left out"`
		FilePath    string            `json:"file_path,omitempty" jsonschema:"an absolute path of a file or folder to answer with, instead of body"`
		DelayMS     int               `json:"delay_ms,omitempty" jsonschema:"milliseconds to wait before answering"`
	}
	mapRemoteInput struct {
		matcherInput
		ToURL        string `json:"to_url" jsonschema:"where matching requests go instead; a URL of only a host keeps their path and query"`
		PreserveHost bool   `json:"preserve_host,omitempty" jsonschema:"keep the original Host header"`
	}
	breakpointInput struct {
		matcherInput
		Phase string `json:"phase,omitempty" jsonschema:"request, response or both (the default)"`
	}
	blockInput struct {
		matcherInput
		Action string `json:"action,omitempty" jsonschema:"block (answer 403, the default) or block_and_hide (drop the connection)"`
	}
	scriptInput struct {
		matcherInput
		ScriptContent  string `json:"script_content" jsonschema:"the JavaScript: async function onRequest(context, url, request) { …; return request; } and async function onResponse(context, url, request, response) { …; return response; }. Read the proxygo://docs/scripting resource first"`
		EnableRequest  *bool  `json:"enable_request,omitempty" jsonschema:"run onRequest: true when left out"`
		EnableResponse *bool  `json:"enable_response,omitempty" jsonschema:"run onResponse: true when left out"`
		MockResponse   bool   `json:"mock_response,omitempty" jsonschema:"answer from onResponse without sending the request to the server"`
	}
	dnsInput struct {
		Host string `json:"host" jsonschema:"the host, as api.example.com; it covers its subdomains"`
		IP   string `json:"ip" jsonschema:"the address it resolves to"`
		Port int    `json:"port,omitempty" jsonschema:"a port to connect to instead"`
	}
	networkInput struct {
		matcherInput
		Profile      string  `json:"profile,omitempty" jsonschema:"a preset: 100% Loss, Edge, 3G, Slow 4G, LTE, Very Bad Network, Wi-Fi or High Latency DNS"`
		LatencyMS    int     `json:"latency_ms,omitempty" jsonschema:"latency, instead of a preset's"`
		DownloadKBps float64 `json:"download_kbps,omitempty" jsonschema:"download bandwidth, in KB/s"`
		UploadKBps   float64 `json:"upload_kbps,omitempty" jsonschema:"upload bandwidth, in KB/s"`
		PacketLoss   float64 `json:"packet_loss,omitempty" jsonschema:"percent of requests that fail"`
	}
	composeInput struct {
		Method  string            `json:"method,omitempty" jsonschema:"GET when left out"`
		URL     string            `json:"url" jsonschema:"the request's http or https URL"`
		Headers map[string]string `json:"headers,omitempty"`
		Body    string            `json:"body,omitempty"`
	}
	composeIDInput struct {
		ComposeID string `json:"compose_id" jsonschema:"a draft's id, from create_compose_http"`
	}
	updateComposeInput struct {
		ComposeID string            `json:"compose_id" jsonschema:"a draft's id"`
		Method    string            `json:"method,omitempty"`
		URL       string            `json:"url,omitempty"`
		Headers   map[string]string `json:"headers,omitempty" jsonschema:"headers to set; an empty value removes one"`
		Body      *string           `json:"body,omitempty"`
	}
	sendComposeInput struct {
		ComposeID       string `json:"compose_id" jsonschema:"a draft's id"`
		TimeoutSeconds  int    `json:"timeout_seconds,omitempty" jsonschema:"seconds before the request fails: 60 when left out"`
		FollowRedirects bool   `json:"follow_redirects,omitempty" jsonschema:"follow redirects, recording each hop"`
	}
)

func readOnly(name, title, desc string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc, Annotations: &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, OpenWorldHint: new(false)}}
}

func change(name, title, desc string, destructive bool) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc, Annotations: &mcp.ToolAnnotations{Title: title, DestructiveHint: new(destructive), OpenWorldHint: new(false)}}
}

func (s *Server) addTools() {
	srv := s.srv
	mcp.AddTool(srv, readOnly("get_version", "Version", "ProxyGo's version."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		return jsonText(map[string]string{"name": "ProxyGo", "version": s.host.Version()})
	})
	mcp.AddTool(srv, readOnly("get_proxy_status", "Proxy Status", "Whether ProxyGo records, where it listens, whether macOS uses it, whether SSL Proxying decrypts HTTPS, and its HTTP version mode."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		return jsonText(control.StatusOf(s.host))
	})
	mcp.AddTool(srv, readOnly("get_flows", "Flows", "The flows ProxyGo recorded, newest first: method, URL, status, duration, sizes, client app, comment, color and the tools that changed them. Read one with get_flow_detail."), func(_ context.Context, _ *mcp.CallToolRequest, in getFlowsInput) (*mcp.CallToolResult, any, error) {
		flows := s.host.Store().Snapshot()
		var out []FlowSummary
		skip := max(in.Offset, 0)
		limit := clamp(in.Limit, 50, 500)
		for i := len(flows) - 1; i >= 0 && len(out) < limit; i-- {
			f := flows[i]
			if in.HostFilter != "" && !rules.HostMatch(in.HostFilter, f.Host()) {
				continue
			}
			if skip > 0 {
				skip--
				continue
			}
			out = append(out, s.summary(f))
		}
		return jsonText(map[string]any{"total": len(flows), "flows": orEmpty(out)})
	})
	mcp.AddTool(srv, readOnly("filter_flows", "Filter Flows", "Flows matching conditions, as ProxyGo's advanced filter: all of them (AND) or any (OR), newest first."), func(_ context.Context, _ *mcp.CallToolRequest, in filterInput) (*mcp.CallToolResult, any, error) {
		filter := store.Filter{Any: strings.EqualFold(in.Combination, "OR")}
		for _, p := range in.Filters {
			c, err := condition(p)
			if err != nil {
				return nil, nil, err
			}
			filter.Conditions = append(filter.Conditions, c)
		}
		flows := store.Apply(s.host.Store().Snapshot(), filter)
		var out []FlowSummary
		for i := len(flows) - 1; i >= 0 && len(out) < clamp(in.Limit, 50, 500); i-- {
			out = append(out, s.summary(flows[i]))
		}
		return jsonText(map[string]any{"matched": len(flows), "flows": orEmpty(out)})
	})
	mcp.AddTool(srv, readOnly("get_flow_detail", "Flow Detail", "A flow's request and response: headers, query, bodies (decoded), timing, TLS, client and the tools that changed it."), func(_ context.Context, _ *mcp.CallToolRequest, in detailInput) (*mcp.CallToolResult, any, error) {
		f, err := s.flow(in.FlowID)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(s.detail(f, clamp(in.MaxBodyBytes, 64<<10, 1<<20), in.IncludeBinary))
	})
	mcp.AddTool(srv, readOnly("get_flow_timing", "Flow Timing", "The phases of flows, in milliseconds from each one's start: client TLS, connecting, server TLS, sending, waiting for the server, downloading."), func(_ context.Context, _ *mcp.CallToolRequest, in timingInput) (*mcp.CallToolResult, any, error) {
		flows, err := s.flowsOrSelected(in.FlowIDs)
		if err != nil {
			return nil, nil, err
		}
		out := map[string]any{}
		for _, f := range flows {
			out[f.UniqueID] = timing(f)
		}
		return jsonText(out)
	})
	mcp.AddTool(srv, readOnly("get_traffic_overview", "Traffic Overview", "A summary of the session: flows, statuses, errors, data, durations, top hosts and apps, and the HTTPS hosts not decrypted."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		return jsonText(overview(s.host.Store().Snapshot()))
	})
	mcp.AddTool(srv, readOnly("list_websocket_sessions", "WebSocket Sessions", "The WebSocket flows, and whether each is still open."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		var out []map[string]any
		for _, f := range s.host.Store().Snapshot() {
			if !f.IsWebSocket() {
				continue
			}
			n := 0
			if f.WebSocketMessageStorage != nil {
				n = len(f.WebSocketMessageStorage.Messages)
			}
			out = append(out, map[string]any{"flow": s.summary(f), "messages": n, "open": s.host.Proxy().WebSocketOpen(f.UniqueID)})
		}
		return jsonText(orEmpty(out))
	})
	mcp.AddTool(srv, readOnly("get_websocket_messages", "WebSocket Messages", "A WebSocket flow's messages, the last ones, by direction, without ping and pong unless asked."), func(_ context.Context, _ *mcp.CallToolRequest, in wsMessagesInput) (*mcp.CallToolResult, any, error) {
		f, err := s.flow(in.FlowID)
		if err != nil {
			return nil, nil, err
		}
		if !f.IsWebSocket() {
			return nil, nil, errors.New("not a WebSocket flow")
		}
		var msgs []map[string]any
		if f.WebSocketMessageStorage != nil {
			for _, m := range f.WebSocketMessageStorage.Messages {
				if !in.IncludePingPong && (m.Type == "ping" || m.Type == "pong") || in.Direction != "" && !strings.EqualFold(m.From, in.Direction) {
					continue
				}
				data := m.Data
				if m.Type == "binary" {
					data = base64.StdEncoding.EncodeToString(m.RawData)
				} else if s.Redact() {
					if b, changed := redactBody([]byte(data), "application/json"); changed {
						data = string(b)
					}
				}
				msgs = append(msgs, map[string]any{"from": m.From, "type": m.Type, "data": data, "closeCode": m.CloseCode,
					"time": time.Unix(0, int64(m.Time*1e9)).UTC().Format(time.RFC3339Nano), "sentByProxyGo": m.Injected})
			}
		}
		if n := clamp(in.Limit, 100, 10000); len(msgs) > n {
			msgs = msgs[len(msgs)-n:]
		}
		return jsonText(map[string]any{"messages": orEmpty(msgs)})
	})
	mcp.AddTool(srv, readOnly("export_flow_curl", "Copy as cURL", "A flow's request as a curl command."), func(_ context.Context, _ *mcp.CallToolRequest, in flowInput) (*mcp.CallToolResult, any, error) {
		f, err := s.flow(in.FlowID)
		if err != nil {
			return nil, nil, err
		}
		return text("%s", codegen.Curl(s.codeRequest(f)))
	})
	mcp.AddTool(srv, readOnly("generate_code", "Generate Code", "A flow's request as code in a language of ProxyGo's code generator."), func(_ context.Context, _ *mcp.CallToolRequest, in codeInput) (*mcp.CallToolResult, any, error) {
		f, err := s.flow(in.FlowID)
		if err != nil {
			return nil, nil, err
		}
		lang := cmp.Or(in.Language, "cURL")
		if !slices.ContainsFunc(codegen.Languages, func(l codegen.Language) bool { return l.Name == lang }) {
			var names []string
			for _, l := range codegen.Languages {
				names = append(names, l.Name)
			}
			return nil, nil, fmt.Errorf("unknown language %q: use one of %s", lang, strings.Join(names, ", "))
		}
		return text("%s", codegen.Named(lang)(s.codeRequest(f)))
	})
	mcp.AddTool(srv, change("export_flows", "Export Flows", "Write flows to a new file: HAR, a ProxyGo session, a Postman collection, an OpenAPI document, CSV or raw HTTP. Credentials are written as they were captured.", false), func(_ context.Context, _ *mcp.CallToolRequest, in exportInput) (*mcp.CallToolResult, any, error) {
		if !filepath.IsAbs(in.Path) {
			return nil, nil, errors.New("the path must be absolute")
		}
		if _, err := filepathStat(in.Path); err == nil {
			return nil, nil, errors.New("a file is there already: choose another path")
		}
		flows := s.host.Store().Snapshot()
		if len(in.FlowIDs) > 0 {
			var err error
			if flows, err = s.flowsOrSelected(in.FlowIDs); err != nil {
				return nil, nil, err
			}
		}
		if err := s.host.Export(in.Path, cmp.Or(in.Format, "har"), flows); err != nil {
			return nil, nil, err
		}
		return text("Wrote %d flows to %s", len(flows), in.Path)
	})
	mcp.AddTool(srv, readOnly("get_ssl_proxying_list", "SSL Proxying List", "Whether SSL Proxying is on, and the hosts it decrypts and leaves alone."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		d := s.host.Rules().Current()
		include, exclude := []string{}, []string{}
		for _, r := range d.SSL.Rules {
			if !r.Enabled {
				continue
			}
			if r.List == "exclude" {
				exclude = append(exclude, r.Target)
			} else {
				include = append(include, r.Target)
			}
		}
		return jsonText(map[string]any{"enabled": d.SSL.Enabled, "include": include, "exclude": exclude})
	})
	mcp.AddTool(srv, readOnly("list_rules", "Rules", "The debugging tools' rules with their IDs, for toggle_rule and delete_rule."), func(_ context.Context, _ *mcp.CallToolRequest, in ruleTypeInput) (*mcp.CallToolResult, any, error) {
		out := map[string]any{}
		for name, tool := range ruleTypes {
			if in.RuleType != "" && in.RuleType != name {
				continue
			}
			l, err := control.RuleCall(s.host.Rules(), "list", tool, "", nil)
			if err != nil {
				return nil, nil, err
			}
			out[name] = l
		}
		if len(out) == 0 {
			return nil, nil, fmt.Errorf("unknown rule type %q", in.RuleType)
		}
		return jsonText(out)
	})
	mcp.AddTool(srv, readOnly("list_tool_status", "Tool Status", "Which debugging tools are on."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		return jsonText(control.ToolStatus(s.host.Rules().Current()))
	})
	mcp.AddTool(srv, readOnly("get_certificate_status", "Certificate Status", "ProxyGo's root certificate: its name, fingerprint, expiry, and whether this Mac trusts it."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		c := s.host.Certs()
		if c == nil {
			return nil, nil, errors.New("ProxyGo has no certificate authority")
		}
		return jsonText(map[string]any{"name": c.CommonName(), "sha256": c.Fingerprint(), "expires": c.NotAfter().UTC().Format(time.RFC3339), "trustedOnThisMac": c.Trusted(), "path": c.CertPath()})
	})
	mcp.AddTool(srv, readOnly("get_system_proxy_status", "System Proxy", "Whether macOS sends its traffic to ProxyGo."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		return jsonText(map[string]bool{"systemProxyOverridden": s.host.SystemProxy()})
	})
	mcp.AddTool(srv, readOnly("get_http_version_mode", "HTTP Version Mode", "The HTTP version policy: http1_only, or prefer_http2, which falls back to HTTP/1.1."), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		return jsonText(map[string]string{"mode": s.host.Rules().Current().HTTPVersionMode()})
	})

	mcp.AddTool(srv, change("set_http_version_mode", "Set HTTP Version Mode", "Change the HTTP version policy; open connections close, so new ones negotiate anew.", false), func(_ context.Context, _ *mcp.CallToolRequest, in httpModeInput) (*mcp.CallToolResult, any, error) {
		_, err := control.Call(s.host, "http.version.set", mustJSON(map[string]string{"mode": in.Mode}))
		if err != nil {
			return nil, nil, err
		}
		return text("HTTP version mode: %s", in.Mode)
	})
	mcp.AddTool(srv, change("toggle_recording", "Recording", "Pause or resume recording; traffic still flows while paused.", false), func(_ context.Context, _ *mcp.CallToolRequest, in enabledInput) (*mcp.CallToolResult, any, error) {
		s.host.SetRecording(in.Enabled)
		return text("Recording: %v", in.Enabled)
	})
	mcp.AddTool(srv, change("clear_session", "Clear Session", "Remove every flow of the session. It cannot be undone.", true), func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
		s.host.ClearSession()
		return text("Cleared the session")
	})
	mcp.AddTool(srv, change("set_system_proxy", "System Proxy", "Point macOS at ProxyGo, or give it back the proxy it had; macOS asks the user for an administrator's password.", false), func(_ context.Context, _ *mcp.CallToolRequest, in enabledInput) (*mcp.CallToolResult, any, error) {
		if err := s.host.SetSystemProxy(in.Enabled); err != nil {
			return nil, nil, err
		}
		return text("macOS proxy overridden: %v", in.Enabled)
	})
	mcp.AddTool(srv, change("toggle_tool", "Toggle Tool", "Switch a debugging tool on or off as a whole, keeping its rules.", false), func(_ context.Context, _ *mcp.CallToolRequest, in toggleToolInput) (*mcp.CallToolResult, any, error) {
		name, ok := toolNames[in.Tool]
		if !ok {
			return nil, nil, fmt.Errorf("unknown tool %q", in.Tool)
		}
		if err := control.SetTool(s.host.Rules(), name, in.Enabled); err != nil {
			return nil, nil, err
		}
		return text("%s: %v", in.Tool, in.Enabled)
	})
	mcp.AddTool(srv, change("toggle_no_caching", "No Caching", "Strip caching headers so every request reaches the server, or stop.", false), func(_ context.Context, _ *mcp.CallToolRequest, in enabledInput) (*mcp.CallToolResult, any, error) {
		if err := control.SetTool(s.host.Rules(), "no-caching", in.Enabled); err != nil {
			return nil, nil, err
		}
		return text("No Caching: %v", in.Enabled)
	})
	mcp.AddTool(srv, change("enable_ssl_proxying", "Enable SSL Proxying", "Decrypt a host's HTTPS from now on; its clients must trust ProxyGo's certificate. Connections already open stay encrypted.", false), func(_ context.Context, _ *mcp.CallToolRequest, in domainInput) (*mcp.CallToolResult, any, error) {
		host := domainOf(in.Domain)
		if host == "" {
			return nil, nil, errors.New("enter a domain")
		}
		s.host.Rules().Update(func(d *rules.Data) {
			d.SSL.Enabled = true
			for _, r := range d.SSL.Rules {
				if strings.EqualFold(r.Target, host) {
					r.Enabled, r.List = true, "include"
					return
				}
			}
			d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: rules.NewID(), Enabled: true, List: "include", Target: host, TargetType: "domain"})
		})
		return text("SSL Proxying decrypts %s", host)
	})
	mcp.AddTool(srv, change("disable_ssl_proxying", "Disable SSL Proxying", "Stop decrypting a host, keeping it on the list, switched off.", false), func(_ context.Context, _ *mcp.CallToolRequest, in domainInput) (*mcp.CallToolResult, any, error) {
		host := domainOf(in.Domain)
		found := false
		s.host.Rules().Update(func(d *rules.Data) {
			for _, r := range d.SSL.Rules {
				if strings.EqualFold(r.Target, host) && r.List != "exclude" {
					r.Enabled, found = false, true
				}
			}
		})
		if !found {
			return nil, nil, fmt.Errorf("%s is not on the SSL Proxying List", host)
		}
		return text("SSL Proxying no longer decrypts %s", host)
	})
	mcp.AddTool(srv, change("toggle_rule", "Toggle Rule", "Switch one rule on or off.", false), func(_ context.Context, _ *mcp.CallToolRequest, in toggleRuleInput) (*mcp.CallToolResult, any, error) {
		tool, ok := ruleTypes[in.RuleType]
		if !ok {
			return nil, nil, fmt.Errorf("unknown rule type %q", in.RuleType)
		}
		op := map[bool]string{true: "enable", false: "disable"}[in.Enabled]
		r, err := control.RuleCall(s.host.Rules(), op, tool, in.ID, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(r)
	})
	mcp.AddTool(srv, change("delete_rule", "Delete Rule", "Delete one rule. It cannot be undone.", true), func(_ context.Context, _ *mcp.CallToolRequest, in ruleInput) (*mcp.CallToolResult, any, error) {
		tool, ok := ruleTypes[in.RuleType]
		if !ok {
			return nil, nil, fmt.Errorf("unknown rule type %q", in.RuleType)
		}
		if _, err := control.RuleCall(s.host.Rules(), "delete", tool, in.ID, nil); err != nil {
			return nil, nil, err
		}
		return text("Deleted %s %s", in.RuleType, in.ID)
	})
	mcp.AddTool(srv, change("create_map_local", "Create Map Local", "Answer matching requests with a response written here, or a local file, without the server.", false), func(_ context.Context, _ *mcp.CallToolRequest, in mapLocalInput) (*mcp.CallToolResult, any, error) {
		r := &rules.MapLocalRule{ID: rules.NewID(), Enabled: true, Name: cmp.Or(in.Name, "MCP Map Local"), Matcher: in.matcher(), StatusCode: cmp.Or(in.StatusCode, 200),
			ContentType: in.ContentType, Body: in.Body, Path: in.FilePath, DelayMS: in.DelayMS}
		for k, v := range in.Headers {
			r.Headers = append(r.Headers, rules.Pair{Name: k, Value: v})
		}
		return s.addRule(r.Matcher, func(d *rules.Data) { d.MapLocal = append(d.MapLocal, r); delete(d.DisabledTools, rules.ToolMapLocal) }, r)
	})
	mcp.AddTool(srv, change("create_map_local_from_flow", "Map Local from Flow", "Answer requests like a flow's with its captured response, headers and body, from now on.", false), func(_ context.Context, _ *mcp.CallToolRequest, in flowInput) (*mcp.CallToolResult, any, error) {
		f, err := s.flow(in.FlowID)
		if err != nil {
			return nil, nil, err
		}
		if f.Response == nil || f.IsError() {
			return nil, nil, errors.New("the flow has no response")
		}
		u, _, _ := strings.Cut(f.URL(), "?")
		r := &rules.MapLocalRule{ID: rules.NewID(), Enabled: true, Name: f.Host() + f.URLPath(), Matcher: rules.Matcher{URL: u, Method: f.MethodName()},
			StatusCode: f.StatusCode(), Body: string(f.DecodedResponseBody())}
		for _, e := range f.Response.Header.Entries {
			switch strings.ToLower(e.Key.Name) {
			case "content-length", "content-encoding", "transfer-encoding", "connection", "date", ":status":
				continue
			}
			if e.Enabled {
				r.Headers = append(r.Headers, rules.Pair{Name: e.Key.Name, Value: e.Value})
			}
		}
		return s.addRule(r.Matcher, func(d *rules.Data) { d.MapLocal = append(d.MapLocal, r); delete(d.DisabledTools, rules.ToolMapLocal) }, r)
	})
	mcp.AddTool(srv, change("create_map_remote", "Create Map Remote", "Send matching requests to another URL: a staging server, localhost, another path.", false), func(_ context.Context, _ *mcp.CallToolRequest, in mapRemoteInput) (*mcp.CallToolResult, any, error) {
		if u, err := url.Parse(in.ToURL); err != nil || u.Host == "" {
			return nil, nil, errors.New("to_url needs a scheme and a host")
		}
		r := &rules.MapRemoteRule{ID: rules.NewID(), Enabled: true, Name: cmp.Or(in.Name, "MCP Map Remote"), Matcher: in.matcher(), NewURL: in.ToURL, PreserveHost: in.PreserveHost}
		r.IncludeSubpaths = true
		return s.addRule(r.Matcher, func(d *rules.Data) {
			d.MapRemote = append(d.MapRemote, r)
			delete(d.DisabledTools, rules.ToolMapRemote)
		}, r)
	})
	mcp.AddTool(srv, change("create_breakpoint", "Create Breakpoint", "Pause matching requests or responses in ProxyGo's Breakpoint window, for the user to edit.", false), func(_ context.Context, _ *mcp.CallToolRequest, in breakpointInput) (*mcp.CallToolResult, any, error) {
		phase := cmp.Or(in.Phase, rules.PhaseBoth)
		if phase != rules.PhaseRequest && phase != rules.PhaseResponse && phase != rules.PhaseBoth {
			return nil, nil, fmt.Errorf("phase is request, response or both, not %q", in.Phase)
		}
		r := &rules.BreakpointRule{ID: rules.NewID(), Enabled: true, Name: cmp.Or(in.Name, "MCP Breakpoint"), Matcher: in.matcher(), Phase: phase}
		return s.addRule(r.Matcher, func(d *rules.Data) {
			d.Breakpoints = append(d.Breakpoints, r)
			delete(d.DisabledTools, rules.ToolBreakpoint)
		}, r)
	})
	mcp.AddTool(srv, change("create_blacklist", "Create Block Rule", "Block matching requests: answer 403, or drop the connection and hide them.", false), func(_ context.Context, _ *mcp.CallToolRequest, in blockInput) (*mcp.CallToolResult, any, error) {
		r := &rules.URLRule{ID: rules.NewID(), Enabled: true, Name: cmp.Or(in.Name, "MCP Block"), Matcher: in.matcher()}
		switch in.Action {
		case "", "block":
		case "block_and_hide":
			r.Action = rules.BlockHide
		default:
			return nil, nil, fmt.Errorf("action is block or block_and_hide, not %q", in.Action)
		}
		return s.addRule(r.Matcher, func(d *rules.Data) { d.Block = append(d.Block, r); delete(d.DisabledTools, rules.ToolBlock) }, r)
	})
	mcp.AddTool(srv, change("create_allow_list", "Create Allow Rule", "Allow matching requests; while the Allow List has rules, every other request is answered 403.", false), func(_ context.Context, _ *mcp.CallToolRequest, in matcherInput) (*mcp.CallToolResult, any, error) {
		r := &rules.URLRule{ID: rules.NewID(), Enabled: true, Name: cmp.Or(in.Name, "MCP Allow"), Matcher: in.matcher()}
		return s.addRule(r.Matcher, func(d *rules.Data) { d.Allow = append(d.Allow, r); delete(d.DisabledTools, rules.ToolAllow) }, r)
	})
	mcp.AddTool(srv, change("create_scripting_rule", "Create Script", "A JavaScript rule that changes matching requests and responses. Read proxygo://docs/scripting first.", false), func(_ context.Context, _ *mcp.CallToolRequest, in scriptInput) (*mcp.CallToolResult, any, error) {
		r := &rules.ScriptRule{ID: rules.NewID(), Enabled: true, Name: cmp.Or(in.Name, "MCP Script"), Matcher: in.matcher(), Script: in.ScriptContent,
			OnRequest: in.EnableRequest == nil || *in.EnableRequest, OnResponse: in.EnableResponse == nil || *in.EnableResponse, MockResponse: in.MockResponse}
		if err := scriptCheck(r.Name, r.Script); err != nil {
			return nil, nil, fmt.Errorf("the script does not compile: %w", err)
		}
		return s.addRule(r.Matcher, func(d *rules.Data) { d.Scripts = append(d.Scripts, r); delete(d.DisabledTools, rules.ToolScripting) }, r)
	})
	mcp.AddTool(srv, change("create_dns_spoofing", "Create DNS Spoofing", "Resolve a host to another address when ProxyGo connects to it.", false), func(_ context.Context, _ *mcp.CallToolRequest, in dnsInput) (*mcp.CallToolResult, any, error) {
		r := &rules.DNSRule{ID: rules.NewID(), Enabled: true, Host: in.Host, IP: in.IP, Port: in.Port}
		res, err := control.RuleCall(s.host.Rules(), "create", "dns-spoofing", "", mustJSON(r))
		if err != nil {
			return nil, nil, err
		}
		return jsonText(res)
	})
	mcp.AddTool(srv, change("create_network_condition", "Create Network Condition", "Slow matching traffic down: a preset as 3G, or latency, bandwidth and loss.", false), func(_ context.Context, _ *mcp.CallToolRequest, in networkInput) (*mcp.CallToolResult, any, error) {
		r := &rules.NetworkCondition{ID: rules.NewID(), Enabled: true, Name: cmp.Or(in.Profile, "Custom"), Matcher: in.matcher(),
			LatencyMS: in.LatencyMS, DownloadKBps: in.DownloadKBps, UploadKBps: in.UploadKBps, PacketLoss: in.PacketLoss}
		if in.Profile != "" {
			i := slices.IndexFunc(rules.Presets, func(p rules.Preset) bool { return strings.EqualFold(p.Name, in.Profile) })
			if i < 0 {
				return nil, nil, fmt.Errorf("unknown profile %q", in.Profile)
			}
			p := rules.Presets[i]
			r.Name, r.LatencyMS, r.DownloadKBps, r.UploadKBps, r.PacketLoss = p.Name, p.LatencyMS, p.DownloadKBps, p.UploadKBps, p.PacketLoss
		}
		return s.addRule(r.Matcher, func(d *rules.Data) {
			d.NetworkConditions = append(d.NetworkConditions, r)
			delete(d.DisabledTools, rules.ToolNetwork)
		}, r)
	})
	s.addComposeTools()
}

var ruleTypes = map[string]string{
	"map_local": "map-local", "map_remote": "map-remote", "breakpoint": "breakpoint", "blacklist": "block-list",
	"allow_list": "allow-list", "scripting": "scripting", "network_condition": "network-condition",
	"dns_spoofing": "dns-spoofing", "reverse_proxy": "reverse-proxy", "ssl_proxying": "ssl-proxying", "protobuf": "protobuf",
}

var toolNames = map[string]string{
	"map_local": "map-local", "map_remote": "map-remote", "breakpoint": "breakpoint", "blacklist": "block-list",
	"allow_list": "allow-list", "scripting": "scripting", "network_condition": "network-condition",
	"dns_spoofing": "dns-spoofing", "reverse_proxy": "reverse-proxy", "ssl_proxying": "ssl-proxying", "no_caching": "no-caching",
}

// domainOf is the host the SSL Proxying tools name: the domain given, or
// the host of a URL.
func domainOf(domain string) string {
	host := strings.TrimSpace(domain)
	if u, err := url.Parse(host); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	return host
}

func (m matcherInput) matcher() rules.Matcher {
	out := rules.Matcher{URL: strings.TrimSpace(m.URL), Method: strings.ToUpper(m.Method)}
	if out.Method == "ANY" {
		out.Method = ""
	}
	if m.Regex {
		out.Match = "regex"
	}
	return out
}

func (s *Server) addRule(m rules.Matcher, add func(*rules.Data), r any) (*mcp.CallToolResult, any, error) {
	if msg := m.Valid(); msg != "" {
		return nil, nil, errors.New(msg)
	}
	s.host.Rules().Update(add)
	return jsonText(r)
}

func (s *Server) flowsOrSelected(ids []string) ([]*flow.Flow, error) {
	if len(ids) == 0 {
		sel := s.host.Selected()
		if len(sel) == 0 {
			return nil, errors.New("no flow is selected in ProxyGo: pass flow_ids")
		}
		return sel, nil
	}
	var out []*flow.Flow
	for _, id := range ids {
		f, err := s.flow(id)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *Server) codeRequest(f *flow.Flow) codegen.Request {
	r := codegen.Of(f)
	if s.Redact() {
		r.Header, _ = redactHeader(r.Header)
		r.URL, _ = redactURL(r.URL)
		r.Body, _ = redactBody(r.Body, f.Request.Header.Get("Content-Type"))
	}
	return r
}

func condition(p filterParam) (store.Condition, error) {
	fields := map[string]store.Field{
		"url": store.FieldURL, "host": store.FieldHost, "path": store.FieldPath, "query": store.FieldQuery,
		"method": store.FieldMethod, "statuscode": store.FieldStatus, "status": store.FieldStatus, "client": store.FieldClient,
		"contenttype": store.FieldContentType, "requestheader": store.FieldRequestHeader, "responseheader": store.FieldResponseHeader,
		"requestbody": store.FieldRequestBody, "responsebody": store.FieldResponseBody, "graphql": store.FieldGraphQL,
		"comment": store.FieldComment, "duration": store.FieldDuration, "responsesize": store.FieldSize,
	}
	ops := map[string]store.Op{
		"": store.OpContains, "contains": store.OpContains, "notcontains": store.OpNotContains, "equals": store.OpEquals, "is": store.OpEquals,
		"notequals": store.OpNotEquals, "startswith": store.OpStartsWith, "endswith": store.OpEndsWith, "regex": store.OpRegex,
		"greaterthan": store.OpGreater, "lessthan": store.OpLess,
	}
	norm := func(s string) string {
		return strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(s))
	}
	f, ok := fields[norm(p.Key)]
	if !ok {
		return store.Condition{}, fmt.Errorf("unknown filter key %q", p.Key)
	}
	op, ok := ops[norm(p.Matching)]
	if !ok {
		return store.Condition{}, fmt.Errorf("unknown matching %q", p.Matching)
	}
	if op == store.OpRegex {
		if msg := store.ValidRegexp(p.Value); msg != "" {
			return store.Condition{}, fmt.Errorf("invalid regex: %s", msg)
		}
	}
	return store.Condition{Enabled: true, Field: f, Op: op, Value: p.Value}, nil
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func clamp(n, def, most int) int {
	if n <= 0 {
		return def
	}
	return min(n, most)
}

func overview(flows []*flow.Flow) map[string]any {
	status := map[string]int{"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "failed": 0, "active": 0}
	hosts, apps := map[string]int{}, map[string]int{}
	encrypted := map[string]bool{}
	var up, down int64
	var durations []float64
	for _, f := range flows {
		up += int64(f.RequestSize())
		down += int64(f.ResponseSize())
		hosts[f.Host()]++
		apps[cmp.Or(f.Client.Name, "System")]++
		switch code := f.StatusCode(); {
		case f.IsError():
			status["failed"]++
		case f.IsActive():
			status["active"]++
		case code > 0:
			status[fmt.Sprintf("%dxx", min(code/100, 5))]++
		}
		if f.IsTunnel() {
			encrypted[f.Host()] = true
		}
		if d := f.Duration(); d > 0 {
			durations = append(durations, float64(d.Microseconds())/1000)
		}
	}
	top := func(m map[string]int) []map[string]any {
		keys := store.ByCount(m)
		var out []map[string]any
		for _, k := range keys[:min(len(keys), 10)] {
			out = append(out, map[string]any{"name": k, "flows": m[k]})
		}
		return out
	}
	out := map[string]any{
		"flows": len(flows), "status": status, "uploadedBytes": up, "downloadedBytes": down,
		"topHosts": top(hosts), "topApps": top(apps),
	}
	if len(durations) > 0 {
		slices.Sort(durations)
		sum := 0.0
		for _, d := range durations {
			sum += d
		}
		out["durationMs"] = map[string]float64{"average": sum / float64(len(durations)), "median": durations[len(durations)/2], "p95": durations[len(durations)*95/100]}
	}
	if len(encrypted) > 0 {
		var hs []string
		for h := range encrypted {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		out["encryptedHosts"] = hs
		out["note"] = "HTTPS to encryptedHosts was tunneled, not decrypted: enable_ssl_proxying shows their requests."
	}
	return out
}
