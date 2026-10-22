package flow

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func (f *Flow) Clone() *Flow {
	if f == nil {
		return nil
	}
	out := *f
	out.Style = cloneAny(f.Style)
	out.ExtraInfo = cloneAny(f.ExtraInfo)
	out.ToolMetadata = cloneAny(f.ToolMetadata)
	out.MatchedDebuggingToolMetadata = cloneAny(f.MatchedDebuggingToolMetadata)
	out.RemoteDevice = cloneAny(f.RemoteDevice)
	out.Summary.Tag = cloneAny(f.Summary.Tag)
	if f.Summary.HostDNS != nil {
		out.Summary.HostDNS = new(*f.Summary.HostDNS)
	}
	out.Client = f.Client
	out.Client.SimulatorDevice = cloneAny(f.Client.SimulatorDevice)
	out.Timing = f.Timing.clone()
	if f.Request != nil {
		r := *f.Request
		r.BodyData = bytes.Clone(f.Request.BodyData)
		r.Header = f.Request.Header.Clone()
		r.CustomPreviewerTabs = cloneAny(f.Request.CustomPreviewerTabs)
		out.Request = &r
	}
	if f.Response != nil {
		r := *f.Response
		r.BodyData = bytes.Clone(f.Response.BodyData)
		r.Header = f.Response.Header.Clone()
		r.CustomPreviewerTabs = cloneAny(f.Response.CustomPreviewerTabs)
		if f.Response.Error != nil {
			r.Error = ResponseError(cloneAny(map[string]any(f.Response.Error)).(map[string]any))
		}
		if f.Response.Status != nil {
			st := *f.Response.Status
			r.Status = &st
		}
		out.Response = &r
	}
	if f.ConnectionRecord != nil {
		cr := *f.ConnectionRecord
		cr.Exchange.Informational = slices.Clone(f.ConnectionRecord.Exchange.Informational)
		out.ConnectionRecord = &cr
	}
	if f.FileName != nil {
		out.FileName = new(*f.FileName)
	}
	if f.TLS != nil {
		t := TLSDetails{Client: f.TLS.Client.clone(), Server: f.TLS.Server.clone()}
		out.TLS = &t
	}
	if f.WebSocketMessageStorage != nil {
		ws := &WebSocketStorage{Messages: make([]WebSocketMessage, len(f.WebSocketMessageStorage.Messages))}
		for i, m := range f.WebSocketMessageStorage.Messages {
			m.RawData = bytes.Clone(m.RawData)
			ws.Messages[i] = m
		}
		out.WebSocketMessageStorage = ws
	}
	return &out
}

func (t *TLSInfo) Clone() *TLSInfo { return t.clone() }

func (t *TLSInfo) clone() *TLSInfo {
	if t == nil {
		return nil
	}
	c := *t
	c.Offered = slices.Clone(t.Offered)
	c.Certificates = slices.Clone(t.Certificates)
	for i := range c.Certificates {
		c.Certificates[i].DNSNames = slices.Clone(c.Certificates[i].DNSNames)
	}
	return &c
}

func (t Timing) clone() Timing {
	cp := func(p *float64) *float64 {
		if p == nil {
			return nil
		}
		return new(*p)
	}
	return Timing{
		ClientTLSEndedAt:         cp(t.ClientTLSEndedAt),
		UpstreamTLSStartedAt:     cp(t.UpstreamTLSStartedAt),
		UpstreamConnectEndedAt:   cp(t.UpstreamConnectEndedAt),
		ClientTLSStartedAt:       cp(t.ClientTLSStartedAt),
		ResponseStartedAt:        cp(t.ResponseStartedAt),
		UpstreamTLSEndedAt:       cp(t.UpstreamTLSEndedAt),
		RequestEndedAt:           cp(t.RequestEndedAt),
		ResponseEndedAt:          cp(t.ResponseEndedAt),
		RequestStartedAt:         cp(t.RequestStartedAt),
		UpstreamConnectStartedAt: cp(t.UpstreamConnectStartedAt),
	}
}

func cloneAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneAny(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneAny(e)
		}
		return out
	case []string:
		return slices.Clone(x)
	default:
		return v
	}
}

func (h Header) Clone() Header {
	return Header{Entries: slices.Clone(h.Entries)}
}

func (f *Flow) IsWebSocket() bool {
	return f != nil && f.Request != nil && f.Request.IsWebSocketUpgrade
}

func (f *Flow) IsHTTPS() bool {
	if f == nil {
		return false
	}
	if f.IsSSL || f.MethodName() == "CONNECT" {
		return true
	}
	u := strings.ToLower(f.URL())
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "wss://")
}

func (f *Flow) IsTunnel() bool {
	return f != nil && f.MethodName() == "CONNECT"
}

func (f *Flow) HTTPVersionLabel() string {
	if f == nil || f.Request == nil {
		return ""
	}
	switch f.Request.Version.Major {
	case 2:
		return "h2"
	case 3:
		return "h3"
	default:
		return "h1"
	}
}

func (f *Flow) ErrorText() string {
	if f == nil || f.Response == nil || len(f.Response.Error) == 0 {
		return ""
	}
	k := slices.Min(slices.Collect(maps.Keys(f.Response.Error)))
	if m, ok := f.Response.Error[k].(map[string]any); ok {
		if msg, ok := m["message"].(string); ok && msg != "" {
			return msg
		}
	}
	return humanizeError(k)
}

func humanizeError(kind string) string {
	known := map[string]string{
		"couldNotConnectToServer": "Could not connect to the server",
		"sslError":                "TLS error",
		"sslHandshakeFailed":      "TLS handshake failed",
		"cannotFindHost":          "Cannot find the host",
		"timedOut":                "The request timed out",
		"cancelled":               "The client cancelled the request",
		"invalidResponse":         "The server sent an invalid response",
	}
	if s, ok := known[kind]; ok {
		return s
	}
	var b strings.Builder
	for i, r := range kind {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte(' ')
			r += 'a' - 'A'
		} else if i == 0 && r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (f *Flow) GraphQLOperation() string {
	if f == nil || f.Request == nil {
		return ""
	}
	if f.MethodName() == http.MethodGet {
		if u, err := url.Parse(f.URL()); err == nil {
			q := u.Query()
			if q.Get("query") != "" {
				if name := q.Get("operationName"); name != "" {
					return name
				}
				return operationFromQuery(q.Get("query"))
			}
		}
		return ""
	}
	body := f.DecodedRequestBody()
	if len(body) == 0 || (body[0] != '{' && body[0] != '[') {
		return ""
	}
	ct := strings.ToLower(f.Request.Header.Get("Content-Type"))
	if ct != "" && !strings.Contains(ct, "json") && !strings.Contains(ct, "graphql") {
		return ""
	}
	type gql struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName"`
	}
	var one gql
	if json.Unmarshal(body, &one) == nil && one.Query != "" {
		return cmp.Or(one.OperationName, operationFromQuery(one.Query))
	}
	var batch []gql
	if json.Unmarshal(body, &batch) == nil && len(batch) > 0 && batch[0].Query != "" {
		return cmp.Or(batch[0].OperationName, operationFromQuery(batch[0].Query))
	}
	return ""
}

func operationFromQuery(q string) string {
	fields := strings.FieldsFunc(q, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == '(' || r == '{' || r == ','
	})
	for i, w := range fields {
		switch w {
		case "query", "mutation", "subscription":
			if i+1 < len(fields) && fields[i+1] != "" {
				return fields[i+1]
			}
			return w
		}
	}
	if strings.HasPrefix(strings.TrimSpace(q), "{") {
		return "query"
	}
	return ""
}

func (f *Flow) Cookies() []*http.Cookie {
	if f == nil || f.Request == nil {
		return nil
	}
	var out []*http.Cookie
	for _, line := range f.Request.Header.Values("Cookie") {
		if cs, err := http.ParseCookie(line); err == nil {
			out = append(out, cs...)
		}
	}
	return out
}

func (f *Flow) SetCookies() []*http.Cookie {
	if f == nil || f.Response == nil {
		return nil
	}
	var out []*http.Cookie
	for _, line := range f.Response.Header.Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(line); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func (f *Flow) QueryItems() [][2]string {
	raw := f.URL()
	_, q, ok := strings.Cut(raw, "?")
	if !ok {
		return nil
	}
	q, _, _ = strings.Cut(q, "#")
	var out [][2]string
	for part := range strings.SplitSeq(q, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		out = append(out, [2]string{k, v})
	}
	return out
}

func (f *Flow) StatusLine() string {
	switch {
	case f == nil || f.IsActive():
		return "Active"
	case f.IsIncomplete():
		return "Incomplete"
	case f.IsError():
		return "Error: " + f.ErrorText()
	}
	phrase := ""
	if f.Response.Status != nil {
		phrase = f.Response.Status.Phrase
	}
	if phrase == "" {
		phrase = http.StatusText(f.StatusCode())
	}
	return fmt.Sprintf("%d %s", f.StatusCode(), phrase)
}
