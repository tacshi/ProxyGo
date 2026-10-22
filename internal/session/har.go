package session

import (
	"cmp"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"proxygo/internal/flow"
)

type (
	harLog struct {
		Log struct {
			Version string     `json:"version"`
			Creator harCreator `json:"creator"`
			Entries []harEntry `json:"entries"`
		} `json:"log"`
	}
	harCreator struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	harNV struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	harPost struct {
		MimeType string  `json:"mimeType"`
		Text     string  `json:"text,omitempty"`
		Encoding string  `json:"encoding,omitempty"`
		Params   []harNV `json:"params,omitempty"`
	}
	harRequest struct {
		Method      string   `json:"method"`
		URL         string   `json:"url"`
		HTTPVersion string   `json:"httpVersion"`
		Cookies     []harNV  `json:"cookies"`
		Headers     []harNV  `json:"headers"`
		QueryString []harNV  `json:"queryString"`
		PostData    *harPost `json:"postData,omitzero"`
		HeadersSize int      `json:"headersSize"`
		BodySize    int      `json:"bodySize"`
	}
	harContent struct {
		Size     int    `json:"size"`
		MimeType string `json:"mimeType"`
		Text     string `json:"text,omitempty"`
		Encoding string `json:"encoding,omitempty"`
	}
	harResponse struct {
		Status      int        `json:"status"`
		StatusText  string     `json:"statusText"`
		HTTPVersion string     `json:"httpVersion"`
		Cookies     []harNV    `json:"cookies"`
		Headers     []harNV    `json:"headers"`
		Content     harContent `json:"content"`
		RedirectURL string     `json:"redirectURL"`
		HeadersSize int        `json:"headersSize"`
		BodySize    int        `json:"bodySize"`
		Error       string     `json:"_error,omitempty"`
	}
	harTimings struct {
		Blocked float64 `json:"blocked"`
		DNS     float64 `json:"dns"`
		Connect float64 `json:"connect"`
		SSL     float64 `json:"ssl"`
		Send    float64 `json:"send"`
		Wait    float64 `json:"wait"`
		Receive float64 `json:"receive"`
	}
	harEntry struct {
		StartedDateTime   time.Time      `json:"startedDateTime"`
		Time              float64        `json:"time"`
		Request           harRequest     `json:"request"`
		Response          harResponse    `json:"response"`
		Cache             struct{}       `json:"cache"`
		Timings           harTimings     `json:"timings"`
		ServerIPAddress   string         `json:"serverIPAddress,omitempty"`
		Comment           string         `json:"comment,omitempty"`
		ResourceType      string         `json:"_resourceType,omitempty"`
		WebSocketMessages []harWSMessage `json:"_webSocketMessages,omitempty"`
	}
	harWSMessage struct {
		Type   string  `json:"type"`
		Time   float64 `json:"time"`
		Opcode int     `json:"opcode"`
		Data   string  `json:"data"`
	}
)

var wsOpcodes = map[string]int{"text": 1, "binary": 2, "close": 8, "ping": 9, "pong": 10}

func WriteHAR(path string, flows []*flow.Flow) error {
	var doc harLog
	doc.Log.Version = "1.2"
	doc.Log.Creator = harCreator{Name: "ProxyGo", Version: "1.0"}
	doc.Log.Entries = []harEntry{}
	for _, f := range flows {
		if f == nil || f.Request == nil || f.IsTunnel() {
			continue
		}
		doc.Log.Entries = append(doc.Log.Entries, harEntryOf(f))
	}
	data, err := json.Marshal(doc, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'))
}

func harEntryOf(f *flow.Flow) harEntry {
	req := harRequest{
		Method: f.MethodName(), URL: f.URL(), HTTPVersion: f.Request.Version.HTTPVersion(),
		Cookies: cookiesOf(f.Cookies()), Headers: pairs(f.Request.Header), QueryString: []harNV{},
		HeadersSize: -1, BodySize: len(f.Request.BodyData),
	}
	for _, q := range f.QueryItems() {
		req.QueryString = append(req.QueryString, harNV{q[0], q[1]})
	}
	if body := f.DecodedRequestBody(); len(body) > 0 {
		req.PostData = &harPost{MimeType: f.Request.Header.Get("Content-Type")}
		req.PostData.Text, req.PostData.Encoding = textOrBase64(body, req.PostData.MimeType)
	}
	resp := harResponse{HTTPVersion: "HTTP/1.1", Cookies: []harNV{}, Headers: []harNV{}, HeadersSize: -1, BodySize: -1}
	if f.Response != nil {
		resp.Status = f.StatusCode()
		if f.Response.Status != nil {
			resp.StatusText = f.Response.Status.Phrase
		}
		if f.IsError() {
			resp.Status, resp.Error = 0, f.ErrorText()
		}
		resp.HTTPVersion = f.Response.Version.HTTPVersion()
		resp.Headers = pairs(f.Response.Header)
		resp.Cookies = cookiesOf(f.SetCookies())
		resp.BodySize = len(f.Response.BodyData)
		body := f.DecodedResponseBody()
		resp.Content = harContent{Size: len(body), MimeType: f.Response.Header.Get("Content-Type")}
		resp.Content.Text, resp.Content.Encoding = textOrBase64(body, resp.Content.MimeType)
		resp.RedirectURL = f.Response.Header.Get("Location")
	}
	started := f.RequestTime()
	if started.IsZero() {
		started = time.Now()
	}
	ms := func(a, b *float64) float64 {
		if a == nil || b == nil || *b < *a {
			return -1
		}
		return (*b - *a) * 1000
	}
	t := f.Timing
	timings := harTimings{
		Blocked: -1, DNS: -1,
		Connect: ms(t.UpstreamConnectStartedAt, t.UpstreamConnectEndedAt),
		SSL:     ms(t.UpstreamTLSStartedAt, t.UpstreamTLSEndedAt),
		Send:    max(ms(t.RequestStartedAt, t.RequestEndedAt), 0),
		Wait:    max(ms(t.RequestEndedAt, t.ResponseStartedAt), 0),
		Receive: max(ms(t.ResponseStartedAt, t.ResponseEndedAt), 0),
	}
	total := float64(f.Duration().Microseconds()) / 1000
	if timings.Send+timings.Wait+timings.Receive == 0 {
		timings.Wait = total
	}
	e := harEntry{
		StartedDateTime: started, Time: total, Request: req, Response: resp,
		Timings: timings, ServerIPAddress: f.Summary.ServerIPAddress, Comment: f.Comment,
	}
	if ws := f.WebSocketMessageStorage; ws != nil {
		e.ResourceType = "websocket"
		for _, m := range ws.Messages {
			typ := "receive"
			if m.From == "client" {
				typ = "send"
			}
			data := m.Data
			if len(m.RawData) > 0 {
				data = base64.StdEncoding.EncodeToString(m.RawData)
			}
			e.WebSocketMessages = append(e.WebSocketMessages, harWSMessage{Type: typ, Time: m.Time, Opcode: wsOpcodes[m.Type], Data: data})
		}
	}
	return e
}

func pairs(h flow.Header) []harNV {
	out := []harNV{}
	for _, e := range h.Entries {
		if e.Enabled {
			out = append(out, harNV{e.Key.Name, e.Value})
		}
	}
	return out
}

func cookiesOf(cs []*http.Cookie) []harNV {
	out := []harNV{}
	for _, c := range cs {
		out = append(out, harNV{c.Name, c.Value})
	}
	return out
}

func textOrBase64(body []byte, mimeType string) (string, string) {
	if len(body) == 0 {
		return "", ""
	}
	if isText(mimeType, body) {
		return string(body), ""
	}
	return base64.StdEncoding.EncodeToString(body), "base64"
}

func isText(mimeType string, body []byte) bool {
	mt := strings.ToLower(mimeType)
	if strings.HasPrefix(mt, "text/") || strings.Contains(mt, "json") || strings.Contains(mt, "xml") ||
		strings.Contains(mt, "javascript") || strings.Contains(mt, "graphql") || strings.Contains(mt, "x-www-form-urlencoded") {
		return true
	}
	if mt != "" {
		return false
	}
	return jsontext.Value(body).IsValid() || strings.ToValidUTF8(string(body), "�") == string(body) && !strings.ContainsRune(string(body), 0)
}

func ReadHAR(path string) ([]*flow.Flow, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the HAR file the user imports.
	if err != nil {
		return nil, err
	}
	var doc harLog
	if err := json.Unmarshal(data, &doc, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("not an HTTP Archive: %w", err)
	}
	flows := make([]*flow.Flow, 0, len(doc.Log.Entries))
	for _, e := range doc.Log.Entries {
		if f := flowOfEntry(e); f != nil {
			flows = append(flows, f)
		}
	}
	sortFlows(flows)
	return flows, nil
}

func flowOfEntry(e harEntry) *flow.Flow {
	u, err := url.Parse(e.Request.URL)
	if err != nil || u.Host == "" {
		return nil
	}
	f := flow.New(flow.NewUniqueID())
	f.IsFromFile = true
	f.Comment = e.Comment
	scheme := cmp.Or(u.Scheme, "http")
	port := 80
	if scheme == "https" || scheme == "wss" {
		port = 443
	}
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	start := float64(e.StartedDateTime.UnixNano()) / 1e9
	end := start + e.Time/1000
	f.Timing = flow.Timing{RequestStartedAt: new(start), ResponseEndedAt: new(end)}
	if e.Timings.Wait > 0 {
		f.Timing.ResponseStartedAt = new(end - max(e.Timings.Receive, 0)/1000)
	}
	f.IsSSL = scheme == "https" || scheme == "wss"
	f.Summary = flow.Summary{ServerIPAddress: e.ServerIPAddress, ServerPort: port}
	f.Client = flow.Client{Name: "HAR", PID: -1}
	version := parseVersion(e.Request.HTTPVersion)
	f.Request = &flow.Request{
		Scheme: scheme, Port: port, IsSSL: f.IsSSL, Version: version,
		FullPath: u.String(), URI: u.RequestURI(), Host: u.Hostname(),
		Method:      flow.Method{Name: strings.ToUpper(e.Request.Method)},
		Header:      headerOf(e.Request.Headers),
		HTTPVersion: version.HTTPVersion(),
	}
	if f.Request.Header.Get("Host") == "" {
		f.Request.Header.Entries = append([]flow.HeaderEntry{{Enabled: true, Key: flow.HeaderKey{Name: "Host", Lower: "host"}, Value: u.Host}}, f.Request.Header.Entries...)
	}
	if p := e.Request.PostData; p != nil {
		body := decodeText(p.Text, p.Encoding)
		if len(body) == 0 && len(p.Params) > 0 {
			v := url.Values{}
			for _, kv := range p.Params {
				v.Add(kv.Name, kv.Value)
			}
			body = []byte(v.Encode())
		}
		f.Request.BodyData = body
	}
	if e.Response.Status == 0 && e.Response.Error != "" {
		f.Response = &flow.Response{Status: &flow.Status{Code: 999, Phrase: "Error"},
			Error: flow.ResponseError{"couldNotConnectToServer": map[string]any{"message": e.Response.Error}}}
		return f
	}
	rv := parseVersion(e.Response.HTTPVersion)
	f.Response = &flow.Response{
		Status:      &flow.Status{Code: e.Response.Status, Phrase: e.Response.StatusText},
		Header:      headerOf(e.Response.Headers),
		BodyData:    decodeText(e.Response.Content.Text, e.Response.Content.Encoding),
		CreatedAt:   end,
		Version:     rv,
		HTTPVersion: rv.HTTPVersion(),
	}
	if f.Response.Header.Get("Content-Encoding") != "" {
		f.Response.Header.Del("Content-Encoding")
	}
	if len(e.WebSocketMessages) > 0 || e.ResourceType == "websocket" {
		ws := &flow.WebSocketStorage{Messages: []flow.WebSocketMessage{}}
		for _, m := range e.WebSocketMessages {
			from := "server"
			if m.Type == "send" {
				from = "client"
			}
			msg := flow.WebSocketMessage{From: from, Type: "text", Time: m.Time}
			for name, op := range wsOpcodes {
				if op == m.Opcode {
					msg.Type = name
				}
			}
			if msg.Type == "binary" {
				if b, err := base64.StdEncoding.DecodeString(m.Data); err == nil {
					msg.RawData = b
				}
			} else {
				msg.Data = m.Data
			}
			ws.Messages = append(ws.Messages, msg)
		}
		f.WebSocketMessageStorage = ws
	}
	return f
}

func headerOf(nvs []harNV) flow.Header {
	var h flow.Header
	for _, nv := range nvs {
		if strings.HasPrefix(nv.Name, ":") {
			continue
		}
		h.Add(nv.Name, nv.Value)
	}
	return h
}

func decodeText(text, encoding string) []byte {
	if strings.EqualFold(encoding, "base64") {
		if b, err := base64.StdEncoding.DecodeString(text); err == nil {
			return b
		}
	}
	if text == "" {
		return nil
	}
	return []byte(text)
}

func parseVersion(s string) flow.Version {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch {
	case s == "H2" || strings.HasPrefix(s, "HTTP/2"):
		return flow.Version{Major: 2}
	case s == "H3" || strings.HasPrefix(s, "HTTP/3"):
		return flow.Version{Major: 3}
	case strings.HasPrefix(s, "HTTP/1.0"):
		return flow.Version{Major: 1}
	}
	return flow.Version{Major: 1, Minor: 1}
}

func HARJSON(f *flow.Flow) string {
	if f == nil || f.Request == nil {
		return ""
	}
	var doc harLog
	doc.Log.Version = "1.2"
	doc.Log.Creator = harCreator{Name: "ProxyGo", Version: "1.0"}
	doc.Log.Entries = []harEntry{harEntryOf(f)}
	b, err := json.Marshal(doc, jsontext.WithIndent("  "))
	if err != nil {
		return ""
	}
	return string(b)
}
