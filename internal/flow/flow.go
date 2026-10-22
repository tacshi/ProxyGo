package flow

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type Blob []byte

func (b Blob) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

func (b *Blob) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*b = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		*b = append((*b)[:0], s...)
		return nil
	}
	*b = raw
	return nil
}

type HeaderKey struct {
	Name    string `json:"name"`
	Lower   string `json:"nameInLowercase"`
	Enabled bool   `json:"-"`
}

type HeaderEntry struct {
	Enabled bool      `json:"isEnabled"`
	Key     HeaderKey `json:"key"`
	Value   string    `json:"value"`
}

type Header struct {
	Entries []HeaderEntry `json:"entries"`
}

func NewHeader(h http.Header) Header {
	out := Header{Entries: make([]HeaderEntry, 0, len(h))}
	preferred := []string{
		"Host", "Accept", "Accept-Encoding", "Accept-Language", "Content-Type",
		"Content-Length", "User-Agent", "Referer", "Origin", "Connection",
		"Cookie", "Authorization",
	}
	seen := map[string]bool{}
	add := func(name string, values []string) {
		lower := strings.ToLower(name)
		if seen[lower] {
			return
		}
		seen[lower] = true
		for _, v := range values {
			out.Entries = append(out.Entries, HeaderEntry{
				Enabled: true,
				Key:     HeaderKey{Name: name, Lower: lower},
				Value:   v,
			})
		}
	}
	for _, name := range preferred {
		if values, ok := h[name]; ok {
			add(name, values)
		}
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && strings.ToLower(names[j]) < strings.ToLower(names[j-1]); j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	for _, name := range names {
		add(name, h[name])
	}
	return out
}

type SentHeader struct {
	Name, Value string
}

func NewHeaderOrdered(h http.Header, sent []SentHeader) Header {
	if len(sent) == 0 {
		return NewHeader(h)
	}
	keys := make(map[string]string, len(h))
	for k := range h {
		keys[strings.ToLower(k)] = k
	}
	out := Header{Entries: make([]HeaderEntry, 0, len(sent)+len(h))}
	used := map[string]int{}
	for _, f := range sent {
		lower := strings.ToLower(f.Name)
		value := f.Value
		if values, ok := h[keys[lower]]; ok {
			if used[lower] >= len(values) {
				continue
			}
			value = values[used[lower]]
			used[lower]++
		}
		out.Entries = append(out.Entries, HeaderEntry{Enabled: true, Key: HeaderKey{Name: f.Name, Lower: lower}, Value: value})
	}
	for _, e := range NewHeader(h).Entries {
		if used[e.Key.Lower] > 0 {
			used[e.Key.Lower]--
			continue
		}
		out.Entries = append(out.Entries, e)
	}
	return out
}

func (h Header) Get(name string) string {
	lower := strings.ToLower(name)
	for _, e := range h.Entries {
		if e.Enabled && strings.EqualFold(e.Key.Name, name) {
			return e.Value
		}
		if e.Enabled && strings.ToLower(e.Key.Name) == lower {
			return e.Value
		}
	}
	return ""
}

func (h Header) Values(name string) []string {
	var out []string
	for _, e := range h.Entries {
		if e.Enabled && strings.EqualFold(e.Key.Name, name) {
			out = append(out, e.Value)
		}
	}
	return out
}

func (h *Header) Set(name, value string) {
	for i := range h.Entries {
		if strings.EqualFold(h.Entries[i].Key.Name, name) {
			h.Entries[i].Value = value
			h.Entries[i].Enabled = true
			return
		}
	}
	h.Entries = append(h.Entries, HeaderEntry{
		Enabled: true,
		Key:     HeaderKey{Name: name, Lower: strings.ToLower(name)},
		Value:   value,
	})
}

func (h *Header) Add(name, value string) {
	h.Entries = append(h.Entries, HeaderEntry{
		Enabled: true,
		Key:     HeaderKey{Name: name, Lower: strings.ToLower(name)},
		Value:   value,
	})
}

func (h *Header) Del(name string) {
	out := h.Entries[:0]
	for _, e := range h.Entries {
		if !strings.EqualFold(e.Key.Name, name) {
			out = append(out, e)
		}
	}
	h.Entries = out
}

func (h Header) HTTP() http.Header {
	out := http.Header{}
	for _, e := range h.Entries {
		if e.Enabled && !strings.HasPrefix(e.Key.Name, ":") {
			out.Add(e.Key.Name, e.Value)
		}
	}
	return out
}

type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

func (v Version) String() string {
	if v.Major == 0 {
		return "1.1"
	}
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

func (v Version) HTTPVersion() string { return "HTTP/" + v.String() }

type Method struct {
	Name string `json:"name"`
}

type Request struct {
	Scheme                  string  `json:"scheme"`
	Port                    int     `json:"port"`
	IsSSL                   bool    `json:"isSSL"`
	Version                 Version `json:"version"`
	FullPath                string  `json:"fullPath"`
	BodyData                Blob    `json:"bodyData"`
	URI                     string  `json:"uri"`
	Header                  Header  `json:"header"`
	Host                    string  `json:"host"`
	IsWebSocketUpgrade      bool    `json:"isWebSocketUpgrade"`
	CustomPreviewerTabs     any     `json:"customPreviewerTabs"`
	CompressedBodyDataCount int     `json:"compressedBodyDataCount"`
	Method                  Method  `json:"method"`

	HTTPVersion string `json:"-"`
}

type Status struct {
	Code   int    `json:"code"`
	Phrase string `json:"phrase"`
	Strict bool   `json:"strict"`
}

type ResponseError map[string]any

type Response struct {
	Error                   ResponseError `json:"error"`
	Status                  *Status       `json:"status"`
	BodyData                Blob          `json:"bodyData"`
	CompressedBodyDataCount int           `json:"compressedBodyDataCount"`
	Header                  Header        `json:"header"`
	CustomPreviewerTabs     any           `json:"customPreviewerTabs"`
	CreatedAt               float64       `json:"createdAt"`
	Version                 Version       `json:"version"`

	HTTPVersion string `json:"-"`
}

type Summary struct {
	ClientIPAddress string  `json:"clientIpAddress"`
	ServerIPAddress string  `json:"serverIpAddress"`
	ServerPort      int     `json:"serverPort"`
	HostDNS         *string `json:"hostDNS"`
	Tag             any     `json:"tag"`
	ClientPort      int     `json:"clientPort"`
}

type Client struct {
	IconImagePath    *string `json:"iconImagePath"`
	Name             string  `json:"name"`
	IsSimulator      bool    `json:"isSimulator"`
	SimulatorDevice  any     `json:"simulatorDevice"`
	Path             string  `json:"path"`
	PID              int     `json:"pid"`
	BundleIdentifier *string `json:"bundleIdentifier"`
}

type Timing struct {
	ClientTLSEndedAt         *float64 `json:"clientTLSEndedAt"`
	UpstreamTLSStartedAt     *float64 `json:"upstreamTLSStartedAt"`
	UpstreamConnectEndedAt   *float64 `json:"upstreamConnectEndedAt"`
	ClientTLSStartedAt       *float64 `json:"clientTLSStartedAt"`
	ResponseStartedAt        *float64 `json:"responseStartedAt"`
	UpstreamTLSEndedAt       *float64 `json:"upstreamTLSEndedAt"`
	RequestEndedAt           *float64 `json:"requestEndedAt"`
	ResponseEndedAt          *float64 `json:"responseEndedAt"`
	RequestStartedAt         *float64 `json:"requestStartedAt"`
	UpstreamConnectStartedAt *float64 `json:"upstreamConnectStartedAt"`
}

type Exchange struct {
	ResponseComplete bool    `json:"responseComplete"`
	RequestSent      bool    `json:"requestSent"`
	StartedAt        float64 `json:"startedAt"`
	Truncated        bool    `json:"truncated"`
	Reused           bool    `json:"reused"`
	ResponseModified bool    `json:"responseModified"`
	Informational    []any   `json:"informational"`
}

type ConnectionRecord struct {
	Exchange Exchange `json:"exchange"`
	TraceID  string   `json:"traceID"`
}

type WebSocketMessage struct {
	From      string  `json:"from"`
	Type      string  `json:"type"`
	Data      string  `json:"data"`
	RawData   Blob    `json:"rawData,omitempty"`
	CloseCode int     `json:"closeCode,omitempty"`
	Time      float64 `json:"time,omitempty"`
	Injected  bool    `json:"injected,omitempty"`
}

type WebSocketStorage struct {
	Messages []WebSocketMessage `json:"messages"`
}

type Flow struct {
	Timezone                     string            `json:"timezone"`
	Style                        any               `json:"style"`
	ExtraInfo                    any               `json:"extraInfo"`
	Summary                      Summary           `json:"summary"`
	IsFromFile                   bool              `json:"isFromFile"`
	IsSSL                        bool              `json:"isSSL"`
	IsIntercepted                bool              `json:"isIntercepted"`
	ToolMetadata                 any               `json:"toolMetadata"`
	Request                      *Request          `json:"request"`
	Client                       Client            `json:"client"`
	ID                           string            `json:"id"`
	UniqueID                     string            `json:"uniqueID"`
	IsUnderNetworkCondition      bool              `json:"isUnderNetworkCondition"`
	MatchedDebuggingToolMetadata any               `json:"matchedDebuggingToolMetadata"`
	Timing                       Timing            `json:"timing"`
	ConnectionRecord             *ConnectionRecord `json:"connectionRecord"`
	Response                     *Response         `json:"response"`
	Name                         string            `json:"name"`
	RemoteDevice                 any               `json:"remoteDevice"`
	IsRelayed                    bool              `json:"isRelayed"`
	FileName                     *string           `json:"fileName"`
	WebSocketMessageStorage      *WebSocketStorage `json:"websocketMessageStorage"`

	Saved         bool        `json:"saved,omitempty"`
	Comment       string      `json:"comment,omitempty"`
	Highlight     string      `json:"highlight,omitempty"`
	Strikethrough bool        `json:"strikethrough,omitempty"`
	TLS           *TLSDetails `json:"proxygoTLS,omitempty"`

	Index int `json:"-"`
}

func New(unique string) *Flow {
	return &Flow{UniqueID: unique, Timezone: "GMT+0"}
}

func (f *Flow) URL() string {
	if f == nil || f.Request == nil {
		return ""
	}
	if f.Request.FullPath != "" {
		return f.Request.FullPath
	}
	scheme := f.Request.Scheme
	if scheme == "" {
		if f.IsSSL {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := f.Request.Host
	path := f.Request.URI
	if strings.HasPrefix(path, "/") {
		return scheme + "://" + host + path
	}
	return scheme + "://" + host
}

func (f *Flow) MethodName() string {
	if f == nil || f.Request == nil {
		return ""
	}
	return f.Request.Method.Name
}

func (f *Flow) StatusCode() int {
	if f == nil || f.Response == nil || f.Response.Status == nil {
		return 0
	}
	return f.Response.Status.Code
}

func (f *Flow) StatusText() string {
	if f == nil || f.Response == nil {
		return "Active"
	}
	if f.Response.Error != nil {
		return "999"
	}
	if f.Response.Status == nil {
		return "Active"
	}
	return fmt.Sprintf("%d", f.Response.Status.Code)
}

func (f *Flow) IsActive() bool {
	return f != nil && (f.Response == nil || (f.Response.Status == nil && f.Response.Error == nil))
}

func (f *Flow) IsError() bool {
	return f != nil && f.Response != nil && f.Response.Error != nil
}

const errIncomplete = "incomplete"

func (f *Flow) MarkIncomplete() {
	if !f.IsActive() {
		return
	}
	f.Response = &Response{
		Error:   ResponseError{errIncomplete: map[string]any{"message": "The session was saved before this flow finished"}},
		Header:  Header{},
		Version: Version{Major: 1, Minor: 1},
	}
}

func (f *Flow) IsIncomplete() bool {
	return f.IsError() && f.Response.Error[errIncomplete] != nil
}

func (f *Flow) Duration() time.Duration {
	if f == nil {
		return 0
	}
	end := f.Timing.ResponseEndedAt
	if end == nil {
		end = f.Timing.ResponseStartedAt
	}
	if end == nil {
		return 0
	}
	start := f.Timing.RequestStartedAt
	if start == nil {
		start = f.Timing.UpstreamConnectStartedAt
	}
	if start == nil {
		return 0
	}
	return time.Duration((*end - *start) * float64(time.Second))
}

func (f *Flow) RequestTime() time.Time {
	if f == nil || f.Timing.RequestStartedAt == nil {
		return time.Time{}
	}
	return time.Unix(0, int64(*f.Timing.RequestStartedAt*1e9))
}

func (f *Flow) RequestSize() int {
	if f == nil || f.Request == nil {
		return 0
	}
	uri := f.Request.URI
	if uri == "" {
		uri = f.URLPath()
	}
	n := len(f.MethodName()) + 1 + len(uri) + 1 + len("HTTP/1.1") + 2
	n += headerBytes(f.Request.Header) + 2
	return n + bodyBytes(f.Request.Header, f.Request.BodyData)
}

func (f *Flow) ResponseSize() int {
	if f == nil || f.Response == nil {
		return 0
	}
	version := "HTTP/1.1"
	if f.Response.Version.Major > 0 {
		version = f.Response.Version.HTTPVersion()
	}
	n := len(version) + 1 + 3 + 1 + len(responseText(f.StatusCode())) + 2
	n += headerBytes(f.Response.Header) + 2
	return n + bodyBytes(f.Response.Header, f.Response.BodyData)
}

func (f *Flow) RequestBodySize() int {
	if f == nil || f.Request == nil {
		return 0
	}
	if ws := f.WebSocketMessageStorage; ws != nil && f.StatusCode() == http.StatusSwitchingProtocols {
		return webSocketBytes(ws.Messages, "client")
	}
	return bodyBytes(f.Request.Header, f.Request.BodyData)
}

func webSocketBytes(msgs []WebSocketMessage, from string) int {
	n := 0
	for _, m := range msgs {
		if m.From == from && (m.Type == "text" || m.Type == "binary") {
			n += max(len(m.RawData), len(m.Data))
		}
	}
	return n
}

func (f *Flow) ResponseBodySize() int {
	if f == nil || f.Response == nil {
		return 0
	}
	if ws := f.WebSocketMessageStorage; ws != nil && f.StatusCode() == http.StatusSwitchingProtocols {
		return webSocketBytes(ws.Messages, "server")
	}
	if code := f.StatusCode(); len(f.Response.BodyData) == 0 && (f.MethodName() == http.MethodHead || code == http.StatusNoContent || code == http.StatusNotModified) {
		return 0
	}
	return bodyBytes(f.Response.Header, f.Response.BodyData)
}

func headerBytes(h Header) int {
	n := 0
	for _, e := range h.Entries {
		if e.Enabled {
			n += len(e.Key.Name) + 2 + len(e.Value) + 2
		}
	}
	return n
}

func bodyBytes(h Header, body []byte) int {
	if len(body) > 0 {
		return len(body)
	}
	if s := h.Get("Content-Length"); s != "" {
		var n int
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

func responseText(code int) string {
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "Status"
}

func (f *Flow) ContentType() string {
	if f == nil {
		return ""
	}
	if f.Response != nil {
		if ct := f.Response.Header.Get("Content-Type"); ct != "" {
			return ct
		}
	}
	if f.Request != nil {
		return f.Request.Header.Get("Content-Type")
	}
	return ""
}

func (f *Flow) MIME() string {
	ct := f.ContentType()
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			return strings.TrimSpace(ct[:i])
		}
		return ct
	}
	return mt
}

func (f *Flow) Category() string {
	if f == nil {
		return "Other"
	}
	if f.IsWebSocket() {
		return "WebSocket"
	}
	if f.MethodName() == "CONNECT" {
		return "HTTPS"
	}
	return f.ContentCategory()
}

func (f *Flow) ContentCategory() string {
	if f == nil {
		return "Other"
	}
	if f.GraphQLOperation() != "" {
		return "GraphQL"
	}
	return contentCategory(f.MIME(), f.pathOnly())
}

func (f *Flow) ContentCategories() []string {
	if f == nil {
		return []string{"Other"}
	}
	out := []string{f.ContentCategory()}
	add := func(c string) {
		if c != "Other" && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	if f.Response != nil {
		add(contentCategory(mediaType(f.Response.Header.Get("Content-Type")), f.pathOnly()))
	}
	if f.Request != nil && len(f.Request.BodyData) > 0 {
		add(contentCategory(mediaType(f.Request.Header.Get("Content-Type")), ""))
	}
	if len(out) > 1 {
		out = slices.DeleteFunc(out, func(c string) bool { return c == "Other" })
	}
	return out
}

func (f *Flow) pathOnly() string {
	path := strings.ToLower(f.URLPath())
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return path
}

func mediaType(ct string) string {
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt, _, _ = strings.Cut(ct, ";")
		return strings.TrimSpace(mt)
	}
	return mt
}

func contentCategory(mt, path string) string {
	switch {
	case strings.Contains(mt, "graphql"):
		return "GraphQL"
	case strings.Contains(mt, "json") || strings.HasSuffix(path, ".json"):
		return "JSON"
	case strings.Contains(mt, "javascript") || strings.Contains(mt, "ecmascript") || strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs"):
		return "JS"
	case strings.Contains(mt, "css") || strings.HasSuffix(path, ".css"):
		return "CSS"
	case strings.HasPrefix(mt, "text/html") || strings.Contains(mt, "xhtml"):
		return "Document"
	case strings.Contains(mt, "xml"):
		return "XML"
	case strings.HasPrefix(mt, "image/") || strings.HasPrefix(mt, "audio/") || strings.HasPrefix(mt, "video/") || strings.Contains(mt, "font"):
		return "Media"
	case strings.Contains(mt, "x-www-form-urlencoded") || strings.Contains(mt, "multipart/form-data"):
		return "Form"
	default:
		return "Other"
	}
}

func (f *Flow) URLPath() string {
	u := f.URL()
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexByte(u, '/'); i >= 0 {
		return u[i:]
	}
	return "/"
}

func (f *Flow) Host() string {
	if f == nil || f.Request == nil {
		return ""
	}
	return f.Request.Host
}

func (f *Flow) Scheme() string {
	if f == nil || f.Request == nil {
		return ""
	}
	if f.Request.Scheme != "" {
		return f.Request.Scheme
	}
	if f.IsSSL {
		return "https"
	}
	return "http"
}

func (f *Flow) DecodedResponseBody() []byte {
	if f == nil || f.Response == nil {
		return nil
	}
	return decodeBody(f.Response.BodyData, f.Response.Header.Get("Content-Encoding"))
}

func (f *Flow) DecodedRequestBody() []byte {
	if f == nil || f.Request == nil {
		return nil
	}
	return decodeBody(f.Request.BodyData, f.Request.Header.Get("Content-Encoding"))
}

func DecodeBody(body []byte, encoding string) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip", "deflate", "br", "zstd":
	default:
		return body, false
	}
	out := decodeBody(body, encoding)
	return out, len(body) == 0 || !bytes.Equal(out, body)
}

func decodeBody(body []byte, encoding string) []byte {
	if len(body) == 0 {
		return body
	}
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer gr.Close()
		r = gr
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			fr := flate.NewReader(bytes.NewReader(body))
			defer fr.Close()
			r = fr
		} else {
			defer zr.Close()
			r = zr
		}
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return body
		}
		defer zr.Close()
		r = zr
	default:
		return body
	}
	out, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil && len(out) == 0 {
		return body
	}
	return out
}

func NewUniqueID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return strings.ToUpper(hex.EncodeToString(b[:]))
}
