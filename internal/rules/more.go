package rules

import (
	"bufio"
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type BreakpointTemplate struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Response bool   `json:"response,omitzero"`
	Raw      string `json:"raw"`
}

type TemplateMessage struct {
	Method     string
	URL        string
	StatusCode int
	Header     []Pair
	Body       []byte
}

func (t *BreakpointTemplate) Parse() (TemplateMessage, error) {
	raw := strings.TrimLeft(t.Raw, "\r\n")
	head, body, found := strings.Cut(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")
	if !found {
		head = strings.TrimRight(head, "\n")
	}
	r := textproto.NewReader(bufio.NewReader(strings.NewReader(head + "\n\n")))
	first, err := r.ReadLine()
	if err != nil {
		return TemplateMessage{}, errors.New("the template is empty")
	}
	var m TemplateMessage
	parts := strings.SplitN(first, " ", 3)
	if t.Response {
		if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
			return m, fmt.Errorf("a response template starts with a status line, as HTTP/1.1 200 OK, not %q", first)
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil || code < 100 || code > 999 {
			return m, fmt.Errorf("bad status %q", parts[1])
		}
		m.StatusCode = code
	} else {
		if len(parts) < 2 {
			return m, fmt.Errorf("a request template starts with a request line, as GET /path HTTP/1.1, not %q", first)
		}
		m.Method, m.URL = strings.ToUpper(parts[0]), parts[1]
	}
	for {
		line, err := r.ReadContinuedLine()
		if err != nil || line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return m, fmt.Errorf("bad header line %q", line)
		}
		m.Header = append(m.Header, Pair{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	m.Body = []byte(body)
	return m, nil
}

func DefaultTemplates() []*BreakpointTemplate {
	return []*BreakpointTemplate{
		{ID: NewID(), Name: "503 Service Unavailable", Response: true, Raw: "HTTP/1.1 503 Service Unavailable\nContent-Type: application/json\nRetry-After: 120\n\n{\"error\": \"Service Unavailable\"}"},
		{ID: NewID(), Name: "429 Too Many Requests", Response: true, Raw: "HTTP/1.1 429 Too Many Requests\nContent-Type: application/json\nRetry-After: 60\n\n{\"error\": \"Too Many Requests\"}"},
		{ID: NewID(), Name: "401 Unauthorized", Response: true, Raw: "HTTP/1.1 401 Unauthorized\nContent-Type: application/json\n\n{\"error\": \"Unauthorized\"}"},
	}
}

type AppRule struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	BundleID string `json:"bundle_id,omitempty"`
	AppName  string `json:"app_name,omitempty"`
	Action   string `json:"action,omitempty"`
}

func (d *Data) BlockedApp(bundleID, appName string) *AppRule {
	if !d.ToolOn(ToolBlock) {
		return nil
	}
	for _, r := range d.BlockedApps {
		if r == nil || !r.Enabled {
			continue
		}
		if r.BundleID != "" && strings.EqualFold(r.BundleID, bundleID) {
			return r
		}
		if r.BundleID == "" && r.AppName != "" && strings.EqualFold(r.AppName, appName) {
			return r
		}
	}
	return nil
}

type ProtobufRule struct {
	ID           string `json:"id"`
	Enabled      bool   `json:"enabled"`
	Name         string `json:"name"`
	Matcher      `json:",inline"`
	RequestType  string `json:"request_type,omitempty"`
	ResponseType string `json:"response_type,omitempty"`
	Payload      string `json:"payload,omitempty"`
}

func (d *Data) ProtobufFor(method, rawURL string) *ProtobufRule {
	for _, r := range d.Protobuf {
		if r != nil && r.Enabled && r.Matches(method, rawURL) {
			return r
		}
	}
	return nil
}

type ServerCertificate struct {
	ID          string   `json:"id"`
	Enabled     bool     `json:"enabled"`
	Hosts       []string `json:"hosts,omitempty"`
	CertPath    string   `json:"cert_path,omitempty"`
	KeyPath     string   `json:"key_path,omitempty"`
	P12Path     string   `json:"p12_path,omitempty"`
	PasswordRef string   `json:"password_ref,omitempty"`
}

type NetworkProfile struct {
	Name         string  `json:"name"`
	LatencyMS    int     `json:"latency_ms"`
	DownloadKBps float64 `json:"download_kbps"`
	UploadKBps   float64 `json:"upload_kbps"`
	PacketLoss   float64 `json:"packet_loss"`
}

type ScriptSettings struct {
	FirstOnly bool `json:"first_only,omitzero"`
	AllowEnv  bool `json:"allow_env,omitzero"`
}

const (
	HTTP1Only   = "http1_only"
	PreferHTTP2 = "prefer_http2"
)

func (d *Data) HTTPVersionMode() string {
	if d.DisableHTTP2 {
		return HTTP1Only
	}
	return PreferHTTP2
}

func (d *Data) SetHTTPVersionMode(mode string) error {
	switch mode {
	case HTTP1Only:
		d.DisableHTTP2 = true
	case PreferHTTP2:
		d.DisableHTTP2 = false
	default:
		return fmt.Errorf("unknown HTTP version mode %q: use %s or %s", mode, HTTP1Only, PreferHTTP2)
	}
	return nil
}

func (d *Data) LeafValidity() time.Duration {
	return time.Duration(cmp.Or(d.LeafValidityDays, DefaultLeafDays)) * 24 * time.Hour
}

const DefaultLeafDays = 397

const MaxFolderDepth = 2

func CleanFolder(folder string) (string, string) {
	var parts []string
	for p := range strings.SplitSeq(folder, "/") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) > MaxFolderDepth {
		return strings.Join(parts, "/"), fmt.Sprintf("Folders nest %d deep at most.", MaxFolderDepth)
	}
	return strings.Join(parts, "/"), ""
}

func (m TemplateMessage) TemplateHeader() http.Header {
	h := http.Header{}
	for _, p := range m.Header {
		h.Add(p.Name, p.Value)
	}
	return h
}

func RawOf(response bool, method, target string, status int, header []Pair, body []byte) string {
	var b bytes.Buffer
	if response {
		fmt.Fprintf(&b, "HTTP/1.1 %d %s\n", status, http.StatusText(status))
	} else {
		fmt.Fprintf(&b, "%s %s HTTP/1.1\n", cmp.Or(method, "GET"), cmp.Or(target, "/"))
	}
	for _, h := range header {
		fmt.Fprintf(&b, "%s: %s\n", h.Name, h.Value)
	}
	b.WriteString("\n")
	_, _ = io.Copy(&b, bytes.NewReader(body))
	return b.String()
}
