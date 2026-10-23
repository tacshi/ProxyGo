package rules

import (
	"cmp"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	ToolMapLocal   = "maplocal"
	ToolMapRemote  = "mapremote"
	ToolBreakpoint = "breakpoint"
	ToolScripting  = "scripting"
	ToolBlock      = "block"
	ToolAllow      = "allow"
	ToolDNS        = "dns"
	ToolNetwork    = "network"
	ToolReverse    = "reverse"
)

var AllTools = []struct{ ID, Name string }{
	{ToolBreakpoint, "Breakpoint"},
	{ToolMapLocal, "Map Local"},
	{ToolMapRemote, "Map Remote"},
	{ToolScripting, "Scripting"},
	{ToolBlock, "Block List"},
	{ToolAllow, "Allow List"},
	{ToolNetwork, "Network Conditions"},
	{ToolDNS, "DNS Spoofing"},
	{ToolReverse, "Reverse Proxy"},
}

type Matcher struct {
	URL             string `json:"url"`
	Match           string `json:"match"`
	IncludeSubpaths bool   `json:"include_subpaths"`
	Method          string `json:"method"`
	GraphQL         string `json:"graphql,omitempty"`
}

func (m Matcher) Matches(method, rawURL string) bool {
	return m.MatchesGraphQL(method, rawURL, "")
}

func (m Matcher) MatchesGraphQL(method, rawURL, op string) bool {
	if m.Method != "" && !strings.EqualFold(m.Method, "ANY") && !strings.EqualFold(m.Method, method) {
		return false
	}
	if g := strings.TrimSpace(m.GraphQL); g != "" {
		if op == "" || !wildcard(g, op) {
			return false
		}
	}
	return matchURL(m.URL, rawURL, m.Match, m.IncludeSubpaths)
}

func (m Matcher) Describe() string {
	var parts []string
	method := m.Method
	if method == "" {
		method = "ANY"
	}
	parts = append(parts, strings.ToUpper(method))
	if m.Match == "regex" {
		parts = append(parts, "Regex")
	} else {
		parts = append(parts, "Wildcard")
	}
	if m.IncludeSubpaths {
		parts = append(parts, "Subpaths")
	}
	if m.GraphQL != "" {
		parts = append(parts, "GraphQL "+m.GraphQL)
	}
	return strings.Join(parts, " · ")
}

func (m Matcher) Valid() string {
	if strings.TrimSpace(m.URL) == "" {
		return "Enter a URL to match."
	}
	if m.Match == "regex" {
		if _, err := regexp.Compile(m.URL); err != nil {
			return "Invalid regular expression: " + err.Error()
		}
	}
	return ""
}

type SSL struct {
	Enabled bool       `json:"feature_enabled"`
	Rules   []*SSLRule `json:"rules"`
}

type SSLRule struct {
	ID         string `json:"id"`
	Enabled    bool   `json:"enabled"`
	List       string `json:"list"`
	Target     string `json:"target"`
	TargetType string `json:"target_type"`
}

type Pair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type MapLocalRule struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name"`
	Matcher     `json:",inline"`
	Path        string `json:"path"`
	DelayMS     int    `json:"delay_ms"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type"`
	Headers     []Pair `json:"headers,omitempty"`
	Body        string `json:"body,omitempty"`
	Folder      string `json:"folder,omitempty"`
}

type MapRemoteRule struct {
	ID                  string `json:"id"`
	Enabled             bool   `json:"enabled"`
	Name                string `json:"name"`
	Matcher             `json:",inline"`
	NewURL              string `json:"new_url"`
	Folder              string `json:"folder,omitempty"`
	Scheme              string `json:"scheme,omitempty"`
	Host                string `json:"host,omitempty"`
	Port                int    `json:"port,omitzero"`
	Path                string `json:"path,omitempty"`
	Query               string `json:"query,omitempty"`
	PreserveHost        bool   `json:"preserve_host"`
	PreserveOriginalURL bool   `json:"preserve_original_url"`
}

func (r *MapRemoteRule) Rewrite(u *url.URL) (*url.URL, error) {
	out := u.Clone()
	if r.NewURL != "" {
		nu, err := url.Parse(r.NewURL)
		if err != nil || nu.Host == "" {
			return nil, fmt.Errorf("invalid Map Remote URL %q", r.NewURL)
		}
		out.Scheme = nu.Scheme
		out.Host = nu.Host
		if (nu.Path != "" && nu.Path != "/") || nu.RawQuery != "" {
			if r.IncludeSubpaths && !strings.ContainsAny(r.URL, "*?") && r.Match != "regex" {
				base := strings.TrimSuffix(stripScheme(r.URL), "/")
				rest := strings.TrimPrefix(stripScheme(u.String()), base)
				rest, _, _ = strings.Cut(rest, "?")
				out.Path = strings.TrimSuffix(nu.Path, "/") + rest
			} else {
				out.Path = nu.Path
			}
			out.RawPath = ""
			if nu.RawQuery != "" {
				out.RawQuery = nu.RawQuery
			}
		}
	}
	if r.Scheme != "" {
		out.Scheme = strings.ToLower(r.Scheme)
	}
	if r.Host != "" || r.Port > 0 {
		host, port := out.Hostname(), out.Port()
		if r.Host != "" {
			host = r.Host
		}
		if r.Port > 0 {
			port = strconv.Itoa(r.Port)
		}
		if port == "" || (port == "443" && out.Scheme == "https") || (port == "80" && out.Scheme == "http") {
			out.Host = hostLiteral(host)
		} else {
			out.Host = net.JoinHostPort(host, port)
		}
	}
	if r.Path != "" {
		out.Path = r.Path
		out.RawPath = ""
	}
	if r.Query != "" {
		out.RawQuery = strings.TrimPrefix(r.Query, "?")
	}
	if out.Scheme == "" {
		out.Scheme = "https"
	}
	return out, nil
}

func hostLiteral(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

const (
	BlockDisplay = ""
	BlockHide    = "hide"
)

type URLRule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Matcher `json:",inline"`
	Action  string `json:"action,omitempty"`
}

type DNSRule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Port    int    `json:"port,omitzero"`
}

type ScriptRule struct {
	ID           string `json:"id"`
	Enabled      bool   `json:"enabled"`
	Name         string `json:"name"`
	Matcher      `json:",inline"`
	Script       string `json:"script"`
	OnRequest    bool   `json:"on_request"`
	OnResponse   bool   `json:"on_response"`
	MockResponse bool   `json:"mock_response"`
}

const (
	PhaseRequest  = "request"
	PhaseResponse = "response"
	PhaseBoth     = "both"
)

type BreakpointRule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Matcher `json:",inline"`
	Phase   string `json:"phase"`
}

type Throttle struct {
	Enabled      bool    `json:"enabled"`
	Name         string  `json:"name"`
	LatencyMS    int     `json:"latency_ms"`
	DownloadKBps float64 `json:"download_kbps"`
	UploadKBps   float64 `json:"upload_kbps"`
	PacketLoss   float64 `json:"packet_loss"`
}

type NetworkCondition struct {
	ID           string `json:"id"`
	Enabled      bool   `json:"enabled"`
	Name         string `json:"name"`
	Matcher      `json:",inline"`
	LatencyMS    int     `json:"latency_ms"`
	DownloadKBps float64 `json:"download_kbps"`
	UploadKBps   float64 `json:"upload_kbps"`
	PacketLoss   float64 `json:"packet_loss"`
}

type Preset struct {
	Name         string
	LatencyMS    int
	DownloadKBps float64
	UploadKBps   float64
	PacketLoss   float64
}

var Presets = []Preset{
	{"100% Loss", 0, 0, 0, 100},
	{"Edge", 400, 30, 12, 0},
	{"3G", 200, 780, 330, 0},
	{"Slow 4G", 150, 1600, 750, 0},
	{"LTE", 50, 6000, 1500, 0},
	{"Very Bad Network", 500, 125, 125, 10},
	{"Wi-Fi", 2, 5000, 2500, 0},
	{"High Latency DNS", 1000, 0, 0, 0},
}

type ReverseProxy struct {
	ID           string `json:"id"`
	Enabled      bool   `json:"enabled"`
	Name         string `json:"name"`
	ListenPort   int    `json:"listen_port"`
	Target       string `json:"target"`
	PreserveHost bool   `json:"preserve_host,omitzero"`
}

type Upstream struct {
	Enabled bool     `json:"enabled"`
	HTTP    string   `json:"http"`
	HTTPS   string   `json:"https"`
	Bypass  []string `json:"bypass,omitempty"`
	PACURL  string   `json:"pac_url,omitempty"`
}

func (u Upstream) ProxyFor(scheme, host string) *url.URL {
	if !u.Enabled {
		return nil
	}
	raw := u.HTTP
	if scheme == "https" || scheme == "wss" {
		raw = u.HTTPS
		if raw == "" {
			raw = u.HTTP
		}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	for _, b := range u.Bypass {
		if hostMatch(b, strings.ToLower(host)) {
			return nil
		}
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	p, err := url.Parse(raw)
	if err != nil || p.Host == "" {
		return nil
	}
	return p
}

const hiddenDots = "••••••"

func proxyPassword(raw string) (start, end int, ok bool) {
	at := strings.LastIndexByte(raw, '@')
	if at < 0 {
		return 0, 0, false
	}
	from := 0
	if i := strings.Index(raw[:at], "://"); i >= 0 {
		from = i + 3
	}
	colon := strings.IndexByte(raw[from:at], ':')
	if colon < 0 {
		return 0, 0, false
	}
	return from + colon + 1, at, true
}

func MaskProxyPassword(raw string) string {
	start, end, ok := proxyPassword(raw)
	if !ok || start == end {
		return raw
	}
	return raw[:start] + hiddenDots + raw[end:]
}

func UnmaskProxyPassword(edited, old string) string {
	start, end, ok := proxyPassword(edited)
	if !ok || edited[start:end] != hiddenDots {
		return edited
	}
	oldStart, oldEnd, ok := proxyPassword(old)
	if !ok {
		return edited
	}
	return edited[:start] + old[oldStart:oldEnd] + edited[end:]
}

const (
	AccessAll   = ""
	AccessLocal = "local"
	AccessList  = "list"
	AccessAsk   = "ask"
)

type AccessControl struct {
	Mode string   `json:"mode"`
	IPs  []string `json:"ips,omitempty"`
}

func (a AccessControl) Allowed(ip net.IP) bool {
	if a.Mode == AccessAll || ip == nil {
		return true
	}
	if ip.IsLoopback() || isOwnAddress(ip) {
		return true
	}
	if a.Mode == AccessLocal {
		return false
	}
	for _, s := range a.IPs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			if n.Contains(ip) {
				return true
			}
			continue
		}
		if x := net.ParseIP(s); x != nil && x.Equal(ip) {
			return true
		}
	}
	return false
}

var ownAddrs = sync.OnceValue(func() []net.IP {
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP)
		}
	}
	return out
})

func isOwnAddress(ip net.IP) bool {
	for _, x := range ownAddrs() {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}

type Socks struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

const DefaultSocksPort = 8889

type ClientCertificate struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	CertPath    string `json:"cert_path"`
	KeyPath     string `json:"key_path"`
	P12Path     string `json:"p12_path,omitempty"`
	PasswordRef string `json:"password_ref,omitempty"`
}

var DefaultBypass = []string{"localhost", "*.local", "127.0.0.1", "169.254/16"}

type Data struct {
	SSL               SSL                  `json:"ssl"`
	MapLocal          []*MapLocalRule      `json:"map_local"`
	MapRemote         []*MapRemoteRule     `json:"map_remote"`
	Block             []*URLRule           `json:"block"`
	Allow             []*URLRule           `json:"allow"`
	DNS               []*DNSRule           `json:"dns"`
	Scripts           []*ScriptRule        `json:"scripts"`
	Breakpoints       []*BreakpointRule    `json:"breakpoints"`
	NetworkConditions []*NetworkCondition  `json:"network_conditions"`
	ReverseProxies    []*ReverseProxy      `json:"reverse_proxies"`
	ClientCerts       []*ClientCertificate `json:"client_certificates"`
	DisabledTools     map[string]bool      `json:"disabled_tools,omitempty"`

	BreakpointTemplates []*BreakpointTemplate `json:"breakpoint_templates"`
	BlockedApps         []*AppRule            `json:"blocked_apps,omitempty"`
	Protobuf            []*ProtobufRule       `json:"protobuf,omitempty"`
	ServerCerts         []*ServerCertificate  `json:"server_certificates,omitempty"`
	NetworkProfiles     []*NetworkProfile     `json:"network_profiles,omitempty"`
	Scripting           ScriptSettings        `json:"scripting,omitzero"`
	DiagnosticHeaders   bool                  `json:"diagnostic_headers,omitzero"`
	LeafValidityDays    int                   `json:"leaf_validity_days,omitzero"`

	NoCaching    bool          `json:"no_caching"`
	InsecureTLS  bool          `json:"insecure_tls"`
	DisableHTTP2 bool          `json:"disable_http2,omitzero"`
	KeyLogPath   string        `json:"tls_key_log,omitempty"`
	Upstream     Upstream      `json:"upstream"`
	Access       AccessControl `json:"access_control"`
	Socks        Socks         `json:"socks"`
	Bypass       []string      `json:"bypass"`

	Throttle      *Throttle `json:"throttle,omitzero"`
	ExternalProxy string    `json:"external_proxy,omitempty"`
}

func (d *Data) ToolOn(tool string) bool { return !d.DisabledTools[tool] }

type Store struct {
	mu      sync.Mutex
	data    Data
	path    string
	current atomic.Pointer[Data]
	version atomic.Uint64

	listenMu  sync.Mutex
	listeners map[int]func()
	nextID    int
}

func (s *Store) OnChange(fn func()) (off func()) {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	if s.listeners == nil {
		s.listeners = map[int]func(){}
	}
	id := s.nextID
	s.nextID++
	s.listeners[id] = fn
	return func() {
		s.listenMu.Lock()
		delete(s.listeners, id)
		s.listenMu.Unlock()
	}
}

func (s *Store) notify() {
	s.listenMu.Lock()
	fns := slices.Collect(maps.Values(s.listeners))
	s.listenMu.Unlock()
	for _, fn := range fns {
		go fn()
	}
}

func Open(path string) *Store {
	s := &Store{path: path}
	s.data.Bypass = append([]string(nil), DefaultBypass...)
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- ProxyGo's own rules file.
		_ = json.Unmarshal(b, &s.data)
	}
	if s.data.BreakpointTemplates == nil {
		s.data.BreakpointTemplates = DefaultTemplates()
	}
	s.normalize()
	s.publish()
	return s
}

func Memory(d Data) *Store {
	s := &Store{data: d}
	s.normalize()
	s.publish()
	return s
}

func (s *Store) normalize() {
	d := &s.data
	if d.Throttle != nil {
		if d.Throttle.Enabled || d.Throttle.LatencyMS > 0 || d.Throttle.DownloadKBps > 0 {
			t := d.Throttle
			d.NetworkConditions = append(d.NetworkConditions, &NetworkCondition{
				ID: NewID(), Enabled: t.Enabled, Name: cmp.Or(t.Name, "Custom"), Matcher: Matcher{URL: "*"},
				LatencyMS: t.LatencyMS, DownloadKBps: t.DownloadKBps, UploadKBps: t.UploadKBps, PacketLoss: t.PacketLoss,
			})
		}
		d.Throttle = nil
	}
	if d.ExternalProxy != "" {
		if d.Upstream.HTTP == "" && d.Upstream.HTTPS == "" {
			d.Upstream = Upstream{Enabled: true, HTTP: d.ExternalProxy, HTTPS: d.ExternalProxy}
		}
		d.ExternalProxy = ""
	}
	d.SSL.Rules = nonNil(d.SSL.Rules)
	d.MapLocal = nonNil(d.MapLocal)
	d.MapRemote = nonNil(d.MapRemote)
	d.Block = nonNil(d.Block)
	d.Allow = nonNil(d.Allow)
	d.DNS = nonNil(d.DNS)
	d.Scripts = nonNil(d.Scripts)
	d.Breakpoints = nonNil(d.Breakpoints)
	d.NetworkConditions = nonNil(d.NetworkConditions)
	d.ReverseProxies = nonNil(d.ReverseProxies)
	d.ClientCerts = nonNil(d.ClientCerts)
	d.ServerCerts = nonNil(d.ServerCerts)
	d.BreakpointTemplates = slices.DeleteFunc(d.BreakpointTemplates, isNil)
	d.BlockedApps = slices.DeleteFunc(d.BlockedApps, isNil)
	d.Protobuf = slices.DeleteFunc(d.Protobuf, isNil)
	d.NetworkProfiles = slices.DeleteFunc(d.NetworkProfiles, isNil)
	if d.Socks.Port == 0 {
		d.Socks.Port = DefaultSocksPort
	}
	for _, list := range [][]*URLRule{d.Block, d.Allow} {
		for _, r := range list {
			if r.ID == "" {
				r.ID = NewID()
			}
		}
	}
	for _, r := range d.MapLocal {
		r.Folder, _ = CleanFolder(r.Folder)
	}
	for _, r := range d.MapRemote {
		r.Folder, _ = CleanFolder(r.Folder)
	}
}

func isNil[T any](r *T) bool { return r == nil }

func nonNil[T any](list []*T) []*T {
	if list = slices.DeleteFunc(list, isNil); list == nil {
		return []*T{}
	}
	return list
}

func (s *Store) publish() {
	cp := clone(s.data)
	s.current.Store(&cp)
	s.version.Add(1)
}

func clone(d Data) Data {
	b, _ := json.Marshal(d)
	var out Data
	_ = json.Unmarshal(b, &out)
	return out
}

func (s *Store) Snapshot() Data {
	return clone(*s.current.Load())
}

func (s *Store) Current() *Data { return s.current.Load() }

func (s *Store) Version() uint64 { return s.version.Load() }

func (s *Store) Update(fn func(*Data)) {
	s.mu.Lock()
	fn(&s.data)
	s.normalize()
	s.publish()
	b, _ := json.Marshal(s.data, jsontext.WithIndent("  "))
	path := s.path
	if path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0o750)
		_ = os.WriteFile(path, b, 0o600)
	}
	s.mu.Unlock()
	s.notify()
}

func (s *Store) Export(path string) error {
	s.mu.Lock()
	b, err := json.Marshal(s.data, jsontext.WithIndent("  "))
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644) // #nosec G306 -- rules exported to the path the user chose.
}

func (s *Store) Import(path string) error {
	b, err := os.ReadFile(path) // #nosec G304 -- the rules file the user imports.
	if err != nil {
		return err
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("not a ProxyGo settings file: %w", err)
	}
	s.Update(func(cur *Data) { *cur = d })
	return nil
}

func (r *SSLRule) IsClient() bool { return r.TargetType == "client" }

func (d *Data) ShouldMITM(host string) bool { return d.ShouldMITMFor("", host) }

func (d *Data) ShouldMITMFor(client, host string) bool {
	if !d.SSL.Enabled {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	included := false
	for _, r := range d.SSL.Rules {
		if r == nil || !r.Enabled {
			continue
		}
		if r.IsClient() {
			if client == "" || !strings.EqualFold(r.Target, client) {
				continue
			}
		} else if !hostMatch(r.Target, host) {
			continue
		}
		if r.List == "exclude" {
			return false
		}
		included = true
	}
	return included
}

func (d *Data) MapLocalFor(method, rawURL, op string) *MapLocalRule {
	if !d.ToolOn(ToolMapLocal) {
		return nil
	}
	for _, r := range d.MapLocal {
		if r != nil && r.Enabled && r.MatchesGraphQL(method, rawURL, op) {
			return r
		}
	}
	return nil
}

func (d *Data) MapRemoteFor(method, rawURL, op string) *MapRemoteRule {
	if !d.ToolOn(ToolMapRemote) {
		return nil
	}
	for _, r := range d.MapRemote {
		if r == nil || !r.Enabled {
			continue
		}
		if r.NewURL == "" && r.Scheme == "" && r.Host == "" && r.Port == 0 && r.Path == "" && r.Query == "" {
			continue
		}
		if r.MatchesGraphQL(method, rawURL, op) {
			return r
		}
	}
	return nil
}

func (d *Data) Blocked(method, rawURL string) (bool, string, string) {
	if d.ToolOn(ToolBlock) {
		for _, r := range d.Block {
			if r != nil && r.Enabled && r.Matches(method, rawURL) {
				return true, cmp.Or(r.Name, r.URL), r.Action
			}
		}
	}
	if !d.ToolOn(ToolAllow) {
		return false, "", ""
	}
	hasAllow := false
	for _, r := range d.Allow {
		if r == nil || !r.Enabled {
			continue
		}
		hasAllow = true
		if r.Matches(method, rawURL) {
			return false, "", ""
		}
	}
	if hasAllow {
		return true, "Not in Allow List", BlockDisplay
	}
	return false, "", ""
}

func (d *Data) BlockedHost(host string, port int) (bool, string, string) {
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	root := scheme + "://" + host + "/"
	if d.ToolOn(ToolBlock) {
		for _, r := range d.Block {
			if r == nil || !r.Enabled {
				continue
			}
			if r.Matches("CONNECT", root) || r.Matches("GET", root) || r.Matches("CONNECT", scheme+"://"+host) {
				return true, cmp.Or(r.Name, r.URL), r.Action
			}
		}
	}
	return false, "", ""
}

func (d *Data) ScriptsFor(method, rawURL, op string) []*ScriptRule {
	if !d.ToolOn(ToolScripting) {
		return nil
	}
	var out []*ScriptRule
	for _, r := range d.Scripts {
		if r != nil && r.Enabled && r.MatchesGraphQL(method, rawURL, op) {
			out = append(out, r)
			if d.Scripting.FirstOnly {
				break
			}
		}
	}
	return out
}

func (d *Data) BreakpointFor(method, rawURL, op string, response bool) *BreakpointRule {
	if !d.ToolOn(ToolBreakpoint) {
		return nil
	}
	for _, r := range d.Breakpoints {
		if r == nil || !r.Enabled || !r.MatchesGraphQL(method, rawURL, op) {
			continue
		}
		if response && r.Phase == PhaseRequest {
			continue
		}
		if !response && r.Phase == PhaseResponse {
			continue
		}
		return r
	}
	return nil
}

func (d *Data) ConditionFor(method, rawURL string) *NetworkCondition {
	if !d.ToolOn(ToolNetwork) {
		return nil
	}
	for _, r := range d.NetworkConditions {
		if r != nil && r.Enabled && r.Matches(method, rawURL) {
			return r
		}
	}
	return nil
}

func (d *Data) DNSFor(host string) *DNSRule {
	if !d.ToolOn(ToolDNS) {
		return nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, r := range d.DNS {
		if r != nil && r.Enabled && hostMatch(r.Host, host) {
			return r
		}
	}
	return nil
}

func (d *Data) ClientCertFor(host string) *ClientCertificate {
	host = strings.ToLower(host)
	for _, r := range d.ClientCerts {
		if r != nil && r.Enabled && hostMatch(r.Host, host) {
			return r
		}
	}
	return nil
}

func HostMatch(pattern, host string) bool { return hostMatch(pattern, strings.ToLower(host)) }

func hostMatch(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if i := strings.Index(pattern, "://"); i >= 0 {
		pattern = pattern[i+3:]
	}
	pattern, _, _ = strings.Cut(pattern, "/")
	if strings.ContainsAny(pattern, "*?") {
		return wildcard(pattern, host)
	}
	if pattern == host {
		return true
	}
	return strings.HasSuffix(host, "."+pattern)
}

var regexCache sync.Map

func compiled(pattern string) *regexp.Regexp {
	if v, ok := regexCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	regexCache.Store(pattern, re)
	return re
}

func wildcardRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?is)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return compiled(b.String())
}

func wildcard(pattern, s string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return strings.EqualFold(pattern, s)
	}
	re := wildcardRegexp(pattern)
	return re != nil && re.MatchString(s)
}

func MatchURL(pattern, rawURL, mode string, includeSubpaths bool) bool {
	return matchURL(pattern, rawURL, mode, includeSubpaths)
}

func matchURL(pattern, rawURL, mode string, includeSubpaths bool) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if mode == "regex" {
		re := compiled(pattern)
		return re != nil && re.MatchString(rawURL)
	}
	subject := rawURL
	if !strings.Contains(pattern, "://") {
		subject = stripScheme(rawURL)
	}
	if !hasPort(pattern) {
		subject = stripPort(subject)
	}
	if pattern == "*" {
		return true
	}
	if strings.ContainsAny(pattern, "*?") {
		if wildcard(pattern, subject) {
			return true
		}
		if base, ok := strings.CutSuffix(pattern, "/*"); ok && strings.EqualFold(strings.TrimSuffix(subject, "/"), base) {
			return true
		}
		return includeSubpaths && wildcard(strings.TrimSuffix(pattern, "/")+"/*", subject)
	}
	if !strings.Contains(pattern, "?") {
		subject, _, _ = strings.Cut(subject, "?")
	}
	base := strings.TrimSuffix(pattern, "/")
	subj := strings.TrimSuffix(subject, "/")
	if strings.EqualFold(subj, base) {
		return true
	}
	if !strings.Contains(base, "/") {
		if path, ok := strings.CutPrefix(strings.ToLower(subject), strings.ToLower(base)); ok && (path == "/" || strings.HasPrefix(path, "/?")) {
			return true
		}
	}
	if includeSubpaths {
		lower := strings.ToLower(subject)
		lb := strings.ToLower(base)
		return strings.HasPrefix(lower, lb+"/") || strings.HasPrefix(lower, lb+"?")
	}
	return false
}

func authority(s string) (string, int) {
	start := 0
	if i := strings.Index(s, "://"); i >= 0 {
		start = i + 3
	}
	end := len(s)
	if i := strings.IndexAny(s[start:], "/?"); i >= 0 {
		end = start + i
	}
	return s[start:end], start
}

func hasPort(s string) bool {
	a, _ := authority(s)
	if strings.HasPrefix(a, "[") {
		return strings.Contains(a, "]:")
	}
	return strings.Contains(a, ":")
}

func stripPort(s string) string {
	a, start := authority(s)
	i := strings.LastIndexByte(a, ':')
	if i < 0 || strings.HasSuffix(a, "]") || !strings.HasPrefix(a, "[") && strings.Count(a, ":") > 1 {
		return s
	}
	return s[:start+i] + s[start+len(a):]
}

func stripScheme(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		return rawURL[i+3:]
	}
	return rawURL
}

func NewID() string { return rand.Text()[:10] }
