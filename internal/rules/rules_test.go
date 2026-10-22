package rules

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchURL(t *testing.T) {
	cases := []struct {
		pattern, url, mode string
		sub, want          bool
	}{
		{"http://localhost/*", "http://localhost:3000/api", "", false, true},
		{"localhost/api", "http://localhost:3000/api?x=1", "", false, true},
		{"127.0.0.1", "http://127.0.0.1:8080/", "", false, true},
		{"localhost:3000/*", "http://localhost:3000/api", "", false, true},
		{"localhost:3000/*", "http://localhost:4000/api", "", false, false},
		{"http://[::1]/*", "http://[::1]:8080/x", "", false, true},
		{"https://example.com/api/*", "https://example.com/api/users", "", false, true},
		{"https://example.com/api/*", "https://example.com/api", "", false, true},
		{"https://example.com/api/*", "http://example.com/api/users", "", false, false},
		{"example.com/api/*", "http://example.com/api/users?x=1", "", false, true},
		{"example.com", "https://example.com/", "", false, true},
		{"example.com", "https://example.com/?q=1", "", false, true},
		{"example.com", "https://example.com/deep", "", false, false},
		{"example.com", "https://example.com/deep", "", true, true},
		{"https://example.com/api", "https://example.com/api/v1/x", "", true, true},
		{"https://example.com/api", "https://example.com/apis", "", true, false},
		{"*.example.com/*", "https://cdn.example.com/a.js", "", false, true},
		{"*", "https://anything.dev/x", "", false, true},
		{`^https://api\.[a-z]+\.com/v\d+/`, "https://api.github.com/v3/users", "regex", false, true},
		{`^https://api\.[a-z]+\.com/v\d+/`, "https://api.github.com/users", "regex", false, false},
		{`(unclosed`, "https://x", "regex", false, false},
		{"HTTPS://EXAMPLE.COM/API/*", "https://example.com/api/x", "", false, true},
	}
	for _, tc := range cases {
		if got := MatchURL(tc.pattern, tc.url, tc.mode, tc.sub); got != tc.want {
			t.Errorf("MatchURL(%q, %q, %q, %v) = %v", tc.pattern, tc.url, tc.mode, tc.sub, got)
		}
	}
}

func TestMatcherMethodAndGraphQL(t *testing.T) {
	m := Matcher{URL: "https://api.dev/graphql", Method: "POST", GraphQL: "Get*"}
	if !m.MatchesGraphQL("POST", "https://api.dev/graphql", "GetUser") {
		t.Fatal("GraphQL operation should match")
	}
	if m.MatchesGraphQL("POST", "https://api.dev/graphql", "UpdateUser") {
		t.Fatal("other operation matched")
	}
	if m.MatchesGraphQL("GET", "https://api.dev/graphql", "GetUser") {
		t.Fatal("other method matched")
	}
	any := Matcher{URL: "*", Method: "ANY"}
	if !any.Matches("PATCH", "http://x/") {
		t.Fatal("ANY should match every method")
	}
	if (Matcher{URL: "(", Match: "regex"}).Valid() == "" || (Matcher{}).Valid() == "" {
		t.Fatal("invalid matchers reported valid")
	}
	if (Matcher{URL: "*"}).Describe() != "ANY · Wildcard" {
		t.Fatal((Matcher{URL: "*"}).Describe())
	}
}

func TestShouldMITM(t *testing.T) {
	d := Data{SSL: SSL{Enabled: true, Rules: []*SSLRule{
		{Enabled: true, List: "include", Target: "*.example.com"},
		{Enabled: true, List: "include", Target: "api.dev"},
		{Enabled: true, List: "exclude", Target: "secure.example.com"},
		{Enabled: false, List: "include", Target: "off.dev"},
	}}}
	for host, want := range map[string]bool{
		"www.example.com":    true,
		"secure.example.com": false,
		"api.dev":            true,
		"v2.api.dev":         true,
		"off.dev":            false,
		"other.org":          false,
	} {
		if got := d.ShouldMITM(host); got != want {
			t.Errorf("ShouldMITM(%s) = %v", host, got)
		}
	}
	d.SSL.Enabled = false
	if d.ShouldMITM("api.dev") {
		t.Fatal("SSL proxying off still decrypts")
	}
}

func TestToolSwitches(t *testing.T) {
	d := Data{
		MapLocal:    []*MapLocalRule{{Enabled: true, Matcher: Matcher{URL: "*"}}},
		Breakpoints: []*BreakpointRule{{Enabled: true, Matcher: Matcher{URL: "*"}, Phase: PhaseRequest}},
		Block:       []*URLRule{{Enabled: true, Matcher: Matcher{URL: "*/ads/*"}}},
	}
	if d.MapLocalFor("GET", "http://x/", "") == nil {
		t.Fatal("map local should match")
	}
	if d.BreakpointFor("GET", "http://x/", "", false) == nil || d.BreakpointFor("GET", "http://x/", "", true) != nil {
		t.Fatal("request breakpoint phases")
	}
	d.DisabledTools = map[string]bool{ToolMapLocal: true, ToolBreakpoint: true, ToolBlock: true}
	if d.MapLocalFor("GET", "http://x/", "") != nil || d.BreakpointFor("GET", "http://x/", "", false) != nil {
		t.Fatal("disabled tools still match")
	}
	if blocked, _, _ := d.Blocked("GET", "http://x/ads/1"); blocked {
		t.Fatal("disabled block list blocks")
	}
}

func TestBlockAndAllow(t *testing.T) {
	d := Data{
		Block: []*URLRule{{Enabled: true, Name: "ads", Matcher: Matcher{URL: "*/ads/*"}, Action: BlockHide}},
		Allow: []*URLRule{{Enabled: true, Matcher: Matcher{URL: "api.dev/*"}}},
	}
	if blocked, name, action := d.Blocked("GET", "https://api.dev/ads/1"); !blocked || name != "ads" || action != BlockHide {
		t.Fatalf("block rule: %v %q %q", blocked, name, action)
	}
	if blocked, _, _ := d.Blocked("GET", "https://api.dev/users"); blocked {
		t.Fatal("allowed URL blocked")
	}
	if blocked, name, _ := d.Blocked("GET", "https://other.dev/"); !blocked || name != "Not in Allow List" {
		t.Fatalf("allow list: %v %q", blocked, name)
	}
	h := Data{Block: []*URLRule{{Enabled: true, Matcher: Matcher{URL: "tracker.io"}}}}
	if blocked, _, _ := h.BlockedHost("tracker.io", 443); !blocked {
		t.Fatal("host block for tunnels")
	}
}

func TestMapRemoteRewrite(t *testing.T) {
	u, _ := url.Parse("https://prod.api.com/v1/users?id=1")
	cases := []struct {
		rule MapRemoteRule
		want string
	}{
		{MapRemoteRule{NewURL: "http://localhost:3000"}, "http://localhost:3000/v1/users?id=1"},
		{MapRemoteRule{NewURL: "https://staging.api.com/v2/people"}, "https://staging.api.com/v2/people?id=1"},
		{MapRemoteRule{Host: "staging.api.com"}, "https://staging.api.com/v1/users?id=1"},
		{MapRemoteRule{Scheme: "http", Host: "127.0.0.1", Port: 8080}, "http://127.0.0.1:8080/v1/users?id=1"},
		{MapRemoteRule{Path: "/v2/users", Query: "id=2"}, "https://prod.api.com/v2/users?id=2"},
		{MapRemoteRule{Matcher: Matcher{URL: "https://prod.api.com/v1", IncludeSubpaths: true}, NewURL: "https://new.api.com/api/v1"}, "https://new.api.com/api/v1/users?id=1"},
	}
	for _, tc := range cases {
		got, err := tc.rule.Rewrite(u)
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != tc.want {
			t.Errorf("%+v: %s, want %s", tc.rule, got, tc.want)
		}
	}
	if _, err := (&MapRemoteRule{NewURL: "not a url"}).Rewrite(u); err == nil {
		t.Fatal("bad URL accepted")
	}
}

func TestUpstreamAndAccess(t *testing.T) {
	up := Upstream{Enabled: true, HTTP: "127.0.0.1:8080", HTTPS: "http://10.0.0.1:3128", Bypass: []string{"*.internal"}}
	if p := up.ProxyFor("http", "example.com"); p == nil || p.Host != "127.0.0.1:8080" {
		t.Fatalf("http proxy %v", p)
	}
	if p := up.ProxyFor("https", "example.com"); p == nil || p.Host != "10.0.0.1:3128" {
		t.Fatalf("https proxy %v", p)
	}
	if p := up.ProxyFor("https", "db.internal"); p != nil {
		t.Fatal("bypassed host proxied")
	}
	up.Enabled = false
	if up.ProxyFor("http", "x") != nil {
		t.Fatal("disabled upstream used")
	}

	ac := AccessControl{Mode: AccessList, IPs: []string{"192.168.1.0/24", "10.1.2.3"}}
	for ip, want := range map[string]bool{"127.0.0.1": true, "192.168.1.77": true, "10.1.2.3": true, "10.1.2.4": false, "::1": true} {
		if got := ac.Allowed(net.ParseIP(ip)); got != want {
			t.Errorf("Allowed(%s) = %v", ip, got)
		}
	}
	ask := AccessControl{Mode: AccessAsk, IPs: []string{"10.1.2.3"}}
	if !ask.Allowed(net.ParseIP("10.1.2.3")) || ask.Allowed(net.ParseIP("10.9.9.9")) || !ask.Allowed(net.ParseIP("127.0.0.1")) {
		t.Fatal("ask mode lets listed and local devices in, and asks about others")
	}
	if (AccessControl{Mode: AccessLocal}).Allowed(net.ParseIP("10.9.9.9")) {
		t.Fatal("local-only allowed a remote client")
	}
	if !(AccessControl{}).Allowed(net.ParseIP("10.9.9.9")) {
		t.Fatal("default access denied a client")
	}
}

func TestDNSAndClientCert(t *testing.T) {
	d := Data{
		DNS:         []*DNSRule{{Enabled: true, Host: "api.dev", IP: "127.0.0.1"}},
		ClientCerts: []*ClientCertificate{{Enabled: true, Host: "*.bank.com", CertPath: "c"}},
	}
	if r := d.DNSFor("v1.api.dev."); r == nil || r.IP != "127.0.0.1" {
		t.Fatal("DNS rule should cover subdomains")
	}
	if d.ClientCertFor("www.bank.com") == nil || d.ClientCertFor("bank.org") != nil {
		t.Fatal("client certificate host match")
	}
}

func TestStorePersistsAndMigrates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	old := `{"throttle":{"enabled":true,"name":"3G","latency_ms":200,"download_kbps":780},
	"external_proxy":"http://127.0.0.1:8888",
	"map_local":[{"id":"A","enabled":true,"name":"x","url":"https://a/*","path":"/tmp/x","match":"wildcard"}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s := Open(path)
	d := s.Snapshot()
	if len(d.NetworkConditions) != 1 || d.NetworkConditions[0].LatencyMS != 200 || d.NetworkConditions[0].URL != "*" {
		t.Fatalf("throttle not migrated: %+v", d.NetworkConditions)
	}
	if !d.Upstream.Enabled || d.Upstream.HTTPS != "http://127.0.0.1:8888" {
		t.Fatalf("external proxy not migrated: %+v", d.Upstream)
	}
	if len(d.MapLocal) != 1 || d.MapLocal[0].URL != "https://a/*" {
		t.Fatalf("flattened matcher not read: %+v", d.MapLocal)
	}
	if len(d.Bypass) == 0 || d.Socks.Port != DefaultSocksPort {
		t.Fatalf("defaults missing: %+v %+v", d.Bypass, d.Socks)
	}

	v := s.Version()
	s.Update(func(d *Data) {
		d.Breakpoints = append(d.Breakpoints, &BreakpointRule{ID: "B", Enabled: true, Matcher: Matcher{URL: "*"}, Phase: PhaseBoth})
	})
	if s.Version() == v {
		t.Fatal("version did not change")
	}
	if len(s.Current().Breakpoints) != 1 {
		t.Fatal("current rules not updated")
	}
	reopened := Open(path)
	if len(reopened.Snapshot().Breakpoints) != 1 {
		t.Fatal("update not saved")
	}
	raw, _ := os.ReadFile(path) // #nosec G304 -- a file of the test's directory.
	if strings.Contains(string(raw), `"throttle"`) || strings.Contains(string(raw), `"external_proxy"`) {
		t.Fatal("migrated keys written back")
	}

	snap := s.Snapshot()
	snap.Breakpoints[0].URL = "changed"
	if s.Current().Breakpoints[0].URL != "*" {
		t.Fatal("snapshot shares rules with the store")
	}

	backup := filepath.Join(dir, "backup.json")
	if err := s.Export(backup); err != nil {
		t.Fatal(err)
	}
	other := Memory(Data{})
	if err := other.Import(backup); err != nil {
		t.Fatal(err)
	}
	if len(other.Current().Breakpoints) != 1 || len(other.Current().MapLocal) != 1 {
		t.Fatal("import lost rules")
	}
	if err := other.Import(path + ".missing"); err == nil {
		t.Fatal("import of a missing file succeeded")
	}
}

func TestBreakpointTemplates(t *testing.T) {
	resp := &BreakpointTemplate{Response: true, Raw: "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nX-Long: a\r\n b\r\n\r\n{\"e\":1}\n"}
	m, err := resp.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if m.StatusCode != 503 || len(m.Header) != 2 || m.Header[1].Value != "a b" || string(m.Body) != "{\"e\":1}\n" {
		t.Errorf("%+v", m)
	}
	req := &BreakpointTemplate{Raw: "post https://api.dev/x?y=1 HTTP/1.1\nContent-Type: text/plain\n\nhello"}
	if m, err := req.Parse(); err != nil || m.Method != "POST" || m.URL != "https://api.dev/x?y=1" || string(m.Body) != "hello" {
		t.Errorf("%+v %v", m, err)
	}
	if m, err := (&BreakpointTemplate{Response: true, Raw: "HTTP/1.1 204 No Content"}).Parse(); err != nil || m.StatusCode != 204 {
		t.Errorf("no body: %+v %v", m, err)
	}
	for _, bad := range []*BreakpointTemplate{{Response: true, Raw: "GET / HTTP/1.1\n\n"}, {Response: true, Raw: "HTTP/1.1 abc"}, {Raw: ""}, {Raw: "GET / HTTP/1.1\nno colon\n\n"}} {
		if _, err := bad.Parse(); err == nil {
			t.Errorf("%q parsed", bad.Raw)
		}
	}
	raw := RawOf(true, "", "", 429, []Pair{{"Retry-After", "1"}}, []byte("x"))
	if m, err := (&BreakpointTemplate{Response: true, Raw: raw}).Parse(); err != nil || m.StatusCode != 429 || string(m.Body) != "x" {
		t.Errorf("round trip %q: %+v %v", raw, m, err)
	}

	path := filepath.Join(t.TempDir(), "rules.json")
	s := Open(path)
	if len(s.Current().BreakpointTemplates) == 0 {
		t.Fatal("no default templates")
	}
	s.Update(func(d *Data) { d.BreakpointTemplates = d.BreakpointTemplates[:0] })
	if n := len(Open(path).Current().BreakpointTemplates); n != 0 {
		t.Errorf("deleted templates came back: %d", n)
	}
}

func TestNewRules(t *testing.T) {
	d := Data{
		BlockedApps: []*AppRule{{Enabled: true, BundleID: "com.example.app"}, {Enabled: true, AppName: "curl"}, {Enabled: false, AppName: "Safari"}},
		Protobuf:    []*ProtobufRule{{Enabled: true, Matcher: Matcher{URL: "api.dev/rpc/*"}, ResponseType: "demo.User"}},
		Scripts: []*ScriptRule{
			{ID: "1", Enabled: true, Matcher: Matcher{URL: "*"}},
			{ID: "2", Enabled: true, Matcher: Matcher{URL: "*"}},
		},
	}
	if d.BlockedApp("COM.EXAMPLE.APP", "Example") == nil || d.BlockedApp("", "CURL") == nil || d.BlockedApp("", "Safari") != nil || d.BlockedApp("com.other", "Other") != nil {
		t.Error("BlockedApp")
	}
	d.DisabledTools = map[string]bool{ToolBlock: true}
	if d.BlockedApp("com.example.app", "") != nil {
		t.Error("the Block List switch turns app rules off")
	}
	if r := d.ProtobufFor("POST", "https://api.dev/rpc/Get"); r == nil || r.ResponseType != "demo.User" {
		t.Error("ProtobufFor")
	}
	if n := len(d.ScriptsFor("GET", "https://x/", "")); n != 2 {
		t.Errorf("every script: %d", n)
	}
	d.Scripting.FirstOnly = true
	if s := d.ScriptsFor("GET", "https://x/", ""); len(s) != 1 || s[0].ID != "1" {
		t.Errorf("the first script: %v", s)
	}
	if d.HTTPVersionMode() != PreferHTTP2 || d.SetHTTPVersionMode(HTTP1Only) != nil || !d.DisableHTTP2 || d.SetHTTPVersionMode("auto") == nil {
		t.Error("HTTP version mode")
	}
	if d.LeafValidity() != 397*24*time.Hour {
		t.Error("LeafValidity")
	}
	if f, msg := CleanFolder(" API / v1 /"); f != "API/v1" || msg != "" {
		t.Errorf("CleanFolder %q %q", f, msg)
	}
	if _, msg := CleanFolder("a/b/c"); msg == "" {
		t.Error("three levels")
	}
}
