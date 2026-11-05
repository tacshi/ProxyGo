package mcp

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"proxygo/internal/control/hosttest"
	"proxygo/internal/flow"
)

func TestRedactBody(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		// Numbers under password, PIN and one-time code keys are secrets;
		// usage counts are not.
		{`{"otp":123456,"usage":{"total_tokens":12}}`, `{"otp":"<redacted>","usage":{"total_tokens":12}}`},
		// Every string a sensitive key holds is, however deep.
		{`{"credentials":{"user":"ada","key":"k1"},"api_keys":["a","b"]}`, `{"api_keys":["<redacted>","<redacted>"],"credentials":{"key":"<redacted>","user":"<redacted>"}}`},
		// Each value of an NDJSON body is redacted, and none is dropped.
		{"{\"id\":1}\n{\"token\":\"t2\"}\n", "{\"id\":1}\n{\"token\":\"<redacted>\"}"},
	} {
		got, changed := redactBody([]byte(c.body), "application/json")
		if !changed || string(got) != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.body, got, c.want)
		}
	}
	for _, body := range []string{`{"id":1,"active":true,"token":""}`, `{"a":1} not json`} {
		if got, changed := redactBody([]byte(body), "application/json"); changed || string(got) != body {
			t.Errorf("%s changed: %s", body, got)
		}
	}
}

// A text body cut at the limit stays text, rather than reading as binary
// data, when the limit falls inside a character.
func TestTruncatedTextStaysText(t *testing.T) {
	s := &Server{Redact: func() bool { return false }}
	var redacted bool
	m := s.message(flow.Header{}, []byte("ab€cd"), "text/plain", 4, false, &redacted)
	if m.Body != "ab" || !m.Truncated {
		t.Errorf("body %q, truncated %v", m.Body, m.Truncated)
	}
	m = s.message(flow.Header{}, []byte(strings.Repeat("x", 10)), "text/plain", 4, false, &redacted)
	if m.Body != "xxxx" || !m.Truncated {
		t.Errorf("body %q, truncated %v", m.Body, m.Truncated)
	}
}

func TestRedactBodyFormats(t *testing.T) {
	for _, c := range []struct{ body, ct, secret string }{
		{")]}'\n{\"access_token\":\"S1\"}", "application/json", "S1"},
		{"\ufeff{\"token\":\"S2\"}", "application/json", "S2"},
		{"while(1);{\"token\":\"S3\"}", "", "S3"},
		{"{\"protocol\":\"json\"}\x1e{\"arguments\":[{\"token\":\"S4\"}]}\x1e", "application/json", "S4"},
		{"{\"refresh_token\":\"S5\",\"data\":\"cut", "application/json", "S5"},
		{`{"pin":"S6"}`, "application/json", "S6"},
		{`[{"name":"Authorization","value":"Bearer S7"}]`, "application/json", "S7"},
		{"--XX\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nS8\r\n--XX\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"api_key\":\"S9\"}\r\n--XX--\r\n", "multipart/form-data; boundary=XX", "S8 S9"},
		{"<a href=\"/cb?state=1&access_token=S10\">", "text/html", "S10"},
	} {
		out, changed := redactBody([]byte(c.body), c.ct)
		for secret := range strings.FieldsSeq(c.secret) {
			if !changed || strings.Contains(string(out), secret) {
				t.Errorf("%q leaks %s: %q", c.body, secret, out)
			}
		}
	}
	multipart := "--XX\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nada\r\n--XX\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nS\r\n--XX--\r\n"
	out, _ := redactBody([]byte(multipart), "multipart/form-data; boundary=XX")
	if want := strings.Replace(multipart, "\r\n\r\nS\r\n", "\r\n\r\n<redacted>\r\n", 1); string(out) != want {
		t.Errorf("multipart:\n got %q\nwant %q", out, want)
	}
	for _, body := range []string{"plain text", `{"key":"settings","value":"dark"}`, "a=1&b=2"} {
		if out, changed := redactBody([]byte(body), "text/plain"); changed {
			t.Errorf("%q changed: %q", body, out)
		}
	}
}

func TestRedactHeaders(t *testing.T) {
	h := flow.NewHeaderOrdered(http.Header{"Private-Token": {"S1"}, "X-Vault-Token": {"S2"}, "Referer": {"https://site/reset?token=S3"},
		"Access-Control-Allow-Credentials": {"true"}, "Accept": {"*/*"}},
		[]flow.SentHeader{{Name: ":path", Value: "/v1/me?access_token=S4&page=2"}, {Name: "Private-Token"}, {Name: "X-Vault-Token"}, {Name: "Referer"}, {Name: "Access-Control-Allow-Credentials"}, {Name: "Accept"}})
	out, changed := redactHeader(h)
	var all []string
	for _, e := range out.Entries {
		all = append(all, e.Key.Name+": "+e.Value)
	}
	text := strings.Join(all, "\n")
	if !changed || regexpSecret.MatchString(text) {
		t.Errorf("headers leak:\n%s", text)
	}
	for _, want := range []string{"Access-Control-Allow-Credentials: true", "Accept: */*", "page=2"} {
		if !strings.Contains(text, want) {
			t.Errorf("lost %q:\n%s", want, text)
		}
	}
}

var regexpSecret = regexp.MustCompile(`\bS\d\b`)

func TestRedactedToolOutputs(t *testing.T) {
	h, err := hosttest.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := flow.New("F1")
	f.Request = &flow.Request{Scheme: "https", Host: "api.dev", Port: 443, FullPath: "https://api.dev/v1/me", URI: "/v1/me",
		Method: flow.Method{Name: "GET"}, Header: flow.NewHeader(http.Header{"Private-Token": {"glpat-S1"}})}
	f.Response = &flow.Response{Status: &flow.Status{Code: 200, Phrase: "OK"}, Header: flow.NewHeader(http.Header{"Set-Cookie": {"sid=S2"}, "Content-Type": {"application/json"}}),
		BodyData: flow.Blob(`{"access_token":"S3"}`)}
	f.ToolMetadata = map[string]any{"mapRemote": map[string]any{"url": "https://staging.dev/v1/me?token=S4"}}
	h.S.Upsert(f)
	s := New(h, t.TempDir())
	c := connect(t, s)
	for name, args := range map[string]any{
		"get_flow_detail":            map[string]any{"flow_id": "F1"},
		"create_map_local_from_flow": map[string]any{"flow_id": "F1"},
		"list_rules":                 map[string]any{"rule_type": "map_local"},
	} {
		if got := callTool(t, c, name, args, false); regexpSecret.MatchString(got) {
			t.Errorf("%s leaks a secret:\n%s", name, got)
		}
	}
	for _, guess := range []string{"^private-token: glpat-S", "^private-token: <redacted>$"} {
		got := callTool(t, c, "filter_flows", map[string]any{"filters": []map[string]string{{"key": "requestHeader", "value": guess, "matching": "regex"}}}, false)
		if want := map[bool]string{true: `"matched": 1`, false: `"matched": 0`}[strings.Contains(guess, "redacted")]; !strings.Contains(got, want) {
			t.Errorf("filter_flows %q: %s", guess, got)
		}
	}
	got := callTool(t, c, "filter_flows", map[string]any{"filters": []map[string]string{{"key": "responseBody", "value": "S3", "matching": "contains"}}}, false)
	if !strings.Contains(got, `"matched": 0`) {
		t.Errorf("filter_flows matches a redacted body: %s", got)
	}
}
