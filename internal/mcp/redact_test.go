package mcp

import (
	"strings"
	"testing"

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
