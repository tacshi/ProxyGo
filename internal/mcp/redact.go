package mcp

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"proxygo/internal/flow"
)

const redacted = "<redacted>"

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "x-auth-token": true, "x-access-token": true,
	"x-csrf-token": true, "x-xsrf-token": true, "x-amz-security-token": true, "x-goog-api-key": true,
}

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|passcode|^pwd$|secret|token|api[-_]?key|apikey|authorization|credential|private[-_]?key|session[-_]?(id|key)|^sid$|cookie|signature|^otp$)`)

func redactHeader(h flow.Header) (flow.Header, bool) {
	out := h.Clone()
	changed := false
	for i, e := range out.Entries {
		if sensitiveHeaders[strings.ToLower(e.Key.Name)] && e.Value != "" {
			scheme, _, found := strings.Cut(e.Value, " ")
			if found && strings.EqualFold(e.Key.Name, "authorization") || found && strings.EqualFold(e.Key.Name, "proxy-authorization") {
				out.Entries[i].Value = scheme + " " + redacted
			} else {
				out.Entries[i].Value = redacted
			}
			changed = true
		}
	}
	return out, changed
}

func redactURL(raw string) (string, bool) {
	base, query, ok := strings.Cut(raw, "?")
	if !ok {
		return raw, false
	}
	query, frag, _ := strings.Cut(query, "#")
	parts := strings.Split(query, "&")
	changed := false
	for i, p := range parts {
		k, _, hasValue := strings.Cut(p, "=")
		name, _ := url.QueryUnescape(k)
		if hasValue && sensitiveKey.MatchString(name) {
			parts[i] = k + "=" + url.QueryEscape(redacted)
			changed = true
		}
	}
	out := base + "?" + strings.Join(parts, "&")
	if frag != "" {
		out += "#" + frag
	}
	return out, changed
}

func redactBody(body []byte, contentType string) ([]byte, bool) {
	ct := strings.ToLower(contentType)
	trimmed := bytes.TrimSpace(body)
	switch {
	case strings.Contains(ct, "json") || len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '['):
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var v any
		if dec.Decode(&v) != nil {
			return body, false
		}
		changed := redactValue(v)
		if !changed {
			return body, false
		}
		out, err := marshal(v, "")
		if err != nil {
			return body, false
		}
		return out, true
	case strings.Contains(ct, "x-www-form-urlencoded"):
		out, changed := redactURL("?" + string(body))
		return []byte(strings.TrimPrefix(out, "?")), changed
	}
	return body, false
}

func redactValue(v any) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, isString := e.(string); isString && s != "" && sensitiveKey.MatchString(k) {
				x[k] = redacted
				changed = true
				continue
			}
			changed = redactValue(e) || changed
		}
	case []any:
		for _, e := range x {
			changed = redactValue(e) || changed
		}
	}
	return changed
}
