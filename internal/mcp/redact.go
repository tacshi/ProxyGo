package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"proxygo/internal/flow"
	"proxygo/internal/store"
)

const redacted = "<redacted>"

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "x-auth-token": true, "x-access-token": true,
	"x-csrf-token": true, "x-xsrf-token": true, "x-amz-security-token": true, "x-goog-api-key": true,
}

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|passcode|^pwd$|^pin$|secret|token|api[-_]?key|apikey|authorization|credential|private[-_]?key|session[-_]?(id|key)|^sid$|cookie|signature|^otp$)`)

var sensitiveParam = regexp.MustCompile(`(?i)^(key|sig|auth|access[-_]?key)$`)

var urlHeaders = map[string]bool{":path": true, "referer": true, "location": true, "content-location": true}

var publicHeaders = map[string]bool{"access-control-allow-credentials": true}

func sensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	return sensitiveHeaders[lower] || !publicHeaders[lower] && sensitiveKey.MatchString(lower)
}

func redactHeaderValue(name, value string) (string, bool) {
	if value == "" {
		return value, false
	}
	lower := strings.ToLower(name)
	switch {
	case sensitiveHeader(lower):
		if lower == "authorization" || lower == "proxy-authorization" {
			if scheme, _, found := strings.Cut(value, " "); found {
				return scheme + " " + redacted, true
			}
		}
		return redacted, true
	case urlHeaders[lower]:
		return redactURL(value)
	}
	return value, false
}

func redactHeader(h flow.Header) (flow.Header, bool) {
	out := h.Clone()
	changed := false
	for i, e := range out.Entries {
		if v, ok := redactHeaderValue(e.Key.Name, e.Value); ok {
			out.Entries[i].Value, changed = v, true
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
		if hasValue && (sensitiveKey.MatchString(name) || sensitiveParam.MatchString(name)) {
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
	if strings.HasPrefix(ct, "multipart/") {
		if out, changed, ok := redactMultipart(body, contentType); ok {
			return out, changed
		}
	}
	prefix, rest := jsonPrefix(body)
	trimmed := bytes.TrimSpace(rest)
	switch {
	case strings.Contains(ct, "json") || len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '['):
		if out, changed, ok := redactJSON(rest); ok {
			if !changed {
				return body, false
			}
			return append(slices.Clip(prefix), out...), true
		}
		if out, changed, ok := redactRecords(rest); ok {
			if !changed {
				return body, false
			}
			return append(slices.Clip(prefix), out...), true
		}
	case strings.Contains(ct, "x-www-form-urlencoded"):
		out, changed := redactURL("?" + string(body))
		return []byte(strings.TrimPrefix(out, "?")), changed
	}
	if !utf8.Valid(body) {
		return body, false
	}
	out, changed := redactText(string(body))
	if !changed {
		return body, false
	}
	return []byte(out), true
}

var jsonPrefixes = []string{"\ufeff", ")]}',", ")]}'", "while(1);", "for(;;);", "{}&&"}

func jsonPrefix(body []byte) ([]byte, []byte) {
	rest := bytes.TrimLeft(body, " \t\r\n")
	for _, p := range jsonPrefixes {
		if after, ok := bytes.CutPrefix(rest, []byte(p)); ok {
			n := len(body) - len(after)
			return body[:n], body[n:]
		}
	}
	return nil, body
}

func redactJSON(body []byte) ([]byte, bool, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var values []any
	for {
		var v any
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, false
		}
		values = append(values, v)
	}
	changed := false
	for _, v := range values {
		changed = redactValue(v) || changed
	}
	if !changed {
		return body, false, true
	}
	lines := make([][]byte, len(values))
	for i, v := range values {
		out, err := marshal(v, "")
		if err != nil {
			return nil, false, false
		}
		lines[i] = out
	}
	return bytes.Join(lines, []byte("\n")), true, true
}

func redactRecords(body []byte) ([]byte, bool, bool) {
	const sep = 0x1e
	if bytes.IndexByte(body, sep) < 0 {
		return nil, false, false
	}
	records := bytes.Split(body, []byte{sep})
	changed := false
	for i, r := range records {
		if len(bytes.TrimSpace(r)) == 0 {
			continue
		}
		out, ch, ok := redactJSON(r)
		if !ok {
			return nil, false, false
		}
		if ch {
			records[i], changed = out, true
		}
	}
	return bytes.Join(records, []byte{sep}), changed, true
}

func redactMultipart(body []byte, contentType string) ([]byte, bool, bool) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return nil, false, false
	}
	sep := []byte("--" + params["boundary"])
	parts := bytes.Split(body, sep)
	changed := false
	for i := 1; i < len(parts); i++ {
		head, content, ok := bytes.Cut(parts[i], []byte("\r\n\r\n"))
		if !ok {
			continue
		}
		name, ct := partHeader(head)
		data, crlf := bytes.CutSuffix(content, []byte("\r\n"))
		var out []byte
		var ch bool
		if sensitiveKey.MatchString(name) && len(data) > 0 {
			out, ch = []byte(redacted), true
		} else {
			out, ch = redactBody(data, ct)
		}
		if !ch {
			continue
		}
		part := slices.Concat(head, []byte("\r\n\r\n"), out)
		if crlf {
			part = append(part, "\r\n"...)
		}
		parts[i], changed = part, true
	}
	return bytes.Join(parts, sep), changed, true
}

func partHeader(head []byte) (name, contentType string) {
	for line := range strings.SplitSeq(string(head), "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "content-disposition":
			if _, p, err := mime.ParseMediaType(strings.TrimSpace(v)); err == nil {
				name = p["name"]
			}
		case "content-type":
			contentType = strings.TrimSpace(v)
		}
	}
	return name, contentType
}

var (
	jsonPair  = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"(\s*:\s*)("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)`)
	queryPair = regexp.MustCompile(`(?m)(^|[?&;\s])([\w.\-\[\]%]+)=([^&#;\s"'<>]+)`)
)

func redactText(s string) (string, bool) {
	changed := false
	s = jsonPair.ReplaceAllStringFunc(s, func(m string) string {
		sub := jsonPair.FindStringSubmatch(m)
		key, value := sub[1], sub[3]
		isString := strings.HasPrefix(value, `"`)
		if isString && value != `""` && sensitiveKey.MatchString(key) || !isString && numericSecretKey.MatchString(key) {
			changed = true
			return `"` + key + `"` + sub[2] + `"` + redacted + `"`
		}
		return m
	})
	s = queryPair.ReplaceAllStringFunc(s, func(m string) string {
		sub := queryPair.FindStringSubmatch(m)
		name, err := url.QueryUnescape(sub[2])
		if err != nil {
			name = sub[2]
		}
		if sensitiveKey.MatchString(name) || sensitiveParam.MatchString(name) {
			changed = true
			return sub[1] + sub[2] + "=" + url.QueryEscape(redacted)
		}
		return m
	})
	return s, changed
}

func redactValue(v any) bool { return redactIn(v, false) }

// numericSecretKey names the keys whose numbers are secrets, as a PIN or a
// one-time code; other numbers, as usage counts under "total_tokens", stay.
var numericSecretKey = regexp.MustCompile(`(?i)(password|passwd|passcode|^pwd$|^pin$|^otp$|secret)`)

// redactIn redacts the secrets in v; inSecret is set inside the object or
// array a sensitive key holds, whose strings are all secrets.
func redactIn(v any, inSecret bool) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		if name, ok := x["name"].(string); ok {
			if v, ok := x["value"].(string); ok && v != "" && sensitiveHeader(name) {
				x["value"], changed = redacted, true
			}
		}
		for k, e := range x {
			sensitive := inSecret || sensitiveKey.MatchString(k)
			switch e := e.(type) {
			case string:
				if sensitive && e != "" {
					x[k], changed = redacted, true
				}
			case json.Number:
				if numericSecretKey.MatchString(k) {
					x[k], changed = redacted, true
				}
			default:
				changed = redactIn(e, sensitive) || changed
			}
		}
	case []any:
		for i, e := range x {
			if s, isString := e.(string); isString {
				if inSecret && s != "" {
					x[i], changed = redacted, true
				}
				continue
			}
			changed = redactIn(e, inSecret) || changed
		}
	}
	return changed
}

func (s *Server) redactRule(v any) any {
	if !s.Redact() {
		return v
	}
	var x any
	dec := json.NewDecoder(bytes.NewReader(mustJSON(v)))
	dec.UseNumber()
	if dec.Decode(&x) != nil {
		return v
	}
	redactRuleFields(x)
	redactValue(x)
	return x
}

func redactRuleFields(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			switch e := e.(type) {
			case string:
				switch k {
				case "body":
					ct, _ := x["content_type"].(string)
					if b, changed := redactBody([]byte(e), ct); changed {
						x[k] = string(b)
					}
				case "url", "new_url":
					x[k], _ = redactURL(e)
				}
			default:
				redactRuleFields(e)
			}
		}
	case []any:
		for _, e := range x {
			redactRuleFields(e)
		}
	}
}

func redactStrings(m map[string]any) map[string]any {
	var x map[string]any
	dec := json.NewDecoder(bytes.NewReader(mustJSON(m)))
	dec.UseNumber()
	if dec.Decode(&x) != nil {
		return nil
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch v := v.(type) {
		case string:
			out, _ := redactText(v)
			return out
		case map[string]any:
			for k, e := range v {
				v[k] = walk(e)
			}
		case []any:
			for i, e := range v {
				v[i] = walk(e)
			}
		}
		return v
	}
	walk(x)
	return x
}

func filterRedacted(flows []*flow.Flow, filter store.Filter) []*flow.Flow {
	bodies := slices.ContainsFunc(filter.Conditions, func(c store.Condition) bool {
		switch c.Field {
		case store.FieldRequestBody, store.FieldResponseBody, store.FieldRequestJQ, store.FieldResponseJQ, store.FieldRequestJSONPath, store.FieldResponseJSONPath:
			return true
		}
		return false
	})
	views := make([]*flow.Flow, len(flows))
	orig := make(map[*flow.Flow]*flow.Flow, len(flows))
	for i, f := range flows {
		views[i] = redactedView(f, bodies)
		orig[views[i]] = f
	}
	matched := store.Apply(views, filter)
	out := make([]*flow.Flow, len(matched))
	for i, v := range matched {
		out[i] = orig[v]
	}
	return out
}

func redactedView(f *flow.Flow, bodies bool) *flow.Flow {
	v := *f
	if f.Request != nil {
		r := *f.Request
		r.Header, _ = redactHeader(f.Request.Header)
		r.FullPath, _ = redactURL(f.URL())
		r.URI, _ = redactURL(f.Request.URI)
		if bodies {
			r.BodyData, _ = redactBody(f.DecodedRequestBody(), f.Request.Header.Get("Content-Type"))
			r.Header.Del("Content-Encoding")
		}
		v.Request = &r
	}
	if f.Response != nil {
		r := *f.Response
		r.Header, _ = redactHeader(f.Response.Header)
		if bodies {
			r.BodyData, _ = redactBody(f.DecodedResponseBody(), f.Response.Header.Get("Content-Type"))
			r.Header.Del("Content-Encoding")
		}
		v.Response = &r
	}
	return &v
}
