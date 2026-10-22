package session

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"proxygo/internal/flow"
	"proxygo/internal/formdata"
)

type (
	postmanCollection struct {
		Info postmanInfo   `json:"info"`
		Item []postmanItem `json:"item"`
	}
	postmanInfo struct {
		PostmanID   string `json:"_postman_id"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Schema      string `json:"schema"`
	}
	postmanItem struct {
		Name     string            `json:"name"`
		Item     []postmanItem     `json:"item,omitempty"`
		Request  *postmanRequest   `json:"request,omitempty"`
		Response []postmanResponse `json:"response,omitempty"`
	}
	postmanRequest struct {
		Method      string       `json:"method"`
		Header      []postmanKV  `json:"header"`
		Body        *postmanBody `json:"body,omitempty"`
		URL         postmanURL   `json:"url"`
		Description string       `json:"description,omitempty"`
	}
	postmanKV struct {
		Key      string `json:"key"`
		Value    string `json:"value"`
		Type     string `json:"type,omitempty"`
		Disabled bool   `json:"disabled,omitempty"`
	}
	postmanBody struct {
		Mode       string         `json:"mode"`
		Raw        string         `json:"raw,omitempty"`
		URLEncoded []postmanKV    `json:"urlencoded,omitempty"`
		FormData   []postmanKV    `json:"formdata,omitempty"`
		Options    map[string]any `json:"options,omitempty"`
	}
	postmanURL struct {
		Raw      string      `json:"raw"`
		Protocol string      `json:"protocol,omitempty"`
		Host     []string    `json:"host,omitempty"`
		Port     string      `json:"port,omitempty"`
		Path     []string    `json:"path,omitempty"`
		Query    []postmanKV `json:"query,omitempty"`
	}
	postmanResponse struct {
		Name            string          `json:"name"`
		OriginalRequest *postmanRequest `json:"originalRequest"`
		Status          string          `json:"status"`
		Code            int             `json:"code"`
		Language        string          `json:"_postman_previewlanguage,omitempty"`
		Header          []postmanKV     `json:"header"`
		Body            string          `json:"body"`
	}
)

func WritePostman(path, name string, flows []*flow.Flow) error {
	c := postmanCollection{
		Info: postmanInfo{PostmanID: strings.ToLower(newUUID()), Name: name, Description: "Exported from ProxyGo",
			Schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
		Item: []postmanItem{},
	}
	for _, f := range flows {
		if it, ok := postmanItemOf(f); ok {
			c.Item = append(c.Item, it)
		}
	}
	b, err := json.Marshal(c, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'))
}

func postmanItemOf(f *flow.Flow) (postmanItem, bool) {
	if f == nil || f.Request == nil || f.IsTunnel() || f.IsWebSocket() {
		return postmanItem{}, false
	}
	req := postmanRequestOf(f)
	it := postmanItem{Name: f.MethodName() + " " + strings.SplitN(f.URLPath(), "?", 2)[0], Request: req}
	if f.Response != nil && !f.IsError() && f.Response.Status != nil {
		body := f.DecodedResponseBody()
		text := ""
		if isText(f.Response.Header.Get("Content-Type"), body) {
			text = string(body)
		}
		it.Response = []postmanResponse{{
			Name: it.Name, OriginalRequest: req, Status: cmpPhrase(f), Code: f.StatusCode(),
			Language: previewLanguage(f.Response.Header.Get("Content-Type")),
			Header:   postmanHeaders(f.Response.Header, true), Body: text,
		}}
	}
	return it, true
}

func PostmanJSON(f *flow.Flow) string {
	it, ok := postmanItemOf(f)
	if !ok {
		return ""
	}
	b, _ := json.Marshal(it, jsontext.WithIndent("  "))
	return string(b)
}

func cmpPhrase(f *flow.Flow) string {
	if f.Response.Status.Phrase != "" {
		return f.Response.Status.Phrase
	}
	return http.StatusText(f.StatusCode())
}

func postmanRequestOf(f *flow.Flow) *postmanRequest {
	r := &postmanRequest{Method: f.MethodName(), Header: postmanHeaders(f.Request.Header, false), URL: postmanURLOf(f.URL())}
	body := f.DecodedRequestBody()
	if len(body) == 0 {
		return r
	}
	ct := f.Request.Header.Get("Content-Type")
	mt, _, _ := mime.ParseMediaType(ct)
	switch {
	case mt == "application/x-www-form-urlencoded":
		r.Body = &postmanBody{Mode: "urlencoded", URLEncoded: []postmanKV{}}
		for _, p := range formdata.ParseURLEncoded(body) {
			r.Body.URLEncoded = append(r.Body.URLEncoded, postmanKV{Key: p.Name, Value: string(p.Value), Type: "text"})
		}
	case strings.HasPrefix(mt, "multipart/form-data"):
		parts, err := formdata.ParseMultipart(body, ct, 1<<20)
		if err != nil {
			break
		}
		r.Body = &postmanBody{Mode: "formdata", FormData: []postmanKV{}}
		for _, p := range parts {
			if p.FileName != "" || !isText(p.ContentType, p.Value) {
				r.Body.FormData = append(r.Body.FormData, postmanKV{Key: p.Name, Type: "file", Value: p.FileName})
				continue
			}
			r.Body.FormData = append(r.Body.FormData, postmanKV{Key: p.Name, Value: string(p.Value), Type: "text"})
		}
		r.Header = dropKV(r.Header, "Content-Type")
	case isText(ct, body):
		r.Body = &postmanBody{Mode: "raw", Raw: string(body)}
		if lang := previewLanguage(ct); lang != "" && lang != "text" {
			r.Body.Options = map[string]any{"raw": map[string]string{"language": lang}}
		}
	default:
		r.Description = "The request's binary body is not in the collection."
	}
	return r
}

func dropKV(kvs []postmanKV, key string) []postmanKV {
	out := kvs[:0]
	for _, kv := range kvs {
		if !strings.EqualFold(kv.Key, key) {
			out = append(out, kv)
		}
	}
	return out
}

func postmanHeaders(h flow.Header, response bool) []postmanKV {
	out := []postmanKV{}
	for _, e := range h.Entries {
		switch strings.ToLower(e.Key.Name) {
		case "content-length", "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding":
			if !response {
				continue
			}
		}
		if strings.HasPrefix(e.Key.Name, ":") {
			continue
		}
		out = append(out, postmanKV{Key: e.Key.Name, Value: e.Value, Disabled: !e.Enabled})
	}
	return out
}

func postmanURLOf(raw string) postmanURL {
	u, err := url.Parse(raw)
	if err != nil {
		return postmanURL{Raw: raw}
	}
	out := postmanURL{Raw: raw, Protocol: u.Scheme, Host: strings.Split(u.Hostname(), "."), Port: u.Port()}
	for seg := range strings.SplitSeq(strings.TrimPrefix(u.EscapedPath(), "/"), "/") {
		out.Path = append(out.Path, seg)
	}
	if u.RawQuery != "" {
		for part := range strings.SplitSeq(u.RawQuery, "&") {
			k, v, _ := strings.Cut(part, "=")
			ku, err1 := url.QueryUnescape(k)
			vu, err2 := url.QueryUnescape(v)
			if err1 == nil && err2 == nil {
				k, v = ku, vu
			}
			out.Query = append(out.Query, postmanKV{Key: k, Value: v})
		}
	}
	return out
}

func previewLanguage(ct string) string {
	mt := strings.ToLower(ct)
	switch {
	case strings.Contains(mt, "json"):
		return "json"
	case strings.Contains(mt, "html"):
		return "html"
	case strings.Contains(mt, "xml"):
		return "xml"
	case strings.Contains(mt, "javascript"):
		return "javascript"
	case strings.HasPrefix(mt, "text/"):
		return "text"
	}
	return ""
}
