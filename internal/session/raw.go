package session

import (
	"bytes"
	"cmp"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"proxygo/internal/flow"
)

func RawHTTP(f *flow.Flow) []byte {
	var b bytes.Buffer
	if f == nil || f.Request == nil {
		return nil
	}
	target := f.Request.URI
	if target == "" {
		target = f.URLPath()
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", f.MethodName(), target)
	body := f.DecodedRequestBody()
	if f.Request.Header.Get("Host") == "" && f.Request.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", f.Request.Host)
	}
	writeRawHeaders(&b, f.Request.Header, body)
	b.Write(body)
	if f.Response == nil || f.IsError() || f.Response.Status == nil {
		return b.Bytes()
	}
	if len(body) > 0 {
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", f.StatusCode(), cmp.Or(f.Response.Status.Phrase, statusText(f.StatusCode())))
	body = f.DecodedResponseBody()
	writeRawHeaders(&b, f.Response.Header, body)
	b.Write(body)
	return b.Bytes()
}

func writeRawHeaders(b *bytes.Buffer, h flow.Header, body []byte) {
	hadLength := false
	for _, e := range h.Entries {
		if !e.Enabled || strings.HasPrefix(e.Key.Name, ":") {
			continue
		}
		switch strings.ToLower(e.Key.Name) {
		case "content-encoding", "transfer-encoding":
			continue
		case "content-length":
			hadLength = true
			continue
		}
		fmt.Fprintf(b, "%s: %s\r\n", e.Key.Name, e.Value)
	}
	if hadLength || len(body) > 0 {
		fmt.Fprintf(b, "Content-Length: %s\r\n", strconv.Itoa(len(body)))
	}
	b.WriteString("\r\n")
}

func WriteRaw(path string, flows []*flow.Flow) error {
	var b bytes.Buffer
	for _, f := range flows {
		if f == nil || f.Request == nil || f.IsTunnel() {
			continue
		}
		fmt.Fprintf(&b, "### %s %s %s\r\n", cmp.Or(f.ID, f.UniqueID), f.MethodName(), f.URL())
		b.Write(RawHTTP(f))
		b.WriteString("\r\n\r\n")
	}
	return writeAtomic(path, b.Bytes())
}

func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "Status"
}
