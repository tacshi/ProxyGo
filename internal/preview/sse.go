package preview

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

type SSEEvent struct {
	Type  string
	Data  string
	ID    string
	Retry time.Duration
}

type SSEStream struct {
	Events   []SSEEvent
	Comments int
	Pending  *SSEEvent
}

func ParseSSE(body []byte) SSEStream {
	var out SSEStream
	body = bytes.TrimPrefix(body, []byte("\xEF\xBB\xBF"))
	var data strings.Builder
	var hasData bool
	typ, lastID := "", ""
	var retry time.Duration
	dispatch := func() {
		if hasData {
			d := strings.TrimSuffix(data.String(), "\n")
			out.Events = append(out.Events, SSEEvent{Type: cmpOr(typ, "message"), Data: d, ID: lastID, Retry: retry})
		}
		data.Reset()
		hasData, typ, retry = false, "", 0
	}
	for len(body) > 0 {
		i := bytes.IndexAny(body, "\r\n")
		if i < 0 {
			line := string(body)
			body = nil
			field(line, &data, &hasData, &typ, &lastID, &retry, &out.Comments)
			break
		}
		line := string(body[:i])
		if body[i] == '\r' && i+1 < len(body) && body[i+1] == '\n' {
			i++
		}
		body = body[i+1:]
		if line == "" {
			dispatch()
			continue
		}
		field(line, &data, &hasData, &typ, &lastID, &retry, &out.Comments)
	}
	if hasData || typ != "" {
		out.Pending = &SSEEvent{Type: cmpOr(typ, "message"), Data: strings.TrimSuffix(data.String(), "\n"), ID: lastID, Retry: retry}
	}
	return out
}

func field(line string, data *strings.Builder, hasData *bool, typ, lastID *string, retry *time.Duration, comments *int) {
	if strings.HasPrefix(line, ":") {
		*comments++
		return
	}
	name, value, _ := strings.Cut(line, ":")
	value = strings.TrimPrefix(value, " ")
	switch name {
	case "data":
		data.WriteString(value)
		data.WriteByte('\n')
		*hasData = true
	case "event":
		*typ = value
	case "id":
		if !strings.ContainsRune(value, 0) {
			*lastID = value
		}
	case "retry":
		if value != "" && strings.Trim(value, "0123456789") == "" {
			if ms, err := strconv.ParseInt(value, 10, 64); err == nil {
				*retry = time.Duration(ms) * time.Millisecond
			}
		}
	}
}

func IsSSE(contentType string) bool {
	mt, _, _ := strings.Cut(strings.ToLower(contentType), ";")
	return strings.TrimSpace(mt) == "text/event-stream"
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
