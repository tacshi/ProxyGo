package settings

import (
	"net/url"
	"strings"

	"proxygo/internal/flow"
	"proxygo/internal/query"
)

const (
	SourceHeader   = "header"
	SourceQuery    = "query"
	SourceKeyPath  = "keypath"
	SourceJQ       = "jq"
	SourceJSONPath = "jsonpath"
)

var Sources = []struct{ ID, Name string }{
	{SourceHeader, "Header"},
	{SourceQuery, "Query Parameter"},
	{SourceKeyPath, "JSON Body (Key Path)"},
	{SourceJQ, "JSON Body (jq)"},
	{SourceJSONPath, "JSON Body (JSON Path)"},
}

type Column struct {
	Name     string `json:"name"`
	Response bool   `json:"response,omitzero"`
	Source   string `json:"source"`
	Key      string `json:"key"`
}

func (c Column) ID() string {
	side := "req"
	if c.Response {
		side = "res"
	}
	if c.Source == SourceHeader {
		return "header:" + side + ":" + c.Key
	}
	return "col:" + side + ":" + c.Source + ":" + c.Key
}

func (c Column) Label() string {
	side := "Request"
	if c.Response {
		side = "Response"
	}
	if c.Source == SourceQuery {
		side = "Query"
	}
	return side + ": " + c.Name
}

func (c Column) Value(f *flow.Flow) string {
	if f == nil || f.Request == nil {
		return ""
	}
	var h flow.Header
	var body func() []byte
	if c.Response {
		if f.Response == nil {
			return ""
		}
		h, body = f.Response.Header, f.DecodedResponseBody
	} else {
		h, body = f.Request.Header, f.DecodedRequestBody
	}
	switch c.Source {
	case SourceHeader:
		return h.Get(c.Key)
	case SourceQuery:
		u, err := url.Parse(f.URL())
		if err != nil {
			return ""
		}
		return u.Query().Get(c.Key)
	case SourceKeyPath, SourceJQ, SourceJSONPath:
		b := body()
		if len(b) == 0 || (b[0] != '{' && b[0] != '[' && !strings.Contains(strings.ToLower(h.Get("Content-Type")), "json")) {
			return ""
		}
		values, err := query.Run(c.Source, b, c.Key)
		if err != nil {
			return ""
		}
		return query.Join(values)
	}
	return ""
}

func (c Column) Valid() string {
	switch {
	case strings.TrimSpace(c.Name) == "":
		return "Enter the column's name."
	case strings.TrimSpace(c.Key) == "":
		return "Enter the header, parameter or query to show."
	}
	switch c.Source {
	case SourceHeader, SourceQuery, SourceKeyPath:
	case SourceJQ, SourceJSONPath:
		if err := query.Check(c.Source, c.Key); err != nil {
			return "Invalid query: " + err.Error()
		}
	default:
		return "Choose where the value comes from."
	}
	return ""
}
