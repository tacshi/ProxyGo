package settings

import (
	"net/http"
	"testing"

	"proxygo/internal/flow"
)

func TestColumnValues(t *testing.T) {
	f := flow.New("C")
	f.Request = &flow.Request{FullPath: "https://api.dev/s?page=2&q=a+b", Method: flow.Method{Name: "POST"},
		Header: flow.NewHeader(http.Header{"Content-Type": {"application/json"}}), BodyData: flow.Blob(`{"user":{"name":"Ada"}}`)}
	f.Response = &flow.Response{Status: &flow.Status{Code: 200}, Header: flow.NewHeader(http.Header{"X-Request-Id": {"r1"}, "Content-Type": {"application/json"}}),
		BodyData: flow.Blob(`{"items":[{"id":1},{"id":2}]}`)}
	for _, tc := range []struct {
		c    Column
		want string
	}{
		{Column{Source: SourceHeader, Key: "x-request-id", Response: true}, "r1"},
		{Column{Source: SourceQuery, Key: "q"}, "a b"},
		{Column{Source: SourceKeyPath, Key: "user.name"}, "Ada"},
		{Column{Source: SourceJQ, Key: ".items | length", Response: true}, "2"},
		{Column{Source: SourceJSONPath, Key: "$.items[*].id", Response: true}, "1\n2"},
		{Column{Source: SourceKeyPath, Key: "missing"}, ""},
	} {
		if got := tc.c.Value(f); got != tc.want {
			t.Errorf("%+v = %q, want %q", tc.c, got, tc.want)
		}
	}
	if (Column{Name: "x", Source: SourceJQ, Key: ".["}).Valid() == "" || (Column{Name: "x", Source: SourceJQ, Key: ".a"}).Valid() != "" || (Column{Source: SourceHeader, Key: "a"}).Valid() == "" {
		t.Error("Valid")
	}
	if (Column{Source: SourceJQ, Key: ".a", Response: true}).ID() != "col:res:jq:.a" {
		t.Error("ID")
	}
}
