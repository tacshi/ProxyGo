package query

import (
	"strings"
	"testing"
)

const doc = `{"data":{"items":[{"id":12345678901234567890,"name":"Ada","tags":["a","b"]},{"id":2,"name":"Linus","age":54.5}],"total":2},"ok":true,"key.with.dots":1}`

func TestQueries(t *testing.T) {
	for _, tc := range []struct {
		lang, expr, want string
	}{
		{LangJQ, ".data.items[].name", "Ada\nLinus"},
		{LangJQ, ".data.items[0].id", "12345678901234567890"},
		{LangJQ, "[.data.items[] | select(.age > 50) | .name]", `["Linus"]`},
		{LangJQ, ".data.total + 1", "3"},
		{LangJQ, `.["key.with.dots"]`, "1"},
		{LangJSONPath, "$.data.items[0].name", "Ada"},
		{LangJSONPath, "$.data.items[*].name", "Ada\nLinus"},
		{LangJSONPath, "$..tags[1]", "b"},
		{LangJSONPath, "$.data.items[?@.age > 50].name", "Linus"},
		{LangJSONPath, "$['key.with.dots']", "1"},
		{LangKeyPath, "data.items[1].name", "Linus"},
		{LangKeyPath, "data.items.0.tags.-1", "b"},
		{LangKeyPath, "$.ok", "true"},
		{LangKeyPath, "data", `{"items":[{"id":12345678901234567890,"name":"Ada","tags":["a","b"]},{"age":54.5,"id":2,"name":"Linus"}],"total":2}`},
	} {
		got, err := Run(tc.lang, []byte(doc), tc.expr)
		if err != nil {
			t.Errorf("%s %s: %v", tc.lang, tc.expr, err)
			continue
		}
		if s := Join(got); s != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.lang, tc.expr, s, tc.want)
		}
	}
}

func TestQueryErrors(t *testing.T) {
	for _, tc := range []struct{ lang, expr, input string }{
		{LangJQ, ".data | ", doc},
		{LangJSONPath, "data.items", doc},
		{LangKeyPath, "data.missing", doc},
		{LangKeyPath, "ok.x", doc},
		{LangJQ, ".", "not json"},
		{LangJQ, ".", `{} {}`},
		{"xpath", ".", doc},
	} {
		if _, err := Run(tc.lang, []byte(tc.input), tc.expr); err == nil {
			t.Errorf("%s %q on %q succeeded", tc.lang, tc.expr, tc.input)
		}
	}
	if _, err := JQ([]byte(doc), "[limit(5000; repeat(1))]"); err != nil {
		t.Errorf("a long but finite query: %v", err)
	}
	if _, err := JQ([]byte(doc), "repeat(1)"); err == nil || !strings.Contains(err.Error(), "results") {
		t.Errorf("an endless query: %v", err)
	}
	if Check(LangJQ, ".[") == nil || Check(LangJSONPath, "$[") == nil || Check(LangJQ, ".a") != nil {
		t.Error("Check")
	}
}
