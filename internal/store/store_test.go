package store

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"proxygo/internal/flow"
)

func mk(id, method, rawURL string, status int, ct string) *flow.Flow {
	f := flow.New(id)
	start := float64(time.Now().UnixNano()) / 1e9
	end := start + 0.1
	f.Timing = flow.Timing{RequestStartedAt: &start, ResponseEndedAt: &end}
	scheme, rest, _ := strings.Cut(rawURL, "://")
	host, _, _ := strings.Cut(rest, "/")
	f.Request = &flow.Request{Scheme: scheme, Host: host, FullPath: rawURL, Method: flow.Method{Name: method}, Version: flow.Version{Major: 1, Minor: 1}}
	f.IsSSL = scheme == "https"
	if status > 0 {
		f.Response = &flow.Response{Status: &flow.Status{Code: status}, Header: flow.NewHeader(http.Header{"Content-Type": {ct}}), BodyData: flow.Blob("body of " + id)}
	}
	return f
}

func TestUpsertKeepsUserFieldsAndRows(t *testing.T) {
	s := New(100)
	a := mk("A", "GET", "https://a.dev/x", 0, "")
	s.Upsert(a.Clone())
	s.Upsert(mk("B", "GET", "https://b.dev/", 200, "text/plain"))
	v := s.Version()
	s.Update("A", func(f *flow.Flow) { f.Comment, f.Highlight, f.Saved = "note", "red", true })
	if s.Version() == v {
		t.Fatal("update did not bump version")
	}
	held := s.Snapshot()[0]

	done := a.Clone()
	done.Response = &flow.Response{Status: &flow.Status{Code: 204}}
	s.Upsert(done)
	got, _ := s.Lookup("A")
	if got.StatusCode() != 204 || got.Comment != "note" || got.Highlight != "red" || !got.Saved || got.ID != "1" {
		t.Fatalf("upsert lost user fields: %+v", got)
	}
	if held.StatusCode() != 0 || held.Comment != "note" {
		t.Fatal("a snapshot's flow changed under the reader")
	}
	if s.Len() != 2 || s.Snapshot()[1].ID != "2" {
		t.Fatal("row numbers")
	}
	s.Remove("A")
	s.Upsert(mk("C", "GET", "https://c.dev/", 200, ""))
	if c, _ := s.Lookup("C"); c.ID != "3" {
		t.Fatalf("row numbers reused: %s", c.ID)
	}
	s.Clear()
	s.Upsert(mk("D", "GET", "https://d.dev/", 200, ""))
	if d, _ := s.Lookup("D"); d.ID != "1" || s.Len() != 1 {
		t.Fatal("clear did not start over")
	}
}

func TestTrafficAndLimit(t *testing.T) {
	s := New(10)
	for i := range 25 {
		s.Upsert(mk(strconv.Itoa(i), "GET", "http://x.dev/", 200, "text/plain"))
	}
	if s.Len() > 10 {
		t.Fatalf("kept %d flows", s.Len())
	}
	up, down := s.Traffic()
	var wantUp, wantDown int64
	for _, f := range s.Snapshot() {
		wantUp += int64(f.RequestSize())
		wantDown += int64(f.ResponseSize())
	}
	if up != wantUp || down != wantDown {
		t.Fatalf("traffic %d/%d, want %d/%d", up, down, wantUp, wantDown)
	}
	s.Remove(s.Snapshot()[0].UniqueID)
	up2, _ := s.Traffic()
	if up2 >= up {
		t.Fatal("removing did not lower traffic")
	}
}

func TestConcurrentUse(t *testing.T) {
	s := New(1000)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range 200 {
				id := strconv.Itoa(w*1000 + i)
				s.Upsert(mk(id, "GET", "http://x.dev/"+id, 0, ""))
				s.Update(id, func(f *flow.Flow) { f.Comment = "c" })
				s.Upsert(mk(id, "GET", "http://x.dev/"+id, 200, "text/plain"))
			}
		})
	}
	wg.Go(func() {
		for range 200 {
			for _, f := range s.Snapshot() {
				_ = f.URL() + f.Comment
			}
		}
	})
	wg.Wait()
	if s.Len() != 800 {
		t.Fatalf("%d flows", s.Len())
	}
}

func TestFilter(t *testing.T) {
	flows := []*flow.Flow{
		mk("1", "GET", "https://api.dev/users", 200, "application/json"),
		mk("2", "POST", "http://api.dev/login", 401, "text/html"),
		mk("3", "GET", "https://cdn.dev/a.png", 200, "image/png"),
		mk("4", "GET", "https://cdn.dev/app.js", 500, "application/javascript"),
	}
	flows[0].Client.Name = "Safari"
	flows[1].Comment = "check login"
	flows[2].Saved = true
	flows[3].Request.Version = flow.Version{Major: 2}
	ids := func(fl []*flow.Flow) string {
		s := ""
		for _, f := range fl {
			s += f.UniqueID
		}
		return s
	}
	cases := []struct {
		name string
		f    Filter
		want string
	}{
		{"none", Filter{}, "1234"},
		{"query url", Filter{Query: "cdn"}, "34"},
		{"query comment", Filter{Query: "LOGIN"}, "2"},
		{"query body needs deep", Filter{Query: "body of 3"}, ""},
		{"deep", Filter{Query: "body of 3", Deep: true}, "3"},
		{"https", Filter{Kinds: map[string]bool{"HTTPS": true}}, "134"},
		{"http", Filter{Kinds: map[string]bool{"HTTP": true}}, "2"},
		{"json or media", Filter{Kinds: map[string]bool{"JSON": true, "Media": true}}, "13"},
		{"https and js", Filter{Kinds: map[string]bool{"HTTPS": true, "JS": true}}, "4"},
		{"h2", Filter{Kinds: map[string]bool{"h2": true}}, "4"},
		{"client", Filter{Client: "Safari"}, "1"},
		{"host", Filter{Host: "cdn.dev"}, "34"},
		{"hosts", Filter{Hosts: []string{"API.dev"}}, "12"},
		{"path", Filter{Host: "cdn.dev", Path: "/a.png"}, "3"},
		{"path prefix", Filter{Host: "api.dev", Path: "/users"}, "1"},
		{"path is not a prefix of another name", Filter{Host: "api.dev", Path: "/user"}, ""},
		{"saved", Filter{Saved: true}, "3"},
		{"status >= 400", Filter{Conditions: []Condition{{Enabled: true, Field: FieldStatus, Op: OpGreater, Value: "399"}}}, "24"},
		{"method and host", Filter{Conditions: []Condition{
			{Enabled: true, Field: FieldMethod, Op: OpEquals, Value: "get"},
			{Enabled: true, Field: FieldHost, Op: OpStartsWith, Value: "cdn"},
		}}, "34"},
		{"any", Filter{Any: true, Conditions: []Condition{
			{Enabled: true, Field: FieldMethod, Op: OpEquals, Value: "POST"},
			{Enabled: true, Field: FieldURL, Op: OpEndsWith, Value: ".js"},
		}}, "24"},
		{"regex", Filter{Conditions: []Condition{{Enabled: true, Field: FieldPath, Op: OpRegex, Value: `\.(png|js)$`}}}, "34"},
		{"not contains", Filter{Conditions: []Condition{{Enabled: true, Field: FieldURL, Op: OpNotContains, Value: "cdn"}}}, "12"},
		{"disabled condition", Filter{Conditions: []Condition{{Enabled: false, Field: FieldURL, Op: OpEquals, Value: "x"}}}, "1234"},
		{"response header", Filter{Conditions: []Condition{{Enabled: true, Field: FieldResponseHeader, Op: OpContains, Value: "image/"}}}, "3"},
		{"no response header", Filter{Conditions: []Condition{{Enabled: true, Field: FieldResponseHeader, Op: OpNotContains, Value: "image/"}}}, "124"},
	}
	for _, tc := range cases {
		if got := ids(Apply(flows, tc.f)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if ValidRegexp("(") == "" {
		t.Fatal("bad regexp accepted")
	}
}

func TestSortAndCounts(t *testing.T) {
	flows := []*flow.Flow{
		mk("a", "POST", "https://b.dev/", 500, ""),
		mk("b", "GET", "https://a.dev/", 200, ""),
		mk("c", "DELETE", "https://a.dev/x", 404, ""),
	}
	for i, f := range flows {
		f.ID = strconv.Itoa(i + 1)
	}
	Sort(flows, SortStatus, false)
	if flows[0].UniqueID != "b" || flows[2].UniqueID != "a" {
		t.Fatal("status ascending")
	}
	Sort(flows, SortURL, true)
	if flows[0].UniqueID != "a" {
		t.Fatal("URL descending")
	}
	Sort(flows, SortRow, false)
	if flows[0].ID != "1" || flows[2].ID != "3" {
		t.Fatal("row order")
	}
	d := Domains(flows)
	if d["a.dev"] != 2 || ByCount(d)[0] != "a.dev" {
		t.Fatalf("domains %v", d)
	}
	if Apps(flows)["System"] != 3 {
		t.Fatal("apps default to System")
	}
}

func TestMemoryLimit(t *testing.T) {
	s := New(1000)
	mk := func(id string, size int, saved bool) *flow.Flow {
		f := flow.New(id)
		f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, Host: "a", URI: "/", BodyData: make(flow.Blob, size)}
		f.Saved = saved
		return f
	}
	s.Upsert(mk("A", 1000, true))
	s.Upsert(mk("B", 1000, false))
	s.Upsert(mk("C", 1000, false))
	s.Upsert(mk("D", 1000, false))
	s.SetMemoryLimit(2500)
	var ids []string
	for _, f := range s.Snapshot() {
		ids = append(ids, f.UniqueID)
	}
	if strings.Join(ids, "") != "AD" {
		t.Errorf("kept %v: the newest, and the saved one", ids)
	}
	if up, _ := s.Traffic(); up > 2500 {
		t.Errorf("%d bytes kept", up)
	}
}

func TestMemoryLimitOnUpdate(t *testing.T) {
	s := New(1000)
	s.SetMemoryLimit(2500)
	mk := func(id string) *flow.Flow {
		f := flow.New(id)
		f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, Host: "a", URI: "/", BodyData: make(flow.Blob, 1000)}
		return f
	}
	s.Upsert(mk("A"))
	s.Upsert(mk("B"))
	b := mk("B")
	b.Response = &flow.Response{Status: &flow.Status{Code: 200}, BodyData: make(flow.Blob, 1400)}
	s.Upsert(b)
	var ids []string
	for _, f := range s.Snapshot() {
		ids = append(ids, f.UniqueID)
	}
	if strings.Join(ids, "") != "B" {
		t.Errorf("kept %v: the updated flow only", ids)
	}
	if up, down := s.Traffic(); up+down > 2500 {
		t.Errorf("%d bytes kept", up+down)
	}
}

func TestJSONConditionsAndPresets(t *testing.T) {
	f := flow.New("J")
	f.Request = &flow.Request{FullPath: "https://api.dev/search?q=hello%20world&page=2", Method: flow.Method{Name: "GET"}}
	f.Response = &flow.Response{Status: &flow.Status{Code: 200}, BodyData: flow.Blob(`{"data":{"items":[{"name":"Ada"},{"name":"Linus"}]}}`)}
	for _, tc := range []struct {
		c    Condition
		want bool
	}{
		{Condition{Enabled: true, Field: FieldResponseJQ, Key: ".data.items[].name", Op: OpEquals, Value: "linus"}, true},
		{Condition{Enabled: true, Field: FieldResponseJQ, Key: ".data.items[].name", Op: OpEquals, Value: "grace"}, false},
		{Condition{Enabled: true, Field: FieldResponseJQ, Key: ".data.items[].name", Op: OpNotEquals, Value: "grace"}, true},
		{Condition{Enabled: true, Field: FieldResponseJSONPath, Key: "$.data.items[0].name", Op: OpContains, Value: "ad"}, true},
		{Condition{Enabled: true, Field: FieldResponseJSONPath, Key: "$.data.missing"}, false},
		{Condition{Enabled: true, Field: FieldResponseJSONPath, Key: "$.data.items"}, true},
		{Condition{Enabled: true, Field: FieldRequestJQ, Key: ".a", Op: OpContains, Value: "x"}, false},
		{Condition{Enabled: true, Field: FieldQuery, Op: OpContains, Value: "q=hello world"}, true},
		{Condition{Enabled: true, Field: FieldResponseJQ, Key: "(", Op: OpContains, Value: "x"}, false},
	} {
		if got := tc.c.Match(f); got != tc.want {
			t.Errorf("%+v = %v", tc.c, got)
		}
	}
	filter := Filter{Query: "api", Kinds: map[string]bool{"JSON": true}, Conditions: []Condition{
		{Enabled: true, Field: FieldStatus, Op: OpGreater, Value: "499"}, {Enabled: true, Field: FieldURL, Op: OpContains},
	}}
	p := PresetOf("p1", "5xx", filter)
	if len(p.Conditions) != 1 || p.Kinds[0] != "JSON" {
		t.Errorf("preset %+v", p)
	}
	back := p.Filter()
	if back.Query != "api" || !back.Kinds["JSON"] || len(back.Conditions) != 1 {
		t.Errorf("filter %+v", back)
	}
}

func TestDeepSearchFindsEscapedJSONText(t *testing.T) {
	f := flow.New("J")
	f.Request = &flow.Request{Scheme: "https", Host: "api.dev", Port: 443, FullPath: "https://api.dev/x", URI: "/x", Method: flow.Method{Name: "GET"}}
	f.Response = &flow.Response{Status: &flow.Status{Code: 200}, BodyData: flow.Blob(`{"name":"中文","url":"https:\/\/cdn.dev\/a.png","quote":"say \"hi\""}`)}
	for _, q := range []string{"中文", "https://cdn.dev/a.png", `say "hi"`} {
		if !(Filter{Query: q, Deep: true}).Match(f) {
			t.Errorf("%q not found", q)
		}
	}
	if (Filter{Query: "nothing here", Deep: true}).Match(f) {
		t.Error("matched text that is not in the body")
	}
}
