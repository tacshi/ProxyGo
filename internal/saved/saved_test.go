package saved

import (
	"testing"

	"proxygo/internal/flow"
)

func mk(id string) *flow.Flow {
	f := flow.New(id)
	start := 1700000000.0 + float64(len(id))
	f.Timing.RequestStartedAt = &start
	f.Request = &flow.Request{FullPath: "https://api.dev/" + id, Host: "api.dev", Method: flow.Method{Name: "GET"}}
	return f
}

func TestFolders(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	if n, err := s.Add("API/Errors", []*flow.Flow{mk("A"), mk("BB")}, nil); err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if n, _ := s.Add("API/Errors", []*flow.Flow{mk("A")}, nil); n != 2 {
		t.Errorf("a flow saved twice: %d", n)
	}
	s = Open(dir)
	fs := s.Folders()
	if len(fs) != 2 || fs[0].Path != "API" || fs[1].Path != "API/Errors" || fs[1].Count != 2 || fs[1].Parent() != "API" || fs[1].Name() != "Errors" {
		t.Fatalf("%+v", fs)
	}
	b, err := s.Open("API/Errors")
	if err != nil || len(b.Flows) != 2 {
		t.Fatalf("%v %d", err, len(b.Flows))
	}
	if err := s.Remove("API/Errors", "A"); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.Open("API/Errors"); len(b.Flows) != 1 || b.Flows[0].UniqueID != "BB" {
		t.Errorf("after remove: %+v", b.Flows)
	}
	if err := s.Rename("API", "Backend"); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.Open("Backend/Errors"); len(b.Flows) != 1 {
		t.Error("rename lost the flows")
	}
	if err := s.Rename("Backend", "Backend/Inner"); err == nil {
		t.Error("into itself")
	}
	if err := s.Delete("Backend"); err != nil || len(Open(dir).Folders()) != 0 {
		t.Errorf("delete: %v %+v", err, Open(dir).Folders())
	}
	for _, bad := range []string{"", " / ", "a/../b", "x:y"} {
		if _, err := Clean(bad); err == nil {
			t.Errorf("%q is a folder", bad)
		}
	}
	if p, _ := Clean(" a / b "); p != "a/b" {
		t.Errorf("Clean %q", p)
	}
}
