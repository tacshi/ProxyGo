package app

import (
	"slices"
	"strings"
	"testing"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
)

func sourceFlows() []*flow.Flow {
	mk := func(id, app, url string) *flow.Flow {
		f := flow.New(id)
		f.Client.Name = app
		scheme := "https"
		host, path, ok := strings.Cut(url, "/")
		path = "/" + path
		if !ok {
			path = "/"
		}
		f.Request = &flow.Request{Scheme: scheme, Host: host, FullPath: scheme + "://" + host + path, URI: path, Method: flow.Method{Name: "GET"}}
		f.Response = &flow.Response{Status: &flow.Status{Code: 200}}
		return f
	}
	return []*flow.Flow{
		mk("1", "Safari", "api.dev/v1/users?page=1"),
		mk("2", "Safari", "api.dev/v1/users/7"),
		mk("3", "Safari", "api.dev/v2/items"),
		mk("4", "Safari", "cdn.dev/"),
		mk("5", "curl", "api.dev/v1/users"),
		mk("6", "", "api.dev/health"),
	}
}

func labels(cs []sourceChild) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.label())
	}
	return out
}

func TestSourceTree(t *testing.T) {
	tree := buildSources(sourceFlows())
	if tree.apps["Safari"] != 4 || tree.apps["System"] != 1 || tree.domains["api.dev"] != 5 {
		t.Fatalf("counts %v %v", tree.apps, tree.domains)
	}
	safari := source{app: "Safari"}
	if !tree.expandable(safari) || !slices.Equal(labels(tree.children(safari)), []string{"api.dev", "cdn.dev"}) {
		t.Fatalf("Safari's domains %v", labels(tree.children(safari)))
	}
	if tree.expandable(source{app: "Safari", host: "cdn.dev"}) {
		t.Fatal("a domain with only / should not open")
	}
	api := source{host: "api.dev"}
	kids := tree.children(api)
	if !slices.Equal(labels(kids), []string{"/v1", "/health", "/v2"}) || kids[0].count != 3 {
		t.Fatalf("api.dev paths %v %+v", labels(kids), kids)
	}
	v1 := kids[0].source
	if v1.id() != "src:\x1fapi.dev\x1f/v1" {
		t.Fatalf("id %q", v1.id())
	}
	users := tree.children(v1)
	if len(users) != 1 || users[0].path != "/v1/users" || users[0].count != 3 {
		t.Fatalf("v1 children %+v", users)
	}
	if !tree.expandable(users[0].source) || tree.children(users[0].source)[0].label() != "/7" {
		t.Fatal("/v1/users/7")
	}
	inSafari := tree.children(source{app: "Safari", host: "api.dev"})
	if inSafari[0].path != "/v1" || inSafari[0].count != 2 || inSafari[0].app != "Safari" {
		t.Fatalf("Safari's api.dev paths %+v", inSafari)
	}

	for _, s := range []source{safari, api, v1, users[0].source, {app: "curl", host: "api.dev", path: "/v1"}} {
		back, ok := parseSource(s.id())
		if !ok || back != s {
			t.Fatalf("round trip %+v → %q → %+v", s, s.id(), back)
		}
	}
	if up, _ := users[0].parent(); up != v1 {
		t.Fatalf("parent %+v", up)
	}
	if up, _ := (source{app: "Safari", host: "api.dev"}).parent(); up != safari {
		t.Fatal("app domain's parent")
	}
	if _, ok := api.parent(); ok {
		t.Fatal("a domain has no parent")
	}
}

func TestSidebarTree(t *testing.T) {
	a, _ := testApp(t)
	for _, f := range sourceFlows() {
		a.store.Upsert(f)
	}
	tt := ui.NewTester(a.view, 1300, 900)
	tt.Frame()
	if tt.HasText("cdn.dev") && !tt.HasText("Domains (2)") {
		t.Fatal("sections")
	}
	mustClick(t, tt, "Expand Safari")
	if !a.expanded["app:Safari"] {
		t.Fatal("not expanded")
	}
	mustClick(t, tt, "Expand api.dev")
	tt.Frame()
	if !tt.HasText("/v1") || !tt.HasText("/v2") {
		t.Fatalf("paths not shown: %v", tt.Texts())
	}
	mustClick(t, tt, "/v1")
	if a.section != (source{app: "Safari", host: "api.dev", path: "/v1"}).id() {
		t.Fatalf("section %q", a.section)
	}
	if len(a.visible) != 2 {
		t.Fatalf("%d flows under Safari api.dev/v1", len(a.visible))
	}
	tt.Key(0, ui.KeyLeft)
	if a.section != (source{app: "Safari", host: "api.dev"}).id() {
		t.Fatalf("left went to %q", a.section)
	}
	tt.Key(0, ui.KeyLeft)
	if a.expanded[a.section] {
		t.Fatal("left did not close")
	}
	tt.Key(0, ui.KeyRight)
	if !a.expanded[a.section] {
		t.Fatal("right did not open")
	}
	a.expanded = map[string]bool{}
	a.sidebarQuery = "cdn"
	tt.Frame()
	if !tt.HasText("cdn.dev") || tt.HasText("curl") {
		t.Fatalf("filtered sidebar: %v", tt.Texts())
	}
}

func TestDotColumnRoomWithoutSidebar(t *testing.T) {
	a, _ := testApp(t)
	width := func() float32 {
		for _, c := range a.columns() {
			if c.ID == "dot" {
				return c.Width
			}
		}
		return 0
	}
	a.set.ShowSidebar = true
	shown := width()
	a.set.ShowSidebar = false
	if width() <= shown {
		t.Fatalf("dot column %v without the sidebar, %v with it", width(), shown)
	}
}
