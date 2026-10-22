package app

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/internal/systemproxy"
	"proxygo/locales"
)

func testApp(t *testing.T) (*App, *[]string) {
	t.Helper()
	a, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var copied []string
	a.clipboard = func(s string) { copied = append(copied, s) }
	t.Cleanup(a.proxy.Stop)
	return a, &copied
}

func at(sec float64) *float64 { return new(1_700_000_000 + sec) }

func pngBytes() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 4, 3))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

func fixtures() []*flow.Flow {
	mk := func(id, method, rawURL string, status int, reqCT string, reqBody []byte, respCT string, respBody []byte) *flow.Flow {
		f := flow.New(id)
		scheme, rest, _ := strings.Cut(rawURL, "://")
		host, path, _ := strings.Cut(rest, "/")
		f.IsSSL = scheme == "https" || scheme == "wss"
		f.Client = flow.Client{Name: "Safari", PID: 42, Path: "/Applications/Safari.app/Contents/MacOS/Safari"}
		f.Timing = flow.Timing{RequestStartedAt: at(float64(len(id))), RequestEndedAt: at(float64(len(id)) + 0.01), ResponseStartedAt: at(float64(len(id)) + 0.05), ResponseEndedAt: at(float64(len(id)) + 0.12),
			UpstreamConnectStartedAt: at(float64(len(id)) + 0.001), UpstreamConnectEndedAt: at(float64(len(id)) + 0.004)}
		h := http.Header{"Host": {host}, "Accept": {"*/*"}, "Cookie": {"session=abc"}}
		if reqCT != "" {
			h.Set("Content-Type", reqCT)
		}
		f.Request = &flow.Request{Scheme: map[string]string{"wss": "https", "ws": "http"}[scheme] + map[bool]string{true: scheme}[scheme == "http" || scheme == "https"],
			Host: host, Port: map[bool]int{true: 443, false: 80}[f.IsSSL], FullPath: rawURL, URI: "/" + path,
			Method: flow.Method{Name: method}, Version: flow.Version{Major: 1, Minor: 1}, Header: flow.NewHeader(h), BodyData: reqBody}
		f.Summary = flow.Summary{ClientIPAddress: "127.0.0.1", ClientPort: 50000, ServerIPAddress: "93.184.216.34", ServerPort: f.Request.Port}
		if status > 0 {
			rh := http.Header{"Content-Type": {respCT}, "Set-Cookie": {"token=xyz; Path=/; HttpOnly; Secure"}, "X-Request-Id": {"req-" + id}}
			f.Response = &flow.Response{Status: &flow.Status{Code: status, Phrase: http.StatusText(status)}, Version: flow.Version{Major: 1, Minor: 1}, Header: flow.NewHeader(rh), BodyData: respBody}
		}
		return f
	}
	jsonFlow := mk("A1", "GET", "https://api.example.com/v1/users?page=2&q=go", 200, "", nil, "application/json", []byte(`{"users":[{"id":1,"name":"Ada"},{"id":2,"name":"Linus"}],"next":null,"ok":true,"count":2}`))
	form := mk("B22", "POST", "http://forms.example.com/login", 302, "application/x-www-form-urlencoded", []byte("user=ada&pass=s%20ecret"), "text/html", []byte("<html><body>Moved</body></html>"))
	img := mk("C333", "GET", "https://cdn.example.com/logo.png", 200, "", nil, "image/png", pngBytes())
	gql := mk("D4444", "POST", "https://api.example.com/graphql", 200, "application/json", []byte(`{"operationName":"GetUser","query":"query GetUser($id: ID!) { user(id: $id) { name } }","variables":{"id":1}}`), "application/json", []byte(`{"data":{"user":{"name":"Ada"}}}`))
	errFlow := mk("E55555", "GET", "https://down.example.com/", 0, "", nil, "", nil)
	errFlow.Response = &flow.Response{Status: &flow.Status{Code: 999, Phrase: "Error"}, Error: flow.ResponseError{"couldNotConnectToServer": map[string]any{"message": "dial tcp: connection refused"}}}
	tunnel := mk("F666666", "CONNECT", "https://secure.example.com", 200, "", nil, "", nil)
	tunnel.Request.URI = "secure.example.com:443"
	ws := mk("G7777777", "GET", "wss://chat.example.com/socket", 101, "", nil, "", nil)
	ws.Request.IsWebSocketUpgrade = true
	ws.WebSocketMessageStorage = &flow.WebSocketStorage{Messages: []flow.WebSocketMessage{
		{From: "client", Type: "text", Data: `{"hello":"world"}`, Time: 1_700_000_008.1},
		{From: "server", Type: "text", Data: "welcome", Time: 1_700_000_008.2},
		{From: "server", Type: "binary", RawData: flow.Blob{1, 2, 3}, Time: 1_700_000_008.3},
		{From: "client", Type: "close", CloseCode: 1000, Time: 1_700_000_008.4},
	}}
	active := mk("H88888888", "GET", "https://slow.example.com/wait", 0, "", nil, "", nil)
	proto := mk("I999999999", "POST", "https://grpc.example.com/svc/Method", 200, "application/grpc", []byte{0, 0, 0, 0, 3, 8, 150, 1}, "application/grpc", []byte{0, 0, 0, 0, 7, 10, 5, 'h', 'e', 'l', 'l', 'o'})
	xml := mk("J1010101010", "GET", "http://feeds.example.com/rss.xml", 200, "", nil, "application/xml", []byte("<rss><channel><title>T</title></channel></rss>"))
	return []*flow.Flow{jsonFlow, form, img, gql, errFlow, tunnel, ws, active, proto, xml}
}

func loaded(t *testing.T) (*App, *ui.Tester, *[]string) {
	t.Helper()
	a, copied := testApp(t)
	for _, f := range fixtures() {
		a.store.Upsert(f)
	}
	tt := ui.NewTester(a.view, 1440, 900)
	tt.Frame()
	return a, tt, copied
}

func mustClick(t *testing.T, tt *ui.Tester, text string) {
	t.Helper()
	if err := tt.Click(text); err != nil {
		t.Fatalf("click %q: %v\n%v", text, err, tt.Texts())
	}
}

func TestMainWindowShowsFlows(t *testing.T) {
	a, tt, _ := loaded(t)
	for _, want := range []string{"ProxyGo", "Overview", "All", "Saved", "https://api.example.com/v1/users?page=2&q=go", "GetUser", "Safari", "10 flows", "Auto Select"} {
		if !tt.HasText(want) {
			t.Errorf("missing %q", want)
		}
	}
	if len(a.visible) != 10 {
		t.Fatalf("%d rows", len(a.visible))
	}
	if !tt.HasText("Select a flow to inspect it") {
		t.Fatal("empty inspector")
	}
}

func TestEveryTabOfEveryFlow(t *testing.T) {
	a, tt, _ := loaded(t)
	for _, dark := range []bool{false, true} {
		tt.SetDark(dark)
		for _, f := range a.store.Snapshot() {
			a.selectFlow(f.UniqueID)
			for _, rt := range reqTabs {
				a.reqTabName = rt
				for _, st := range append(slices.Clone(respTabs), wsTabs...) {
					a.respTabName = st
					tt.Frame()
				}
			}
			if !tt.HasText(f.MethodName()) {
				t.Fatalf("%s: method not shown", f.URL())
			}
			for k := range 6 {
				for key := range a.bodyMode {
					a.bodyMode[key] = k
				}
				a.reqTabName, a.respTabName = "Body", "Body"
				tt.Frame()
			}
		}
	}
}

func TestInspectorContent(t *testing.T) {
	a, tt, _ := loaded(t)
	a.selectFlow("A1")
	a.reqTabName, a.respTabName = "Header", "Header"
	tt.Frame()
	for _, want := range []string{"Request", "Response", "Header", "Query", "Body", "Accept", "*/*", "X-Request-Id", "req-A1", "200 OK"} {
		if !tt.HasText(want) {
			t.Errorf("missing %q", want)
		}
	}
	mustClick(t, tt, "Query")
	if !tt.HasText("page") || !tt.HasText("go") {
		t.Fatal("query table")
	}
	a.respTabName = "Body"
	tt.Frame()
	if !tt.HasText("Pretty") || !tt.HasText("Tree") {
		t.Fatalf("JSON body modes: %v", tt.Texts())
	}
	a.selectFlow("F666666")
	tt.Frame()
	if !tt.HasText("Encrypted HTTPS") || !tt.HasText("Enable only secure.example.com") {
		t.Fatal("tunnel pane")
	}
	mustClick(t, tt, "Enable only secure.example.com")
	if !a.rules.Current().ShouldMITM("secure.example.com") {
		t.Fatal("SSL proxying not enabled")
	}
	a.selectFlow("E55555")
	tt.Frame()
	if !tt.HasText("The request failed") || !tt.HasText("dial tcp: connection refused") {
		t.Fatal("error pane")
	}
	pinned := fixtures()[5]
	pinned.UniqueID = "P1"
	pinned.Response = &flow.Response{Status: &flow.Status{Code: 999, Phrase: "Error"}, Error: flow.ResponseError{"sslHandshake": map[string]any{"message": "The client rejected ProxyGo's certificate"}}}
	pinned.TLS = &flow.TLSDetails{Client: &flow.TLSInfo{Error: "remote error: tls: bad certificate", PinningLikely: true}}
	a.store.Upsert(pinned)
	a.selectFlow("P1")
	tt.Frame()
	if !tt.HasText("Failed") || tt.HasText("Encrypted HTTPS") || !tt.HasText("The client rejected ProxyGo's certificate") {
		t.Fatalf("failed tunnel: %v", tt.Texts())
	}
	mustClick(t, tt, "Exclude secure.example.com from SSL Proxying")
	if a.rules.Current().ShouldMITM("secure.example.com") {
		t.Fatal("host not excluded")
	}
	a.selectFlow("G7777777")
	tt.Frame()
	if !tt.HasText("Messages") || !tt.HasText("welcome") {
		t.Fatalf("websocket messages: %v", tt.Texts())
	}
	a.selectFlow("H88888888")
	tt.Frame()
	if !tt.HasText("Waiting for the response…") {
		t.Fatal("active flow")
	}
}

func TestFilters(t *testing.T) {
	a, tt, _ := loaded(t)
	a.query = "cdn"
	tt.Frame()
	if len(a.visible) != 1 || !tt.HasText("1 of 10 flows") {
		t.Fatalf("query: %d", len(a.visible))
	}
	a.query = ""
	mustClick(t, tt, "JSON")
	if len(a.visible) != 2 {
		t.Fatalf("JSON chip: %d", len(a.visible))
	}
	r, _ := tt.Find("HTTP")
	tt.ClickAt(r.X-22, r.Y+r.H/2)
	if len(a.visible) != 10 || len(a.kinds) != 0 {
		t.Fatalf("All chip: %d %v", len(a.visible), a.kinds)
	}
	mustClick(t, tt, "HTTP")
	for _, f := range a.visible {
		if f.IsHTTPS() {
			t.Fatalf("HTTPS flow %s under HTTP", f.URL())
		}
	}
	mustClick(t, tt, "JSON")
	if err := tt.ClickWith(ui.Cmd, "XML"); err != nil {
		t.Fatal(err)
	}
	if !a.kinds["JSON"] || !a.kinds["XML"] || len(a.visible) != 3 {
		t.Fatalf("Cmd-click: %v, %d flows", a.kinds, len(a.visible))
	}
	a.clearFilters()
	a.advanced = true
	a.conditions = []storeCondition{{Enabled: true, Field: "Status Code", Op: "greater than", Value: "299"}}
	tt.Frame()
	if len(a.visible) != 2 || !tt.HasText("Match All") {
		t.Fatalf("conditions: %d", len(a.visible))
	}
	mustClick(t, tt, "Clear Filters")
	if len(a.visible) != 10 {
		t.Fatal("clear filters")
	}
	a.section = "domain:cdn.example.com"
	tt.Frame()
	if len(a.visible) != 1 {
		t.Fatal("domain section")
	}
	a.section = "app:Safari"
	tt.Frame()
	if len(a.visible) != 10 {
		t.Fatal("app section")
	}
}

func TestSortByColumn(t *testing.T) {
	a, tt, _ := loaded(t)
	a.sort = ui.SortOrder{Column: "statusCode", Descending: true}
	tt.Frame()
	if a.visible[0].StatusCode() != 999 {
		t.Fatalf("first %d", a.visible[0].StatusCode())
	}
	a.sort = ui.SortOrder{}
	tt.Frame()
	if a.visible[0].UniqueID != "A1" {
		t.Fatal("row order")
	}
}

func TestFlowContextMenu(t *testing.T) {
	a, tt, copied := loaded(t)
	url := "https://api.example.com/v1/users?page=2&q=go"
	if err := tt.RightClick(url); err != nil {
		t.Fatal(err)
	}
	menu := tt.Menu()
	for _, want := range []string{"Copy URL", "Copy as cURL", "Repeat", "Edit and Repeat…", "Add Comment…", "Highlight", "Save Request", "Delete 1 Flow"} {
		if !slices.Contains(menu, want) {
			t.Errorf("menu lacks %q: %v", want, menu)
		}
	}
	if err := tt.ChooseMenuItem("Copy as cURL"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if len(*copied) == 0 || !strings.HasPrefix((*copied)[len(*copied)-1], "curl 'https://api.example.com/v1/users") {
		t.Fatalf("copied %v", *copied)
	}
	if a.selected != "A1" {
		t.Fatalf("right click did not select the row: %q", a.selected)
	}
	tt.RightClick(url)
	if err := tt.ChooseMenuItem("Highlight", "Green"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if f, _ := a.store.Lookup("A1"); f.Highlight != "green" {
		t.Fatal("highlight")
	}
	tt.RightClick(url)
	tt.ChooseMenuItem("Save Request")
	tt.Frame()
	if f, _ := a.store.Lookup("A1"); !f.Saved || !tt.HasText("1") {
		t.Fatal("save request")
	}
	tt.RightClick(url)
	tt.ChooseMenuItem("Add Comment…")
	tt.Frame()
	if !a.comment.open || !tt.HasText("Comment") {
		t.Fatal("comment sheet")
	}
	a.comment.text = "look at this"
	mustClick(t, tt, "Save")
	if f, _ := a.store.Lookup("A1"); f.Comment != "look at this" {
		t.Fatal("comment saved")
	}
	tt.RightClick(url)
	tt.ChooseMenuItem("Delete 1 Flow")
	tt.Frame()
	if _, ok := a.store.Lookup("A1"); ok {
		t.Fatal("delete")
	}
}

func TestToolsFromFlow(t *testing.T) {
	a, tt, _ := loaded(t)
	f, _ := a.store.Lookup("A1")
	for _, c := range []struct {
		kind  string
		open  func(*flow.Flow)
		count func(*rules.Data) int
	}{
		{"maplocal", a.mapLocalFromFlow, func(d *rules.Data) int { return len(d.MapLocal) }},
		{"mapremote", a.mapRemoteFromFlow, func(d *rules.Data) int { return len(d.MapRemote) }},
		{"network", a.throttleFromFlow, func(d *rules.Data) int { return len(d.NetworkConditions) }},
	} {
		c.open(f)
		d := a.rules.Current()
		if st := a.tools[c.kind]; c.count(d) != 0 || st == nil || !st.editing || !st.isNew {
			t.Fatalf("%s: %d rules saved before Add", c.kind, c.count(d))
		}
		spec := windowSpecs[c.kind]
		mustClick(t, ui.NewTester(func(ctx *ui.Context) { a.toolWindow(ctx, c.kind) }, spec.width, spec.height), "Add")
		if d := a.rules.Current(); c.count(d) != 1 {
			t.Fatalf("%s: %d rules after Add", c.kind, c.count(d))
		}
	}
	d := a.rules.Current()
	if !strings.Contains(d.MapLocal[0].Body, "Ada") || d.MapLocal[0].StatusCode != 200 {
		t.Fatalf("map local %+v", d.MapLocal)
	}
	a.breakpointFromFlow(f)
	a.blockFromFlow(f, false)
	a.scriptFromFlow(f)
	d = a.rules.Current()
	if len(d.Breakpoints) != 1 || len(d.Block) != 1 || len(d.Scripts) != 1 {
		t.Fatal("tools from flow")
	}
	if !d.Breakpoints[0].Matches("GET", "https://api.example.com/v1/users?page=9") {
		t.Fatal("breakpoint rule should match the URL with any query")
	}
	a.togglePin("host:api.example.com")
	a.section = "pinned"
	tt.Frame()
	if len(a.visible) != 2 || !tt.HasText("api.example.com") {
		t.Fatalf("pinned %d", len(a.visible))
	}
}

func TestOverviewAndPalette(t *testing.T) {
	a, tt, _ := loaded(t)
	mustClick(t, tt, "Overview")
	for _, want := range []string{"Requests", "Status", "Top Domains", "Top Apps", "Content Types", "Slowest", "Largest Responses", "Requests over time", "Data over time", "Response Times", "HTTPS Decryption", "Errors", "Copy as Markdown"} {
		if !tt.HasText(want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	a.section = "all"
	a.selectFlow("A1")
	a.openPalette()
	tt.Frame()
	if !tt.HasText("Repeat") || !tt.HasText("Clear Session") {
		t.Fatal("palette commands")
	}
	tt.Type("clear session")
	tt.Frame()
	tt.Key(0, ui.KeyEnter)
	tt.Frame()
	if a.palette.open || a.store.Len() != 0 {
		t.Fatalf("palette did not clear: open %v, %d flows", a.palette.open, a.store.Len())
	}
	if !tt.HasText("Waiting for traffic") {
		t.Fatal("empty state")
	}
}

func TestLayouts(t *testing.T) {
	a, tt, _ := loaded(t)
	a.selectFlow("D4444")
	for _, right := range []bool{false, true} {
		for _, side := range []bool{false, true} {
			a.set.DetailRight, a.set.ShowSidebar = right, side
			tt.Frame()
			if !tt.HasText("GraphQL · GetUser") {
				t.Fatalf("right %v sidebar %v: inspector missing", right, side)
			}
		}
	}
	a.set.ShowDetail = false
	tt.Frame()
	if tt.HasText("GraphQL · GetUser") {
		t.Fatal("inspector shown while hidden")
	}
	a.set.ShowDetail = true
	tt.SetSize(900, 560)
	tt.Frame()
}

func TestChoosingRows(t *testing.T) {
	a, tt, _ := loaded(t)
	at := func(s string) (float32, float32) {
		t.Helper()
		r, ok := tt.Find(s)
		if !ok {
			t.Fatalf("no %q", s)
		}
		return r.X + 2, r.Y + r.H/2
	}
	jx, jy := at("https://api.example.com/v1/users?page=2&q=go")
	fx, fy := at("http://forms.example.com/login")
	tt.ClickAt(jx, jy)
	tt.ClickAtWith(ui.Cmd, fx, fy)
	tt.Frame()
	if a.chosen.Len() != 2 || a.selected != "B22" {
		t.Fatalf("chosen %d, inspector on %q", a.chosen.Len(), a.selected)
	}
	tt.ClickAtWith(ui.Cmd, fx, fy)
	tt.Frame()
	if a.chosen.Has("B22") || a.selected != "A1" || !tt.HasText("GET") {
		t.Fatalf("chosen %v, inspector on %q", a.chosen.Has("B22"), a.selected)
	}

	a.updateSettings(func(s *settings.Settings) { s.AutoSelect = true })
	tt.Frame()
	nf := fixtures()[0].Clone()
	nf.UniqueID, nf.ID = "K1", "11"
	a.store.Upsert(nf)
	tt.Frame()
	if a.selected != "K1" || !a.chosen.Has("K1") || a.chosen.Len() != 1 {
		t.Fatalf("Auto Select: inspector on %q, %d chosen", a.selected, a.chosen.Len())
	}
	a.selectFlow("A1")
	a.store.Update("K1", func(f *flow.Flow) { f.Comment = "changed" })
	tt.Frame()
	if a.selected != "A1" {
		t.Fatalf("a change to a flow took the choice to %q", a.selected)
	}
}

func TestDeleteShownSource(t *testing.T) {
	a, tt, _ := loaded(t)
	a.section = "domain:api.example.com"
	a.deleteMatching(func(f *flow.Flow) bool { return f.UniqueID == "A1" })
	tt.Frame()
	if a.section != "domain:api.example.com" || len(a.visible) != 1 {
		t.Fatalf("one of two deleted: %s, %d flows", a.section, len(a.visible))
	}
	a.deleteMatching(func(f *flow.Flow) bool { return f.Host() == "api.example.com" })
	tt.Frame()
	if a.section != "all" || len(a.visible) != len(fixtures())-2 {
		t.Fatalf("all deleted: %s, %d flows", a.section, len(a.visible))
	}
}

func TestOpenMovedSession(t *testing.T) {
	a, tt, _ := loaded(t)
	path := t.TempDir() + "/gone.proxygosession"
	a.updateSettings(func(s *settings.Settings) { s.AddRecent(path) })
	a.openPath(path, false)
	tt.Frame()
	if slices.Contains(a.set.RecentSessions, path) || !tt.HasText("gone.proxygosession is no longer there: it was moved or deleted") {
		t.Fatalf("recent %v, texts %v", a.set.RecentSessions, tt.Texts())
	}
	if a.store.Len() != len(fixtures()) {
		t.Fatal("the session was replaced")
	}
}

func TestHeaderRowMenu(t *testing.T) {
	a, tt, _ := loaded(t)
	a.selectFlow("A1")
	a.reqTabName = "Header"
	tt.Frame()
	r, ok := tt.Find("session=abc")
	if !ok {
		t.Fatal("no Cookie header")
	}
	for _, x := range []float32{r.X + 4, r.X + r.W + 60} {
		tt.RightClickAt(x, r.Y+r.H/2)
		if menu := tt.Menu(); !slices.Contains(menu, "Copy Value") || !slices.Contains(menu, "Show Cookie as a Column") {
			t.Fatalf("at x %v: menu %v", x, menu)
		}
		tt.CloseMenu()
	}
}

func TestInspectorKeepsRoom(t *testing.T) {
	a, tt, _ := loaded(t)
	a.certTrusted = false
	a.set.TableHeight = 5000
	a.selectFlow("F666666")
	for _, c := range []struct {
		w, h int
		last string
	}{{1440, 900, "Install Certificate…"}, {900, 560, "Encrypted HTTPS"}} {
		tt.SetSize(c.w, c.h)
		tt.Frame()
		r, ok := tt.Find(c.last)
		footer, _ := tt.Find("Auto Select")
		if !ok || r.H == 0 || r.Y+r.H > footer.Y-8 {
			t.Fatalf("%dx%d: %q (%v) is not above the status bar (%v)", c.w, c.h, c.last, r, footer)
		}
	}
	if a.set.TableHeight != 5000 {
		t.Fatalf("the table's height changed to %v", a.set.TableHeight)
	}
}

func TestCenteredPanesHoldStill(t *testing.T) {
	for _, right := range []bool{false, true} {
		a, _ := testApp(t)
		a.certTrusted = false
		a.set.DetailRight = right
		for _, f := range fixtures() {
			a.store.Upsert(f)
		}
		var tt *ui.Tester
		seen := map[string][]float32{}
		texts := []string{"Select a flow to inspect it", "Encrypted HTTPS", "Waiting for the response…"}
		tt = ui.NewTester(func(c *ui.Context) {
			for _, s := range texts {
				if tt == nil {
					break
				}
				if r, ok := tt.Find(s); ok {
					seen[s] = append(seen[s], r.Y)
				}
			}
			a.view(c)
		}, 1440, 900)
		tt.Frame()
		tt.Frame()
		clear(seen)
		arrive := func(n int) {
			for i := range n {
				f := fixtures()[0]
				f.UniqueID = "N" + strconv.Itoa(len(a.flows)) + "-" + strconv.Itoa(i)
				f.ID = f.UniqueID
				a.store.Upsert(f)
				tt.Frame()
			}
		}
		arrive(3)
		for _, id := range []string{"F666666", "H88888888", "F666666", ""} {
			a.selectFlow(id)
			tt.Frame()
			arrive(3)
		}
		tt.Frame()
		for _, s := range texts {
			ys := seen[s]
			if len(ys) == 0 {
				t.Fatalf("right %v: %q never showed", right, s)
			}
			for _, y := range ys {
				if y != ys[0] {
					t.Fatalf("right %v: %q moved: %v", right, s, ys)
				}
			}
		}
	}
}

func TestToastsShowInTheirWindow(t *testing.T) {
	a, tt, _ := loaded(t)
	cert := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, "certificate") }, 820, 640)
	a.toasts = map[string][]string{"certificate": {"Installed"}}
	cert.Frame()
	tt.Frame()
	if !cert.HasText("Installed") || tt.HasText("Installed") {
		t.Fatalf("certificate window %v, main window %v", cert.HasText("Installed"), tt.HasText("Installed"))
	}
	cert.Advance(5 * time.Second)
	cert.Frame()
	if cert.HasText("Installed") {
		t.Fatal("the toast stayed")
	}
	a.toasts["certificate"] = []string{"Later"}
	a.forget("certificate")
	tt.Frame()
	if !tt.HasText("Later") {
		t.Fatal("a closed window's toast was lost")
	}
}

func TestRouteBanner(t *testing.T) {
	a, tt, _ := loaded(t)
	const hint = "macOS does not send its traffic to ProxyGo: browsers and most apps bypass it."
	if tt.HasText(hint) {
		t.Fatal("shown before the macOS proxy was read")
	}
	a.sysKnown = true
	tt.Frame()
	if !tt.HasText(hint) || !tt.HasText("Override macOS Proxy") {
		t.Fatal("no banner while macOS bypasses ProxyGo")
	}
	a.sys = systemproxy.State{HTTP: true, HTTPS: true, Host: "proxy.corp", Port: 3128}
	tt.Frame()
	if !tt.HasText("macOS sends its traffic to another proxy, proxy.corp:3128, not to ProxyGo.") {
		t.Fatal("the other proxy is not named")
	}
	a.sys = systemproxy.State{HTTP: true, HTTPS: true, Host: "127.0.0.1", Port: a.proxy.Port()}
	tt.Frame()
	if tt.HasText("Override macOS Proxy") {
		t.Fatal("banner while macOS uses ProxyGo")
	}
	a.sys = systemproxy.State{}
	tt.Frame()
	mustClick(t, tt, "Hide")
	if tt.HasText(hint) {
		t.Fatal("the banner did not close")
	}
}

func TestRuleWindows(t *testing.T) {
	a, _ := testApp(t)
	key, err := a.certs.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pair := filepath.Join(t.TempDir(), "pair.pem")
	if err := os.WriteFile(pair, append(a.certs.CertPEM(), key...), 0o600); err != nil {
		t.Fatal(err)
	}
	for kind, k := range ruleKinds {
		tt := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, kind) }, 900, 640)
		tt.Frame()
		before := len(k.ids(a.rules.Current()))
		if !tt.HasText(k.title()) || before == 0 && !tt.HasText(orText(k.empty, locales.NoRulesYet)) {
			t.Fatalf("%s: %v", kind, tt.Texts())
		}
		if err := tt.Click(k.add()); err != nil {
			t.Fatalf("%s add: %v", kind, err)
		}
		st := a.toolState(kind)
		if !st.editing {
			t.Fatalf("%s: editor not open", kind)
		}
		switch r := st.draft.(type) {
		case *rules.MapLocalRule:
			r.URL = "https://api.dev/*"
		case *rules.MapRemoteRule:
			r.URL, r.NewURL = "https://api.dev/*", "http://localhost:3000"
		case *rules.BreakpointRule:
			r.URL = "https://api.dev/*"
		case *rules.URLRule:
			r.URL = "https://api.dev/*"
		case *rules.NetworkCondition:
			r.URL = "https://api.dev/*"
		case *rules.DNSRule:
			r.Host = "api.dev"
		case *rules.ReverseProxy:
			r.Target = "https://api.dev"
		case *rules.ClientCertificate:
			r.Host, r.CertPath = "api.dev", pair
		case *rules.ServerCertificate:
			r.Hosts, r.CertPath = []string{"proxygo.local"}, pair
		case *rules.AppRule:
			r.AppName = "Safari"
		case *rules.ProtobufRule:
			r.URL = "https://api.dev/*"
		}
		st.test = "https://api.dev/users"
		tt.Frame()
		if err := tt.Click("Add"); err != nil {
			t.Fatalf("%s save: %v %v", kind, err, tt.Texts())
		}
		tt.Frame()
		d := a.rules.Current()
		if n := len(k.ids(d)); n != before+1 {
			t.Fatalf("%s: %d rules after adding", kind, n)
		}
		id := k.ids(d)[before]
		a.duplicateRule(kind, id)
		tt.Frame()
		if len(k.ids(a.rules.Current())) != before+2 {
			t.Fatalf("%s: duplicate", kind)
		}
		if k.tool != "" {
			a.setTool(k.tool, false)
			tt.Frame()
			if a.toolOn(k.tool) || !tt.HasText("Off") {
				t.Fatalf("%s: tool switch", kind)
			}
			a.setTool(k.tool, true)
		}
	}
}

func TestMatcherFormTestsURLs(t *testing.T) {
	a, _ := testApp(t)
	st := a.toolState("block")
	a.beginEdit("block", st, &rules.URLRule{ID: "x", Enabled: true, Matcher: rules.Matcher{URL: "*/ads/*"}}, true)
	tt := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, "block") }, 900, 640)
	st.test = "https://site.dev/ads/1"
	tt.Frame()
	if !tt.HasText("This URL matches") {
		t.Fatal("match shown")
	}
	st.test = "https://site.dev/other"
	tt.Frame()
	if !tt.HasText("This URL does not match") {
		t.Fatal("mismatch shown")
	}
	st.draft.(*rules.URLRule).Match = "regex"
	st.draft.(*rules.URLRule).URL = "("
	tt.Frame()
	if !slices.ContainsFunc(tt.Texts(), func(s string) bool { return strings.HasPrefix(s, "Invalid regular expression") }) {
		t.Fatalf("regex error: %v", tt.Texts())
	}
}

func TestSSLWindow(t *testing.T) {
	a, _ := testApp(t)
	tt := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, "ssl") }, 800, 600)
	tt.Frame()
	st := a.toolState("ssl")
	st.newHost = "https://shop.example.com/cart"
	tt.Frame()
	mustClick(t, tt, "Add")
	d := a.rules.Current()
	if !d.SSL.Enabled || len(d.SSL.Rules) != 1 || d.SSL.Rules[0].Target != "shop.example.com" {
		t.Fatalf("ssl %+v", d.SSL)
	}
	mustClick(t, tt, "Exclude")
	if !tt.HasText("No excluded hosts.") {
		t.Fatal("exclude tab")
	}
}

func TestBreakpointEditor(t *testing.T) {
	a, _ := testApp(t)
	tt := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, "bpedit") }, 1000, 700)
	tt.Frame()
	if !tt.HasText("Nothing is paused") {
		t.Fatal("empty editor")
	}
	var h flow.Header
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", "2")
	f := flow.New("P1")
	f.Request = &flow.Request{Method: flow.Method{Name: "POST"}, FullPath: "https://api.dev/items"}
	pause := &proxy.Pause{ID: "pause1", Rule: "items", Flow: f, Message: proxy.Message{Method: "POST", URL: "https://api.dev/items", Header: h, Body: []byte("{}")}}
	result := make(chan decision, 1)
	go func() {
		msg, ok := a.breakpoint(t.Context(), pause)
		result <- decision{msg: msg, ok: ok}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(a.pauses) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		tt.Frame()
	}
	if len(a.pauses) != 1 || !tt.HasText("https://api.dev/items") || !tt.HasText("Execute") {
		t.Fatalf("pause not shown: %v", tt.Texts())
	}
	pd := a.pauses[0]
	pd.edit.method = "PUT"
	pd.edit.body.Buffer.Set(`{"a":1}`)
	mustClick(t, tt, "Execute")
	d := <-result
	if !d.ok || d.msg.Method != "PUT" || string(d.msg.Body) != `{"a":1}` || d.msg.Header.Get("Content-Length") != "7" {
		t.Fatalf("decision %+v", d)
	}
	if len(a.pauses) != 0 {
		t.Fatal("pause not removed")
	}
}

func TestComposeSends(t *testing.T) {
	a, _ := testApp(t)
	ts := newEcho(t)
	a.proxy = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Rules: a.rules, Sink: a.store, Certs: a.certs})
	if err := a.proxy.Start(); err != nil {
		t.Fatal(err)
	}
	a.composeFrom(nil)
	a.compose.edit.method = "POST"
	a.compose.edit.url = ts + "/echo?x=1"
	a.compose.edit.body.Buffer.Set(`{"hi":true}`)
	a.compose.edit.setHeader("Content-Type", "application/json")
	tt := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, "compose") }, 1100, 720)
	tt.Frame()
	mustClick(t, tt, "Send")
	deadline := time.Now().Add(5 * time.Second)
	for a.compose.result == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		tt.Frame()
	}
	if a.compose.result == "" {
		t.Fatalf("no response: %q", a.compose.err)
	}
	tt.Frame()
	if !tt.HasText("200 OK") {
		t.Fatalf("response not shown: %v", tt.Texts())
	}
	f, _ := a.store.Lookup(a.compose.result)
	if string(f.Response.BodyData) != `POST /echo?x=1 {"hi":true}` {
		t.Fatalf("body %q", f.Response.BodyData)
	}
	mustClick(t, tt, "Query")
	if !tt.HasText("Add Parameter") {
		t.Fatal("query editor")
	}
}

func TestOtherWindows(t *testing.T) {
	a, _ := testApp(t)
	for _, f := range fixtures() {
		a.store.Upsert(f)
	}
	a.refreshFlows()
	a.compare(fixtures()[0], fixtures()[3])
	for _, kind := range []string{"diff", "scripting", "certificate", "settings", "help", "compose"} {
		tt := ui.NewTester(func(c *ui.Context) { a.toolWindow(c, kind) }, 1100, 720)
		tt.Frame()
		if len(tt.Texts()) == 0 {
			t.Fatalf("%s is empty", kind)
		}
		if kind == "settings" {
			for i := range settingsTabs {
				a.settingsTab = i
				tt.Frame()
			}
		}
		if kind == "certificate" {
			for i := range certTabs {
				a.certTab = i
				tt.Frame()
			}
			if !tt.HasText("NODE_EXTRA_CA_CERTS") && !tt.HasText("Node.js") {
				t.Fatal("certificate guides")
			}
		}
		if kind == "scripting" {
			mustClick(t, tt, "New Script")
			if len(a.rules.Current().Scripts) != 1 || !tt.HasText("Console") {
				t.Fatal("new script")
			}
		}
		if kind == "diff" && !tt.HasText("Swap Sides") {
			t.Fatalf("diff: %v", tt.Texts())
		}
	}
}

func TestDarkAppearance(t *testing.T) {
	a, tt, _ := loaded(t)
	a.setAppearance("dark")
	tt.Frame()
	if !a.pal.dark {
		t.Fatal("dark palette")
	}
	a.setAppearance("light")
	tt.SetDark(true)
	tt.Frame()
	if a.pal.dark {
		t.Fatal("light appearance followed the system")
	}
}

func TestReturnSavesFilter(t *testing.T) {
	a, tt, _ := loaded(t)
	a.query = "cdn"
	a.presetSave = presetSheet{open: true}
	tt.Frame()
	tt.Type("CDN")
	tt.Frame()
	tt.Key(0, ui.KeyEnter)
	tt.Frame()
	if a.presetSave.open || len(a.set.FilterPresets) != 1 || a.set.FilterPresets[0].Name != "CDN" {
		t.Fatalf("open %v, presets %+v", a.presetSave.open, a.set.FilterPresets)
	}
}

func TestDeleteSelectsNextRow(t *testing.T) {
	a, tt, _ := loaded(t)
	tt.Frame()
	if len(a.visible) < 3 {
		t.Fatalf("%d rows", len(a.visible))
	}
	second, third := a.visible[1].UniqueID, a.visible[2].UniqueID
	a.selectFlow(second)
	a.deleteFlows([]*flow.Flow{a.visible[1]})
	tt.Frame()
	if a.selected != third {
		t.Fatalf("selected %q, want %q", a.selected, third)
	}
	last := a.visible[len(a.visible)-1]
	before := a.visible[len(a.visible)-2].UniqueID
	a.selectFlow(last.UniqueID)
	a.deleteFlows([]*flow.Flow{last})
	tt.Frame()
	if a.selected != before {
		t.Fatalf("selected %q after the last row, want %q", a.selected, before)
	}
}

func TestSmallHelpers(t *testing.T) {
	encode := func(c color.NRGBA) []byte {
		img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
		for i := range 16 {
			img.Set(i%4, i/4, c)
		}
		var b bytes.Buffer
		_ = png.Encode(&b, img)
		return b.Bytes()
	}
	if !blankImage(encode(color.NRGBA{})) || blankImage(encode(color.NRGBA{R: 200, A: 255})) || blankImage([]byte("not an image")) {
		t.Error("blankImage")
	}
	for sec, want := range map[int]string{30: "30 s", 60: "1 min", 7200: "2 h", 86400: "1 day", 3 * 86400: "3 days"} {
		if got := maxAgeText(sec); got != want {
			t.Errorf("maxAgeText(%d) = %q, want %q", sec, got, want)
		}
	}
	share := float32(0)
	adoptShare(&share, 300, 600)
	if share != 0.5 || shareOf(share, 300, 900) != 450 {
		t.Errorf("share %v, size %v", share, shareOf(share, 300, 900))
	}
	f := flow.New("T")
	f.Request = &flow.Request{Header: flow.NewHeader(http.Header{"Accept": {"*/*"}})}
	f.Response = &flow.Response{Status: &flow.Status{Code: 200}, Header: flow.NewHeader(http.Header{"Content-Type": {"text/plain"}})}
	if slices.Contains(requestTabs(f), "Cookies") || slices.Contains(responseTabs(respTabs, f), "Set-Cookie") {
		t.Error("cookie tabs without cookies")
	}
	f.Request.Header.Set("Cookie", "a=1")
	f.Response.Header.Set("Set-Cookie", "b=2")
	if !slices.Contains(requestTabs(f), "Cookies") || !slices.Contains(responseTabs(respTabs, f), "Set-Cookie") {
		t.Error("cookie tabs with cookies")
	}
	if answeredBy(f) != "" {
		t.Error("a server's answer named a tool")
	}
	f.ToolMetadata = map[string]any{"mapLocal": map[string]any{"name": "x"}}
	if answeredBy(f) != "Map Local" {
		t.Errorf("answeredBy %q", answeredBy(f))
	}
}
