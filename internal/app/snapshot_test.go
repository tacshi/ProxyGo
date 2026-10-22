package app

import (
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/store"
)

func TestSnapshots(t *testing.T) {
	dir := os.Getenv("PROXYGO_SNAPSHOTS")
	if dir == "" {
		t.Skip("PROXYGO_SNAPSHOTS is not set")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	save := func(tt *ui.Tester, name string) {
		t.Helper()
		tt.Frame()
		f, err := os.Create(filepath.Join(dir, name+".png")) // #nosec G304 -- the snapshot directory PROXYGO_SNAPSHOTS names.
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := png.Encode(f, tt.Image()); err != nil {
			t.Fatal(err)
		}
	}

	a, tt, _ := loaded(t)
	save(tt, "main-none")
	for _, f := range a.store.Snapshot() {
		a.selectFlow(f.UniqueID)
		a.reqTabName, a.respTabName = "Header", "Header"
		save(tt, "main-"+f.UniqueID)
	}
	a.selectFlow("A1")
	for _, tab := range reqTabs {
		a.reqTabName, a.respTabName = tab, "Body"
		save(tt, "req-"+tab)
	}
	for _, tab := range respTabs {
		a.reqTabName, a.respTabName = "Header", tab
		save(tt, "resp-"+tab)
	}
	for _, id := range []string{"B22", "C333", "D4444", "I999999999", "J1010101010"} {
		a.selectFlow(id)
		a.reqTabName, a.respTabName = "Body", "Body"
		save(tt, "body-"+id)
	}
	a.selectFlow("G7777777")
	a.respTabName = "Messages"
	save(tt, "ws-messages")

	a.set.TableHeight = 640
	for _, id := range []string{"F666666", "E55555", "H88888888", "A1"} {
		a.selectFlow(id)
		a.reqTabName, a.respTabName = "Header", "Header"
		save(tt, "short-"+id)
	}
	a.set.TableHeight = 460

	a.sysKnown = true
	a.store.Update("H88888888", func(f *flow.Flow) { f.MarkIncomplete() })
	a.selectFlow("H88888888")
	a.reqTabName, a.respTabName = "Header", "Header"
	save(tt, "incomplete")
	a.sysKnown = false
	a.selectFlow("A1")

	a.set.ShowSidebar = false
	save(tt, "nosidebar")
	a.set.ShowSidebar, a.set.DetailRight = true, true
	save(tt, "detailright")
	a.set.DetailRight = false
	tt.SetSize(900, 560)
	save(tt, "small")
	tt.SetSize(1440, 900)
	a.advanced = true
	save(tt, "advanced")
	a.advanced = false
	a.editComment(a.chosenFlows())
	save(tt, "sheet-comment")
	a.comment.open = false
	a.advancedRepeat(a.chosenFlows())
	save(tt, "sheet-repeat")
	a.repeat.open = false
	a.openPalette()
	save(tt, "palette")
	a.palette.open = false
	a.section = "overview"
	save(tt, "overview")
	tt.SetSize(1440, 1500)
	save(tt, "overview-full")
	tt.SetSize(900, 1700)
	save(tt, "overview-narrow")
	tt.SetSize(1440, 900)
	a.section = "all"
	tt.SetDark(true)
	save(tt, "dark")
	a.section = "overview"
	save(tt, "dark-overview")
	a.section = "all"
	tt.SetDark(false)

	window := func(kind string, w, h int) *ui.Tester {
		return ui.NewTester(func(c *ui.Context) { a.toolWindow(c, kind) }, w, h)
	}
	for kind, k := range ruleKinds {
		spec := windowSpecs[kind]
		wt := window(kind, spec.width, spec.height)
		save(wt, "tool-"+kind)
		if err := wt.Click(k.add()); err != nil {
			t.Fatalf("%s add: %v", kind, err)
		}
		save(wt, "tool-"+kind+"-edit")
		wt.SetSize(560, 380)
		save(wt, "tool-"+kind+"-min")
	}
	a.compare(fixtures()[0], fixtures()[3])
	for _, kind := range []string{"ssl", "scripting", "compose", "diff", "help", "bpedit"} {
		spec := windowSpecs[kind]
		wt := window(kind, spec.width, spec.height)
		save(wt, "win-"+kind)
		wt.SetSize(560, 380)
		save(wt, "win-"+kind+"-min")
	}
	st := window("scripting", windowSpecs["scripting"].width, windowSpecs["scripting"].height)
	st.Frame()
	if err := st.Click("New Script"); err == nil {
		save(st, "win-scripting-script")
	}
	for i, name := range settingsTabs {
		a.settingsTab = i
		spec := windowSpecs["settings"]
		save(window("settings", spec.width, spec.height), "settings-"+name)
	}
	for i, name := range certTabs {
		a.certTab = i
		spec := windowSpecs["certificate"]
		save(window("certificate", spec.width, spec.height), "cert-"+name)
	}
}

func TestSnapshotsInspector(t *testing.T) {
	dir := os.Getenv("PROXYGO_SNAPSHOTS")
	if dir == "" {
		t.Skip("PROXYGO_SNAPSHOTS is not set")
	}
	save := func(tt *ui.Tester, name string) {
		t.Helper()
		tt.Frame()
		f, err := os.Create(filepath.Join(dir, name+".png")) // #nosec G304 -- the snapshot directory PROXYGO_SNAPSHOTS names.
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		_ = png.Encode(f, tt.Image())
	}
	a, tt, _ := loaded(t)
	for _, f := range inspectorFixtures() {
		a.store.Upsert(f)
	}
	tt.Frame()
	a.selectFlow("K1")
	a.reqTabName, a.respTabName = "JWT", "TLS"
	save(tt, "insp-jwt-tls")
	a.selectFlow("L2")
	a.reqTabName, a.respTabName = "Header", "Body"
	save(tt, "insp-sse")
	a.selectFlow("M3")
	save(tt, "insp-msgpack")
	a.selectFlow("A1")
	a.jsonQueryOf("res").expr = ".users[].name"
	save(tt, "insp-jsonfilter")
	a.jsonQueryOf("res").expr = ""
	a.selectFlow("G7777777")
	a.respTabName = "Messages"
	a.ws.showPings = true
	save(tt, "insp-ws")
	tt.SetDark(true)
	a.selectFlow("K1")
	a.reqTabName, a.respTabName = "JWT", "TLS"
	save(tt, "insp-jwt-tls-dark")
}

func TestSnapshotsTools(t *testing.T) {
	dir := os.Getenv("PROXYGO_SNAPSHOTS")
	if dir == "" {
		t.Skip("PROXYGO_SNAPSHOTS is not set")
	}
	save := func(tt *ui.Tester, name string) {
		t.Helper()
		tt.Frame()
		tt.Frame()
		f, err := os.Create(filepath.Join(dir, name+".png")) // #nosec G304 -- the snapshot directory PROXYGO_SNAPSHOTS names.
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		_ = png.Encode(f, tt.Image())
	}
	a, tt, _ := loaded(t)
	window := func(kind string) *ui.Tester {
		spec := windowSpecs[kind]
		return ui.NewTester(func(c *ui.Context) { a.toolWindow(c, kind) }, spec.width, spec.height)
	}

	a.composeTemplate("POST with Multipart")
	a.compose.edit.parts[1].fileName, a.compose.edit.parts[1].contentType, a.compose.edit.parts[1].data = "avatar.png", "image/png", pngBytes()
	ct := window("compose")
	save(ct, "compose-multipart")
	a.composeTemplate("POST with Form")
	save(ct, "compose-form")
	a.openCurlSheet()
	a.compose.curl.text.Buffer.Set("curl -X POST https://api.example.com/v1/items \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"name\":\"ProxyGo\"}'")
	save(ct, "compose-curl")
	a.compose.curl.open = false
	a.composeTemplate("WebSocket")
	save(ct, "compose-websocket")
	ct.SetDark(true)
	a.composeTemplate("POST with Multipart")
	save(ct, "compose-multipart-dark")

	f := flow.New("P9")
	f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, FullPath: "https://api.example.com/v1/users"}
	m := proxy.Message{Method: "GET", URL: "https://api.example.com/v1/users"}
	pd := &pending{Pause: &proxy.Pause{ID: "pause9", Rule: "users", Flow: f, Message: m}, done: make(chan decision, 1), at: time.Now()}
	pd.edit = newMessageEditor(m, false)
	a.pauses = []*pending{pd}
	bt := window("bpedit")
	save(bt, "bpedit-paused")
	a.tplSave = templateSheet{open: true, pause: pd.ID, name: "Users"}
	save(bt, "bpedit-save-template")
	a.tplSave.open = false

	save(window("setup"), "win-setup")
	for _, tab := range []int{2, 4, 5} {
		a.certTab = tab
		ctt := window("certificate")
		ctt.Frame()
		time.Sleep(100 * time.Millisecond)
		a.runQueued()
		save(ctt, "cert-install-"+certTabs[tab])
	}
	a.rootImport = rootImport{open: true, certPath: a.certs.CertPath()}
	save(window("certificate"), "cert-root-import")
	a.rootImport.open = false

	a.rules.Update(func(d *rules.Data) {
		d.MapLocal = append(d.MapLocal,
			&rules.MapLocalRule{ID: "m1", Enabled: true, Name: "Users", Matcher: rules.Matcher{URL: "https://api.example.com/v1/users"}, Folder: "API/v1", StatusCode: 200},
			&rules.MapLocalRule{ID: "m2", Enabled: true, Name: "Avatar", Matcher: rules.Matcher{URL: "https://cdn.example.com/*"}, Path: "/tmp/avatar.png"})
	})
	save(window("maplocal"), "tool-maplocal-folders")
	st := a.toolState("servercerts")
	a.beginEdit("servercerts", st, &rules.ServerCertificate{ID: "s1", Enabled: true, Hosts: []string{"api.example.com"}, CertPath: a.certs.CertPath()}, true)
	save(window("servercerts"), "tool-servercerts-pem")
	st.tab = 1
	save(window("servercerts"), "tool-servercerts-p12")
	st.editing = false

	for i, host := range []string{"dns.weixin.qq.com", "sgshort.wechat.com"} {
		f := flow.New(fmt.Sprintf("R%d", i))
		f.Request = &flow.Request{Method: flow.Method{Name: "POST"}, Host: host, Scheme: "http", FullPath: "http://" + host + "/mmtls/1"}
		f.Response = &flow.Response{Status: &flow.Status{Code: 200, Phrase: "OK"}}
		f.Client = flow.Client{Name: "192.168.1.7", PID: -1}
		a.store.Upsert(f)
	}
	a.setDeviceName("192.168.1.7", "Rocky's iPhone")
	a.selectFlow("R0")
	a.reqTabName, a.respTabName = "Summary", "Header"
	save(tt, "main-remote-device")
	a.reqTabName = "Header"

	if _, err := a.folders.Add("API/Errors", a.store.Snapshot()[:2], nil); err != nil {
		t.Fatal(err)
	}
	a.set.FilterPresets = []store.Preset{{ID: "p1", Name: "Errors", Conditions: []store.Condition{{Enabled: true, Field: store.FieldStatus, Op: store.OpContains, Value: "5"}}}}
	a.advanced = true
	a.conditions = []store.Condition{{Enabled: true, Field: store.FieldResponseJQ, Op: store.OpEquals, Key: ".users[0].name", Value: "Ada"}}
	save(tt, "main-folders-filters")
	a.presetSave = presetSheet{open: true, name: "Ada"}
	save(tt, "sheet-save-filter")
	a.presetSave.open = false
	a.advanced, a.conditions = false, nil
	a.addToDiffPool(a.store.Snapshot()[:3])
	save(window("diff"), "win-diff-pool")

	a.rules.Update(func(d *rules.Data) {
		d.Access = rules.AccessControl{Mode: rules.AccessAsk, IPs: []string{"192.168.1.7"}}
	})
	a.settingsTab = 0
	save(window("settings"), "settings-general-menubar")
	a.settingsTab = 1
	st2 := window("settings")
	st2.Frame()
	save(st2, "settings-proxy-ask")
}
