package app

import (
	"path/filepath"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"

	"proxygo/internal/codegen"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
)

type menuItems struct {
	pause, sidebar, detail, detailRight, autoSelect, stayOnTop, noCaching, systemProxy *mygo.MenuItem
	recent                                                                             *mygo.MenuItem
	tools                                                                              map[string]*mygo.MenuItem
	appearance                                                                         map[string]*mygo.MenuItem
}

func (a *App) on(fn func()) func(*mygo.MenuItem, *mygo.Window) {
	return func(*mygo.MenuItem, *mygo.Window) { a.do(fn) }
}

func (a *App) installMenu() {
	m := &a.menu
	m.tools = map[string]*mygo.MenuItem{}
	check := func(label, accel string, on bool, fn func(bool)) *mygo.MenuItem {
		return &mygo.MenuItem{Label: label, Type: mygo.MenuItemCheckbox, Checked: on, Accelerator: accel,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) {
				on := it.IsChecked()
				a.do(func() { fn(on) })
			}}
	}
	m.appearance = map[string]*mygo.MenuItem{}
	appearance := func(label, v string) *mygo.MenuItem {
		it := &mygo.MenuItem{Label: label, Type: mygo.MenuItemRadio, Checked: a.appearanceIs(v),
			Click: a.on(func() { a.setAppearance(v) })}
		m.appearance[v] = it
		return it
	}
	m.pause = check("Pause Recording", "CmdOrCtrl+Shift+R", a.paused, a.setPaused)
	m.sidebar = check("Show Sidebar", "CmdOrCtrl+Alt+S", a.set.ShowSidebar, a.setSidebar)
	m.detail = check("Show Inspector", "CmdOrCtrl+Alt+I", a.set.ShowDetail, a.setDetail)
	m.detailRight = check("Dock Inspector to the Right", "", a.set.DetailRight, a.setDetailRight)
	m.autoSelect = check("Auto Select the Latest Request", "", a.set.AutoSelect, func(on bool) {
		a.updateSettings(func(s *settings.Settings) { s.AutoSelect = on })
	})
	m.stayOnTop = check("Stay on Top", "", a.set.StayOnTop, a.setStayOnTop)
	m.noCaching = check("No Caching", "", a.rules.Current().NoCaching, a.setNoCaching)
	m.systemProxy = check("Override macOS Proxy", "", a.systemProxyOn(), a.setSystemProxy)
	m.recent = &mygo.MenuItem{Label: "Open Recent", Submenu: a.recentItems()}

	file := &mygo.MenuItem{Label: "File", Submenu: []*mygo.MenuItem{
		{Label: "New Session", Accelerator: "CmdOrCtrl+N", Click: a.on(a.newSession)},
		{Label: "Open…", Accelerator: "CmdOrCtrl+O", Click: a.on(func() { a.openSessionDialog(false) })},
		{Label: "Open in New Window…", Accelerator: "CmdOrCtrl+Alt+O", Click: a.on(a.openSessionWindowDialog)},
		m.recent,
		{Label: "Import…", Accelerator: "CmdOrCtrl+Shift+O", Click: a.on(func() { a.openSessionDialog(true) })},
		mygo.Separator(),
		{Label: "Save Session", Accelerator: "CmdOrCtrl+S", Click: func(_ *mygo.MenuItem, win *mygo.Window) {
			a.do(func() {
				if win != nil && win == a.windows["scripting"] {
					a.saveOpenScript()
					return
				}
				a.saveSession()
			})
		}},
		{Label: "Save Session As…", Accelerator: "CmdOrCtrl+Shift+S", Click: a.on(func() { a.saveSessionDialog(false) })},
		{Label: "Export", Submenu: a.exportItems(false)},
		mygo.Separator(),
		{Role: mygo.RoleClose},
	}}

	edit := &mygo.MenuItem{Label: "Edit", Submenu: []*mygo.MenuItem{
		{Role: mygo.RoleUndo}, {Role: mygo.RoleRedo}, mygo.Separator(),
		{Role: mygo.RoleCut}, {Role: mygo.RoleCopy}, {Role: mygo.RolePaste}, {Role: mygo.RoleSelectAll},
		mygo.Separator(),
		{Label: "Copy URL", Accelerator: "CmdOrCtrl+Shift+U", Click: a.on(func() { a.copyURLs(a.chosenFlows()) })},
		{Label: "Copy as cURL", Accelerator: "CmdOrCtrl+Shift+C", Click: a.on(func() { a.copyCode(a.chosenFlows(), "cURL") })},
		{Label: "Copy as Code", Submenu: a.codeItems()},
		mygo.Separator(),
		{Label: "Filter…", Accelerator: "CmdOrCtrl+F", Click: a.on(a.focusFilter)},
		{Label: "Advanced Filter", Accelerator: "CmdOrCtrl+Alt+F", Click: a.on(func() { a.setAdvanced(!a.advanced) })},
	}}

	view := &mygo.MenuItem{Label: "View", Submenu: []*mygo.MenuItem{
		{Label: "Command Palette…", Accelerator: "CmdOrCtrl+Shift+P", Click: a.on(a.openPalette)},
		mygo.Separator(),
		m.sidebar, m.detail, m.detailRight,
		{Label: "Overview", Accelerator: "CmdOrCtrl+0", Click: a.on(func() { a.section = "overview" })},
		mygo.Separator(),
		m.autoSelect,
		{Label: "Appearance", Submenu: []*mygo.MenuItem{
			appearance("System", settings.AppearanceSystem),
			appearance("Light", settings.AppearanceLight),
			appearance("Dark", settings.AppearanceDark),
		}},
		mygo.Separator(),
		{Role: mygo.RoleToggleFullScreen},
	}}

	flowMenu := &mygo.MenuItem{Label: "Flow", Submenu: []*mygo.MenuItem{
		{Label: "Repeat", Accelerator: "CmdOrCtrl+R", Click: a.on(func() { a.repeatFlows(a.chosenFlows()) })},
		{Label: "Edit and Repeat…", Accelerator: "CmdOrCtrl+E", Click: a.on(func() { a.composeFrom(a.selectedFlow()) })},
		{Label: "Advanced Repeat…", Accelerator: "CmdOrCtrl+Alt+R", Click: a.on(func() { a.advancedRepeat(a.chosenFlows()) })},
		{Label: "Compose New Request…", Accelerator: "CmdOrCtrl+Shift+N", Click: a.on(func() { a.composeFrom(nil) })},
		mygo.Separator(),
		{Label: "Enable SSL Proxying for This Domain", Click: a.on(func() {
			if f := a.selectedFlow(); f != nil {
				a.enableSSL(f.Host(), false)
			}
		})},
		mygo.Separator(),
		{Label: "Add Comment…", Accelerator: "CmdOrCtrl+Shift+M", Click: a.on(func() { a.editComment(a.chosenFlows()) })},
		{Label: "Highlight", Submenu: a.highlightItems()},
		{Label: "Save Request", Accelerator: "CmdOrCtrl+D", Click: a.on(func() {
			fs := a.chosenFlows()
			if len(fs) > 0 {
				a.setSaved(fs, !fs[0].Saved)
			}
		})},
		mygo.Separator(),
		{Label: "Compare (Diff)", Accelerator: "CmdOrCtrl+Shift+D", Click: a.on(a.compareChosen)},
		{Label: "Export Selected", Submenu: a.exportItems(true)},
		{Label: "Save to Folder…", Accelerator: "CmdOrCtrl+Alt+D", Click: a.on(func() { a.saveToFolder(a.chosenFlows()) })},
		mygo.Separator(),
		{Label: "Delete", Accelerator: "CmdOrCtrl+Backspace", Click: a.on(func() { a.deleteFlows(a.chosenFlows()) })},
		{Label: "Clear Session", Accelerator: "CmdOrCtrl+K", Click: a.on(a.clearFlows)},
	}}

	toolItems := []*mygo.MenuItem{
		m.pause,
		mygo.Separator(),
		{Label: "SSL Proxying List…", Accelerator: "CmdOrCtrl+Alt+P", Click: a.on(func() { a.openWindow("ssl") })},
		{Label: "Compose…", Click: a.on(func() { a.composeFrom(nil) })},
		mygo.Separator(),
		{Label: "Breakpoint Rules…", Accelerator: "CmdOrCtrl+Alt+B", Click: a.on(func() { a.openWindow("breakpoint") })},
		{Label: "Breakpoint Templates…", Click: a.on(func() { a.openWindow("bptemplates") })},
		{Label: "Map Local…", Accelerator: "CmdOrCtrl+Alt+L", Click: a.on(func() { a.openWindow("maplocal") })},
		{Label: "Map Remote…", Accelerator: "CmdOrCtrl+Alt+M", Click: a.on(func() { a.openWindow("mapremote") })},
		{Label: "Scripting…", Accelerator: "CmdOrCtrl+Alt+J", Click: a.on(func() { a.openWindow("scripting") })},
		{Label: "Block List…", Click: a.on(func() { a.openWindow("block") })},
		{Label: "Blocked Apps…", Click: a.on(func() { a.openWindow("blockedapps") })},
		{Label: "Allow List…", Click: a.on(func() { a.openWindow("allow") })},
		{Label: "Network Conditions…", Accelerator: "CmdOrCtrl+Alt+N", Click: a.on(func() { a.openWindow("network") })},
		{Label: "DNS Spoofing…", Click: a.on(func() { a.openWindow("dns") })},
		{Label: "Reverse Proxy…", Click: a.on(func() { a.openWindow("reverse") })},
		{Label: "Client Certificates…", Click: a.on(func() { a.openWindow("clientcerts") })},
		{Label: "Protobuf…", Click: a.on(func() { a.openWindow("protobuf") })},
		mygo.Separator(),
		m.noCaching,
	}
	var switches []*mygo.MenuItem
	for _, t := range rules.AllTools {
		it := check(t.Name, "", a.toolOn(t.ID), func(on bool) { a.setTool(t.ID, on) })
		m.tools[t.ID] = it
		switches = append(switches, it)
	}
	toolItems = append(toolItems,
		&mygo.MenuItem{Label: "Enable / Disable Tools", Submenu: switches},
		mygo.Separator(),
		m.systemProxy,
		&mygo.MenuItem{Label: "Proxy Settings…", Click: a.on(func() { a.settingsTab = 1; a.openWindow("settings") })},
		&mygo.MenuItem{Label: "Import / Export Settings", Submenu: []*mygo.MenuItem{
			{Label: "Export…", Click: a.on(a.exportRules)},
			{Label: "Import…", Click: a.on(a.importRules)},
		}},
	)
	tools := &mygo.MenuItem{Label: "Tools", Submenu: toolItems}

	certificate := &mygo.MenuItem{Label: "Certificate", Submenu: []*mygo.MenuItem{
		{Label: "Install Certificate on this Mac…", Click: a.on(a.installCertificate)},
		{Label: "Install Certificate on iOS…", Click: a.on(func() { a.certTab = 1; a.openWindow("certificate") })},
		{Label: "Install Certificate on Android…", Click: a.on(func() { a.certTab = 3; a.openWindow("certificate") })},
		{Label: "Install Certificate on Other Platforms…", Click: a.on(func() { a.certTab = 5; a.openWindow("certificate") })},
		{Label: "Automatic Setup…", Click: a.on(func() { a.openWindow("setup") })},
		mygo.Separator(),
		{Label: "Export", Submenu: []*mygo.MenuItem{
			{Label: "Root Certificate as PEM…", Click: a.on(func() { a.exportCertificate("pem") })},
			{Label: "Root Certificate as DER…", Click: a.on(func() { a.exportCertificate("der") })},
			{Label: "Root Certificate as P12…", Click: a.on(func() { a.exportCertificate("p12") })},
			{Label: "Private Key…", Click: a.on(func() { a.exportCertificate("key") })},
		}},
		{Label: "Use Your Own Root Certificate…", Click: a.on(func() { a.rootImport = rootImport{open: true}; a.certTab = 0; a.openWindow("certificate") })},
		{Label: "Custom Server Certificates…", Click: a.on(func() { a.openWindow("servercerts") })},
		{Label: "Reset Certificate…", Click: a.on(a.regenerateCertificate)},
		mygo.Separator(),
		{Label: "Certificate Details…", Click: a.on(func() { a.certTab = 0; a.openWindow("certificate") })},
	}}

	window := &mygo.MenuItem{Label: "Window", Role: mygo.RoleWindow, Submenu: []*mygo.MenuItem{
		m.stayOnTop,
		mygo.Separator(),
		{Role: mygo.RoleMinimize}, {Role: mygo.RoleZoom},
	}}
	help := &mygo.MenuItem{Label: "Help", Submenu: []*mygo.MenuItem{
		{Label: "Getting Started", Click: a.on(func() { a.openWindow("help") })},
		{Label: "Keyboard Shortcuts", Click: a.on(func() { a.openWindow("help") })},
		mygo.Separator(),
		{Label: "Open Data Folder", Click: a.on(func() { openPath(a.dir) })},
		{Label: "Reset Network Proxy", Click: a.on(a.resetSystemProxy)},
	}}
	appMenu := &mygo.MenuItem{Label: "ProxyGo", Submenu: []*mygo.MenuItem{
		{Role: mygo.RoleAbout},
		updater.MenuItem(),
		mygo.Separator(),
		{Label: "Settings…", Accelerator: "CmdOrCtrl+,", Click: a.on(func() { a.openWindow("settings") })},
		mygo.Separator(),
		{Role: mygo.RoleServices}, mygo.Separator(),
		{Role: mygo.RoleHide}, {Role: mygo.RoleHideOthers}, {Role: mygo.RoleUnhide},
		mygo.Separator(),
		{Role: mygo.RoleQuit},
	}}
	mygo.App.SetMenu(mygo.NewMenu([]*mygo.MenuItem{appMenu, file, edit, view, flowMenu, tools, certificate, window, help}))
}

func (a *App) exportItems(selection bool) []*mygo.MenuItem {
	har := &mygo.MenuItem{Label: "as HAR (HTTP Archive)…", Click: a.on(func() { a.exportDialog("har", selection) })}
	if !selection {
		har.Accelerator = "CmdOrCtrl+Shift+E"
	}
	return []*mygo.MenuItem{
		{Label: "as ProxyGo Session…", Click: a.on(func() { a.saveSessionDialog(selection) })},
		har,
		{Label: "as CSV…", Click: a.on(func() { a.exportDialog("csv", selection) })},
		{Label: "as Postman Collection…", Click: a.on(func() { a.exportDialog("postman", selection) })},
		{Label: "as OpenAPI (YAML)…", Click: a.on(func() { a.exportDialog("openapi", selection) })},
		{Label: "as OpenAPI (HTML)…", Click: a.on(func() { a.exportDialog("openapi-html", selection) })},
		{Label: "as Raw HTTP…", Click: a.on(func() { a.exportDialog("raw", selection) })},
	}
}

func (a *App) codeItems() []*mygo.MenuItem {
	var items []*mygo.MenuItem
	for _, l := range codegen.Languages {
		items = append(items, &mygo.MenuItem{Label: l.Name, Click: a.on(func() { a.copyCode(a.chosenFlows(), l.Name) })})
	}
	return append(items, mygo.Separator(), &mygo.MenuItem{Label: "Markdown", Click: a.on(func() { a.copyMarkdown(a.chosenFlows()) })})
}

func (a *App) highlightItems() []*mygo.MenuItem {
	var items []*mygo.MenuItem
	for _, color := range highlightColors {
		items = append(items, &mygo.MenuItem{Label: title(color), Click: a.on(func() { a.setHighlight(a.chosenFlows(), color) })})
	}
	return append(items,
		mygo.Separator(),
		&mygo.MenuItem{Label: "Strikethrough", Click: a.on(func() {
			fs := a.chosenFlows()
			if len(fs) > 0 {
				a.setStrike(fs, !fs[0].Strikethrough)
			}
		})},
		&mygo.MenuItem{Label: "Reset", Click: a.on(func() { a.resetStyle(a.chosenFlows()) })},
	)
}

func (a *App) recentItems() []*mygo.MenuItem {
	var items []*mygo.MenuItem
	for _, p := range a.set.RecentSessions {
		items = append(items, &mygo.MenuItem{Label: filepath.Base(p), ToolTip: p, Click: func(*mygo.MenuItem, *mygo.Window) { go a.openPath(p, false) }})
	}
	if len(items) == 0 {
		items = append(items, &mygo.MenuItem{Label: "No Recent Sessions", Disabled: true})
	}
	return append(items, mygo.Separator(), &mygo.MenuItem{Label: "Clear Menu", Click: a.on(func() {
		a.updateSettings(func(s *settings.Settings) { s.RecentSessions = nil })
		a.refreshRecentMenu()
	})})
}

func (a *App) refreshRecentMenu() {
	if a.win != nil {
		a.installMenu()
	}
}

func (a *App) syncMenu() {
	m := a.menu
	if m.pause == nil {
		return
	}
	set := func(it *mygo.MenuItem, on bool) {
		if it.IsChecked() != on {
			it.SetChecked(on)
		}
	}
	set(m.pause, a.paused)
	set(m.sidebar, a.set.ShowSidebar)
	set(m.detail, a.set.ShowDetail)
	set(m.detailRight, a.set.DetailRight)
	set(m.autoSelect, a.set.AutoSelect)
	set(m.stayOnTop, a.set.StayOnTop)
	set(m.systemProxy, a.systemProxyOn())
	d := a.rules.Current()
	set(m.noCaching, d.NoCaching)
	for id, it := range m.tools {
		set(it, d.ToolOn(id))
	}
	for v, it := range m.appearance {
		set(it, a.appearanceIs(v))
	}
	a.syncTray()
}

func (a *App) setSidebar(on bool) {
	a.updateSettings(func(s *settings.Settings) { s.ShowSidebar = on })
}

func (a *App) setDetail(on bool) {
	a.updateSettings(func(s *settings.Settings) { s.ShowDetail = on })
}

func (a *App) setDetailRight(on bool) {
	a.updateSettings(func(s *settings.Settings) { s.DetailRight, s.ShowDetail = on, true })
}

func (a *App) setStayOnTop(on bool) {
	a.updateSettings(func(s *settings.Settings) { s.StayOnTop = on })
	if a.win != nil {
		a.win.SetAlwaysOnTop(on)
	}
	for _, w := range a.windows {
		w.SetAlwaysOnTop(on)
	}
}

func (a *App) appearanceIs(v string) bool {
	cur := a.set.Appearance
	if cur != settings.AppearanceLight && cur != settings.AppearanceDark {
		cur = settings.AppearanceSystem
	}
	return cur == v
}

func (a *App) setAppearance(v string) {
	a.updateSettings(func(s *settings.Settings) { s.Appearance = v })
	if a.win != nil {
		mygo.Theme.SetSource(themeSource(v))
	}
	a.invalidate()
}

func themeSource(v string) mygo.ThemeSource {
	switch v {
	case settings.AppearanceLight:
		return mygo.ThemeLight
	case settings.AppearanceDark:
		return mygo.ThemeDark
	}
	return mygo.ThemeSystem
}

func (a *App) newSession() {
	if a.store.Len() > 0 && a.sessionPath == "" {
		a.saveAutosave()
	}
	a.clearFlows()
	if a.win != nil {
		a.win.SetTitle("ProxyGo")
	}
	a.toast("New session")
}
