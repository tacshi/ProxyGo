package app

import (
	"path/filepath"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"

	"proxygo/internal/codegen"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/locales"
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
	m.pause = check(locales.PauseRecording(), "CmdOrCtrl+Shift+R", a.paused, a.setPaused)
	m.sidebar = check(locales.ShowSidebar(), "CmdOrCtrl+Alt+S", a.set.ShowSidebar, a.setSidebar)
	m.detail = check(locales.ShowInspector(), "CmdOrCtrl+Alt+I", a.set.ShowDetail, a.setDetail)
	m.detailRight = check(locales.DockInspectorToTheRight(), "", a.set.DetailRight, a.setDetailRight)
	m.autoSelect = check(locales.AutoSelectTheLatestRequest(), "", a.set.AutoSelect, func(on bool) {
		a.updateSettings(func(s *settings.Settings) { s.AutoSelect = on })
	})
	m.stayOnTop = check(locales.StayOnTop(), "", a.set.StayOnTop, a.setStayOnTop)
	m.noCaching = check(locales.NoCaching(), "", a.rules.Current().NoCaching, a.setNoCaching)
	m.systemProxy = check(locales.OverrideMacOSProxy(), "", a.systemProxyOn(), a.setSystemProxy)
	m.recent = &mygo.MenuItem{Label: locales.OpenRecent(), Submenu: a.recentItems()}

	file := &mygo.MenuItem{Label: locales.File(), Submenu: []*mygo.MenuItem{
		{Label: locales.NewSession(), Accelerator: "CmdOrCtrl+N", Click: a.on(a.newSession)},
		{Label: locales.OpenEllipsis(), Accelerator: "CmdOrCtrl+O", Click: a.on(func() { a.openSessionDialog(false) })},
		{Label: locales.OpenInNewWindowEllipsis(), Accelerator: "CmdOrCtrl+Alt+O", Click: a.on(a.openSessionWindowDialog)},
		m.recent,
		{Label: locales.ImportEllipsis(), Accelerator: "CmdOrCtrl+Shift+O", Click: a.on(func() { a.openSessionDialog(true) })},
		mygo.Separator(),
		{Label: locales.SaveSession(), Accelerator: "CmdOrCtrl+S", Click: func(_ *mygo.MenuItem, win *mygo.Window) {
			a.do(func() {
				if win != nil && win == a.windows["scripting"] {
					a.saveOpenScript()
					return
				}
				a.saveSession()
			})
		}},
		{Label: locales.SaveSessionAsEllipsis(), Accelerator: "CmdOrCtrl+Shift+S", Click: a.on(func() { a.saveSessionDialog(false) })},
		{Label: locales.Export(), Submenu: a.exportItems(false)},
		mygo.Separator(),
		{Role: mygo.RoleClose},
	}}

	edit := &mygo.MenuItem{Label: locales.Edit(), Submenu: []*mygo.MenuItem{
		{Role: mygo.RoleUndo}, {Role: mygo.RoleRedo}, mygo.Separator(),
		{Role: mygo.RoleCut}, {Role: mygo.RoleCopy}, {Role: mygo.RolePaste}, {Role: mygo.RoleSelectAll},
		mygo.Separator(),
		{Label: locales.CopyURL(), Accelerator: "CmdOrCtrl+Shift+U", Click: a.on(func() { a.copyURLs(a.chosenFlows()) })},
		{Label: locales.CopyAsCURL(), Accelerator: "CmdOrCtrl+Shift+C", Click: a.on(func() { a.copyCode(a.chosenFlows(), "cURL") })},
		{Label: locales.CopyAsCode(), Submenu: a.codeItems()},
		mygo.Separator(),
		{Label: locales.FilterEllipsis(), Accelerator: "CmdOrCtrl+F", Click: a.on(a.focusFilter)},
		{Label: locales.AdvancedFilter(), Accelerator: "CmdOrCtrl+Alt+F", Click: a.on(func() { a.setAdvanced(!a.advanced) })},
	}}

	view := &mygo.MenuItem{Label: locales.View(), Submenu: []*mygo.MenuItem{
		{Label: locales.CommandPaletteEllipsis(), Accelerator: "CmdOrCtrl+Shift+P", Click: a.on(a.openPalette)},
		mygo.Separator(),
		m.sidebar, m.detail, m.detailRight,
		{Label: locales.Overview(), Accelerator: "CmdOrCtrl+0", Click: a.on(func() { a.section = "overview" })},
		mygo.Separator(),
		m.autoSelect,
		{Label: locales.Appearance(), Submenu: []*mygo.MenuItem{
			appearance(locales.System(), settings.AppearanceSystem),
			appearance(locales.Light(), settings.AppearanceLight),
			appearance(locales.Dark(), settings.AppearanceDark),
		}},
		mygo.Separator(),
		{Role: mygo.RoleToggleFullScreen},
	}}

	flowMenu := &mygo.MenuItem{Label: locales.Flow(), Submenu: []*mygo.MenuItem{
		{Label: locales.Repeat(), Accelerator: "CmdOrCtrl+R", Click: a.on(func() { a.repeatFlows(a.chosenFlows()) })},
		{Label: locales.EditAndRepeatEllipsis(), Accelerator: "CmdOrCtrl+E", Click: a.on(func() { a.composeFrom(a.selectedFlow()) })},
		{Label: locales.AdvancedRepeatEllipsis(), Accelerator: "CmdOrCtrl+Alt+R", Click: a.on(func() { a.advancedRepeat(a.chosenFlows()) })},
		{Label: locales.ComposeNewRequestEllipsis(), Accelerator: "CmdOrCtrl+Shift+N", Click: a.on(func() { a.composeFrom(nil) })},
		mygo.Separator(),
		{Label: locales.EnableSSLProxyingForThisDomain(), Click: a.on(func() {
			if f := a.selectedFlow(); f != nil {
				a.enableSSL(f.Host(), false)
			}
		})},
		mygo.Separator(),
		{Label: locales.AddCommentEllipsis(), Accelerator: "CmdOrCtrl+Shift+M", Click: a.on(func() { a.editComment(a.chosenFlows()) })},
		{Label: locales.Highlight(), Submenu: a.highlightItems()},
		{Label: locales.SaveRequest(), Accelerator: "CmdOrCtrl+D", Click: a.on(func() {
			fs := a.chosenFlows()
			if len(fs) > 0 {
				a.setSaved(fs, !fs[0].Saved)
			}
		})},
		mygo.Separator(),
		{Label: locales.CompareDiff(), Accelerator: "CmdOrCtrl+Shift+D", Click: a.on(a.compareChosen)},
		{Label: locales.ExportSelected(), Submenu: a.exportItems(true)},
		{Label: locales.SaveToFolderEllipsis(), Accelerator: "CmdOrCtrl+Alt+D", Click: a.on(func() { a.saveToFolder(a.chosenFlows()) })},
		mygo.Separator(),
		{Label: locales.Delete(), Accelerator: "CmdOrCtrl+Backspace", Click: a.on(func() { a.deleteFlows(a.chosenFlows()) })},
		{Label: locales.ClearSession(), Accelerator: "CmdOrCtrl+K", Click: a.on(a.clearFlows)},
	}}

	toolItems := []*mygo.MenuItem{
		m.pause,
		mygo.Separator(),
		{Label: locales.SSLProxyingListEllipsis(), Accelerator: "CmdOrCtrl+Alt+P", Click: a.on(func() { a.openWindow("ssl") })},
		{Label: locales.ComposeEllipsis(), Click: a.on(func() { a.composeFrom(nil) })},
		mygo.Separator(),
		{Label: locales.BreakpointRulesEllipsis(), Accelerator: "CmdOrCtrl+Alt+B", Click: a.on(func() { a.openWindow("breakpoint") })},
		{Label: locales.BreakpointTemplatesEllipsis(), Click: a.on(func() { a.openWindow("bptemplates") })},
		{Label: locales.MapLocalEllipsis(), Accelerator: "CmdOrCtrl+Alt+L", Click: a.on(func() { a.openWindow("maplocal") })},
		{Label: locales.MapRemoteEllipsis(), Accelerator: "CmdOrCtrl+Alt+M", Click: a.on(func() { a.openWindow("mapremote") })},
		{Label: locales.ScriptingEllipsis(), Accelerator: "CmdOrCtrl+Alt+J", Click: a.on(func() { a.openWindow("scripting") })},
		{Label: locales.BlockListEllipsis(), Click: a.on(func() { a.openWindow("block") })},
		{Label: locales.BlockedAppsEllipsis(), Click: a.on(func() { a.openWindow("blockedapps") })},
		{Label: locales.AllowListEllipsis(), Click: a.on(func() { a.openWindow("allow") })},
		{Label: locales.NetworkConditionsEllipsis(), Accelerator: "CmdOrCtrl+Alt+N", Click: a.on(func() { a.openWindow("network") })},
		{Label: locales.DNSSpoofingEllipsis(), Click: a.on(func() { a.openWindow("dns") })},
		{Label: locales.ReverseProxyEllipsis(), Click: a.on(func() { a.openWindow("reverse") })},
		{Label: locales.ClientCertificatesEllipsis(), Click: a.on(func() { a.openWindow("clientcerts") })},
		{Label: locales.ProtobufEllipsis(), Click: a.on(func() { a.openWindow("protobuf") })},
		mygo.Separator(),
		m.noCaching,
	}
	var switches []*mygo.MenuItem
	for _, t := range rules.AllTools {
		it := check(toolName(t.ID), "", a.toolOn(t.ID), func(on bool) { a.setTool(t.ID, on) })
		m.tools[t.ID] = it
		switches = append(switches, it)
	}
	toolItems = append(toolItems,
		&mygo.MenuItem{Label: locales.EnableDisableTools(), Submenu: switches},
		mygo.Separator(),
		m.systemProxy,
		&mygo.MenuItem{Label: locales.ProxySettingsEllipsis(), Click: a.on(func() { a.settingsTab = 1; a.openWindow("settings") })},
		&mygo.MenuItem{Label: locales.ImportExportSettings(), Submenu: []*mygo.MenuItem{
			{Label: locales.ExportEllipsis(), Click: a.on(a.exportRules)},
			{Label: locales.ImportEllipsis(), Click: a.on(a.importRules)},
		}},
	)
	tools := &mygo.MenuItem{Label: locales.Tools(), Submenu: toolItems}

	certificate := &mygo.MenuItem{Label: locales.Certificate(), Submenu: []*mygo.MenuItem{
		{Label: locales.InstallCertificateOnThisMacEllipsis(), Click: a.on(a.installCertificate)},
		{Label: locales.InstallCertificateOnIOSEllipsis(), Click: a.on(func() { a.certTab = 1; a.openWindow("certificate") })},
		{Label: locales.InstallCertificateOnAndroidEllipsis(), Click: a.on(func() { a.certTab = 3; a.openWindow("certificate") })},
		{Label: locales.InstallCertificateOnOtherPlatformsEllipsis(), Click: a.on(func() { a.certTab = 5; a.openWindow("certificate") })},
		{Label: locales.AutomaticSetupEllipsis(), Click: a.on(func() { a.openWindow("setup") })},
		mygo.Separator(),
		{Label: locales.Export(), Submenu: []*mygo.MenuItem{
			{Label: locales.RootCertificateAsPEMEllipsis(), Click: a.on(func() { a.exportCertificate("pem") })},
			{Label: locales.RootCertificateAsDEREllipsis(), Click: a.on(func() { a.exportCertificate("der") })},
			{Label: locales.RootCertificateAsP12Ellipsis(), Click: a.on(func() { a.exportCertificate("p12") })},
			{Label: locales.PrivateKeyEllipsis(), Click: a.on(func() { a.exportCertificate("key") })},
		}},
		{Label: locales.UseYourOwnRootCertificateEllipsis(), Click: a.on(func() { a.rootImport = rootImport{open: true}; a.certTab = 0; a.openWindow("certificate") })},
		{Label: locales.CustomServerCertificatesEllipsis(), Click: a.on(func() { a.openWindow("servercerts") })},
		{Label: locales.ResetCertificateEllipsis(), Click: a.on(a.regenerateCertificate)},
		mygo.Separator(),
		{Label: locales.CertificateDetailsEllipsis(), Click: a.on(func() { a.certTab = 0; a.openWindow("certificate") })},
	}}

	window := &mygo.MenuItem{Label: locales.Window(), Role: mygo.RoleWindow, Submenu: []*mygo.MenuItem{
		m.stayOnTop,
		mygo.Separator(),
		{Role: mygo.RoleMinimize}, {Role: mygo.RoleZoom},
	}}
	help := &mygo.MenuItem{Label: locales.Help(), Submenu: []*mygo.MenuItem{
		{Label: locales.GettingStarted(), Click: a.on(func() { a.openWindow("help") })},
		{Label: locales.KeyboardShortcuts(), Click: a.on(func() { a.openWindow("help") })},
		mygo.Separator(),
		{Label: locales.OpenDataFolder(), Click: a.on(func() { openPath(a.dir) })},
		{Label: locales.ResetNetworkProxy(), Click: a.on(a.resetSystemProxy)},
	}}
	appMenu := &mygo.MenuItem{Label: "ProxyGo", Submenu: []*mygo.MenuItem{
		{Role: mygo.RoleAbout},
		updater.MenuItem(),
		mygo.Separator(),
		{Label: locales.SettingsEllipsis(), Accelerator: "CmdOrCtrl+,", Click: a.on(func() { a.openWindow("settings") })},
		mygo.Separator(),
		{Role: mygo.RoleServices}, mygo.Separator(),
		{Role: mygo.RoleHide}, {Role: mygo.RoleHideOthers}, {Role: mygo.RoleUnhide},
		mygo.Separator(),
		{Role: mygo.RoleQuit},
	}}
	mygo.App.SetMenu(mygo.NewMenu([]*mygo.MenuItem{appMenu, file, edit, view, flowMenu, tools, certificate, window, help}))
}

func (a *App) exportItems(selection bool) []*mygo.MenuItem {
	har := &mygo.MenuItem{Label: locales.AsHARHTTPArchiveEllipsis(), Click: a.on(func() { a.exportDialog("har", selection) })}
	if !selection {
		har.Accelerator = "CmdOrCtrl+Shift+E"
	}
	return []*mygo.MenuItem{
		{Label: locales.AsProxyGoSessionEllipsis(), Click: a.on(func() { a.saveSessionDialog(selection) })},
		har,
		{Label: locales.AsCSVEllipsis(), Click: a.on(func() { a.exportDialog("csv", selection) })},
		{Label: locales.AsPostmanCollectionEllipsis(), Click: a.on(func() { a.exportDialog("postman", selection) })},
		{Label: locales.AsOpenAPIYAMLEllipsis(), Click: a.on(func() { a.exportDialog("openapi", selection) })},
		{Label: locales.AsOpenAPIHTMLEllipsis(), Click: a.on(func() { a.exportDialog("openapi-html", selection) })},
		{Label: locales.AsRawHTTPEllipsis(), Click: a.on(func() { a.exportDialog("raw", selection) })},
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
		items = append(items, &mygo.MenuItem{Label: colorName(color), Click: a.on(func() { a.setHighlight(a.chosenFlows(), color) })})
	}
	return append(items,
		mygo.Separator(),
		&mygo.MenuItem{Label: locales.Strikethrough(), Click: a.on(func() {
			fs := a.chosenFlows()
			if len(fs) > 0 {
				a.setStrike(fs, !fs[0].Strikethrough)
			}
		})},
		&mygo.MenuItem{Label: locales.Reset(), Click: a.on(func() { a.resetStyle(a.chosenFlows()) })},
	)
}

func (a *App) recentItems() []*mygo.MenuItem {
	var items []*mygo.MenuItem
	for _, p := range a.set.RecentSessions {
		items = append(items, &mygo.MenuItem{Label: filepath.Base(p), ToolTip: p, Click: func(*mygo.MenuItem, *mygo.Window) { go a.openPath(p, false) }})
	}
	if len(items) == 0 {
		items = append(items, &mygo.MenuItem{Label: locales.NoRecentSessions(), Disabled: true})
	}
	return append(items, mygo.Separator(), &mygo.MenuItem{Label: locales.ClearMenu(), Click: a.on(func() {
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
	a.toast(locales.NewSessionStarted())
}
