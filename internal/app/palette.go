package app

import (
	"strings"

	"github.com/egoist/mygo/plugins/updater"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/codegen"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/internal/store"
	"proxygo/locales"
)

type paletteState struct {
	open  bool
	query string
	row   int
	list  ui.ListState
}

type command struct {
	group, name, keys string
	run               func()
}

func (a *App) openPalette() {
	a.palette = paletteState{open: true}
}

func (a *App) commands() []command {
	var out []command
	add := func(group, name, keys string, run func()) {
		out = append(out, command{group, name, keys, run})
	}
	flowGroup, sessionGroup, recordingGroup, toolsGroup := locales.GroupFlow(), locales.GroupSession(), locales.GroupRecording(), locales.GroupTools()
	viewGroup, certGroup, settingsGroup := locales.GroupView(), locales.GroupCertificate(), locales.GroupSettings()
	if fs := a.chosenFlows(); len(fs) > 0 {
		f := fs[0]
		add(flowGroup, locales.Repeat(), "⌘R", func() { a.repeatFlows(fs) })
		add(flowGroup, locales.EditAndRepeat(), "⌘E", func() { a.composeFrom(f) })
		add(flowGroup, locales.AdvancedRepeat(), "⌥⌘R", func() { a.advancedRepeat(fs) })
		add(flowGroup, locales.CopyURL(), "⇧⌘U", func() { a.copyURLs(fs) })
		for _, l := range codegen.Languages {
			add(flowGroup, locales.CopyAsFormat(l.Name), "", func() { a.copyCode(fs, l.Name) })
		}
		add(flowGroup, locales.AddComment(), "⇧⌘M", func() { a.editComment(fs) })
		add(flowGroup, locales.SaveRequest(), "⌘D", func() { a.setSaved(fs, !f.Saved) })
		for _, color := range highlightColors {
			add(flowGroup, locales.HighlightColor(colorName(color)), "", func() { a.setHighlight(fs, color) })
		}
		add(flowGroup, locales.OpenInNewWindow(), "↩", func() { a.openFlowWindow(f) })
		add(flowGroup, locales.MapLocalFromThisResponse(), "", func() { a.mapLocalFromFlow(f) })
		add(flowGroup, locales.MapRemoteThisURL(), "", func() { a.mapRemoteFromFlow(f) })
		add(flowGroup, locales.BreakpointOnThisURL(), "", func() { a.breakpointFromFlow(f) })
		add(flowGroup, locales.ScriptForThisURL(), "", func() { a.scriptFromFlow(f) })
		add(flowGroup, locales.BlockThisURL(), "", func() { a.blockFromFlow(f, false) })
		add(flowGroup, locales.EnableSSLProxyingForHost(f.Host()), "", func() { a.enableSSL(f.Host(), false) })
		add(flowGroup, locales.PinHost(f.Host()), "", func() { a.togglePin("host:" + f.Host()) })
		add(flowGroup, locales.Compare(), "⇧⌘D", a.compareChosen)
		add(flowGroup, locales.AddToDiffPool(), "", func() { a.addToDiffPool(fs) })
		add(flowGroup, locales.SaveToFolderEllipsis(), "⌥⌘D", func() { a.saveToFolder(fs) })
		add(flowGroup, locales.CopyAsMarkdown(), "", func() { a.copyMarkdown(fs) })
		if name := a.clientLabel(f); name != "" {
			add(flowGroup, locales.BlockApp(name), "", func() { a.blockApp(f, false) })
		}
		add(flowGroup, locales.Delete(), "⌘⌫", func() { a.deleteFlows(fs) })
	}
	add(sessionGroup, locales.ClearSession(), "⌘K", a.clearFlows)
	add(sessionGroup, locales.NewSession(), "⌘N", a.newSession)
	add(sessionGroup, locales.OpenSessionEllipsis(), "⌘O", func() { a.openSessionDialog(false) })
	add(sessionGroup, locales.ImportHAROrSessionEllipsis(), "⇧⌘O", func() { a.openSessionDialog(true) })
	add(sessionGroup, locales.SaveSession(), "⌘S", a.saveSession)
	add(sessionGroup, locales.ExportAsFormat(exportTitle("har")), "⇧⌘E", func() { a.exportDialog("har", false) })
	for _, f := range []string{"csv", "postman", "openapi", "openapi-html", "raw"} {
		add(sessionGroup, locales.ExportAsFormat(exportTitle(f)), "", func() { a.exportDialog(f, false) })
	}
	add(sessionGroup, locales.OpenInNewWindowEllipsis(), "⌥⌘O", a.openSessionWindowDialog)
	add(recordingGroup, map[bool]string{true: locales.ResumeRecording(), false: locales.PauseRecording()}[a.paused], "⇧⌘R", func() { a.setPaused(!a.paused) })
	add(recordingGroup, map[bool]string{true: locales.StopOverridingMacOSProxy(), false: locales.OverrideMacOSProxy()}[a.systemProxyOn()], "", func() { a.setSystemProxy(!a.systemProxyOn()) })
	add(recordingGroup, locales.CopyProxyAddress(), "", func() { a.copy(a.proxyAddress(), locales.CopiedTheProxyAddress()) })
	add(toolsGroup, locales.ComposeNewRequest(), "⇧⌘N", func() { a.composeFrom(nil) })
	add(toolsGroup, locales.ImportFromCURL(), "", func() { a.composeFrom(nil); a.openCurlSheet() })
	for _, w := range []struct{ kind, name, keys string }{
		{"ssl", locales.SSLProxyingList(), "⌥⌘P"}, {"breakpoint", locales.BreakpointRules(), "⌥⌘B"}, {"bpedit", locales.BreakpointEditor(), ""},
		{"maplocal", locales.ToolMapLocal(), "⌥⌘L"}, {"mapremote", locales.ToolMapRemote(), "⌥⌘M"}, {"scripting", locales.ToolScripting(), "⌥⌘J"},
		{"block", locales.ToolBlockList(), ""}, {"allow", locales.ToolAllowList(), ""}, {"network", locales.ToolNetworkConditions(), "⌥⌘N"},
		{"dns", locales.ToolDNSSpoofing(), ""}, {"reverse", locales.ToolReverseProxy(), ""}, {"clientcerts", locales.ClientCertificates(), ""},
		{"certificate", locales.Certificate(), ""}, {"diff", locales.Diff(), ""}, {"settings", locales.Settings(), "⌘,"}, {"help", locales.Help(), ""},
		{"bptemplates", locales.BreakpointTemplates(), ""}, {"blockedapps", locales.BlockedApps(), ""}, {"protobuf", "Protobuf", ""},
		{"servercerts", locales.CustomServerCertificates(), ""}, {"setup", locales.AutomaticSetup(), ""},
	} {
		add(toolsGroup, locales.OpenWindowNamed(w.name), w.keys, func() { a.openWindow(w.kind) })
	}
	d := a.rules.Current()
	for _, t := range rules.AllTools {
		on := d.ToolOn(t.ID)
		name := map[bool]string{true: locales.TurnOffTool(toolName(t.ID)), false: locales.TurnOnTool(toolName(t.ID))}[on]
		add(toolsGroup, name, "", func() { a.setTool(t.ID, !on) })
	}
	add(toolsGroup, map[bool]string{true: locales.TurnOffTool(locales.NoCaching()), false: locales.TurnOnTool(locales.NoCaching())}[d.NoCaching], "", func() { a.setNoCaching(!d.NoCaching) })
	add(viewGroup, locales.ToggleSidebar(), "⌥⌘S", func() { a.setSidebar(!a.set.ShowSidebar) })
	add(viewGroup, locales.ToggleInspector(), "⌥⌘I", func() { a.setDetail(!a.set.ShowDetail) })
	add(viewGroup, locales.DockInspectorRight(), "", func() { a.setDetailRight(true) })
	add(viewGroup, locales.DockInspectorBelow(), "", func() { a.setDetailRight(false) })
	add(viewGroup, locales.Overview(), "⌘0", func() { a.section = "overview" })
	add(viewGroup, locales.AdvancedFilter(), "⌥⌘F", func() { a.setAdvanced(true) })
	add(viewGroup, locales.ClearFilters(), "", a.clearFilters)
	add(viewGroup, locales.AppearanceIs(locales.System()), "", func() { a.setAppearance(settings.AppearanceSystem) })
	add(viewGroup, locales.AppearanceIs(locales.Light()), "", func() { a.setAppearance(settings.AppearanceLight) })
	add(viewGroup, locales.AppearanceIs(locales.Dark()), "", func() { a.setAppearance(settings.AppearanceDark) })
	add(certGroup, locales.InstallCertificateOnThisMac(), "", a.installCertificate)
	add(certGroup, locales.ExportRootCertificateAsPEM(), "", func() { a.exportCertificate("pem") })
	add(certGroup, locales.UseYourOwnRootCertificate(), "", func() { a.rootImport = rootImport{open: true}; a.certTab = 0; a.openWindow("certificate") })
	add(settingsGroup, locales.MCPServerAndCommandLineTool(), "", func() { a.settingsTab = 4; a.openWindow("settings") })
	add(settingsGroup, locales.CheckForUpdates(), "", updater.CheckForUpdates)
	for _, pr := range a.set.FilterPresets {
		add(locales.GroupSavedFilter(), pr.Name, "", func() { a.applyPreset(pr) })
	}
	if a.folders != nil {
		for _, fd := range a.folders.Folders() {
			add(locales.GroupSavedFolder(), fd.Path, "", func() { a.openFolder(fd.Path) })
		}
	}
	for i, name := range store.ByCount(store.Domains(a.flows)) {
		if i >= 50 {
			break
		}
		add(locales.GroupGoToDomain(), name, "", func() { a.section = "domain:" + name })
	}
	for _, name := range store.ByCount(store.Apps(a.flows)) {
		add(locales.GroupGoToApp(), name, "", func() { a.section = "app:" + name })
	}
	return out
}

func matchCommands(cmds []command, query string) []command {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		return cmds
	}
	var out []command
outer:
	for _, c := range cmds {
		text := strings.ToLower(c.group + " " + c.name)
		for _, w := range words {
			if !strings.Contains(text, w) {
				continue outer
			}
		}
		out = append(out, c)
	}
	return out
}

func (a *App) paletteOverlay(c *ui.Context) {
	if !a.palette.open {
		return
	}
	p := a.pal
	st := &a.palette
	cmds := matchCommands(a.commands(), st.query)
	if st.row >= len(cmds) {
		st.row = len(cmds) - 1
	}
	if st.row < 0 && len(cmds) > 0 {
		st.row = 0
	}
	run := func(i int) {
		if i >= 0 && i < len(cmds) {
			st.open = false
			cmds[i].run()
		}
	}
	ui.DialogBase(c, &st.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.18)).Justify(ui.Start).PaddingY(90)
		panel.Width(560).MaxHeight(440).Radius(12).Background(p.bg).Border(1, p.border).Shadow(0, 12, 40, 0, ui.RGBA(0, 0, 0, 0.25)).Clip()
		ui.Column(c).FillWidth().Children(func() {
			ui.Row(c).FillWidth().Padding(10, 14).Gap(8).AlignItems(ui.Center).Children(func() {
				glyph(c, "command", 15, p.muted)
				in := ui.TextInput(c.Key("paletteQuery"), &st.query).Placeholder(locales.TypeACommandADomainOrAnApp()).Label(locales.Command()).AutoFocus().Grow(1)
				if in.Changed() {
					st.row = 0
				}
				if in.Submitted() {
					run(st.row)
				}
				if in.Shortcut(0, ui.KeyDown) {
					st.row = min(st.row+1, len(cmds)-1)
					st.list.ScrollIntoView(st.row)
				}
				if in.Shortcut(0, ui.KeyUp) {
					st.row = max(st.row-1, 0)
					st.list.ScrollIntoView(st.row)
				}
			})
			ui.Divider(c)
			if len(cmds) == 0 {
				ui.Text(c, locales.NoCommandsMatch()).TextColor(p.muted).Padding(16)
				return
			}
			ui.List(c.Key("paletteList"), &st.list, len(cmds), func(i int) {
				cmd := cmds[i]
				row := ui.Row(c).FillWidth().Padding(6, 8).Gap(10).Radius(6).AlignItems(ui.Center)
				if i == st.row {
					row.Background(p.accent.Alpha(0.14))
				}
				if row.Hovered() && i != st.row {
					row.Background(p.hover)
				}
				if row.Clicked() {
					run(i)
				}
				row.Children(func() {
					ui.Text(c, cmd.name).TextColor(p.text).SingleLine().Grow(1).Shrink(1)
					ui.Text(c, cmd.group).FontSize(10.5).TextColor(p.faint).SingleLine()
					ui.Text(c, cmd.keys).FontSize(11).TextColor(p.muted).Width(44).TextAlign(ui.End).SingleLine()
				})
			}).MaxHeight(380).Padding(6)
		})
	})
}
