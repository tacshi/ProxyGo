package app

import (
	"strings"

	"github.com/egoist/mygo/plugins/updater"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/codegen"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/internal/store"
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
	if fs := a.chosenFlows(); len(fs) > 0 {
		f := fs[0]
		add("Flow", "Repeat", "⌘R", func() { a.repeatFlows(fs) })
		add("Flow", "Edit and Repeat", "⌘E", func() { a.composeFrom(f) })
		add("Flow", "Advanced Repeat", "⌥⌘R", func() { a.advancedRepeat(fs) })
		add("Flow", "Copy URL", "⇧⌘U", func() { a.copyURLs(fs) })
		for _, l := range codegen.Languages {
			add("Flow", "Copy as "+l.Name, "", func() { a.copyCode(fs, l.Name) })
		}
		add("Flow", "Add Comment", "⇧⌘M", func() { a.editComment(fs) })
		add("Flow", "Save Request", "⌘D", func() { a.setSaved(fs, !f.Saved) })
		for _, color := range highlightColors {
			add("Flow", "Highlight "+title(color), "", func() { a.setHighlight(fs, color) })
		}
		add("Flow", "Open in New Window", "↩", func() { a.openFlowWindow(f) })
		add("Flow", "Map Local from This Response", "", func() { a.mapLocalFromFlow(f) })
		add("Flow", "Map Remote This URL", "", func() { a.mapRemoteFromFlow(f) })
		add("Flow", "Breakpoint on This URL", "", func() { a.breakpointFromFlow(f) })
		add("Flow", "Script for This URL", "", func() { a.scriptFromFlow(f) })
		add("Flow", "Block This URL", "", func() { a.blockFromFlow(f, false) })
		add("Flow", "Enable SSL Proxying for "+f.Host(), "", func() { a.enableSSL(f.Host(), false) })
		add("Flow", "Pin "+f.Host(), "", func() { a.togglePin("host:" + f.Host()) })
		add("Flow", "Compare", "⇧⌘D", a.compareChosen)
		add("Flow", "Add to Diff Pool", "", func() { a.addToDiffPool(fs) })
		add("Flow", "Save to Folder…", "⌥⌘D", func() { a.saveToFolder(fs) })
		add("Flow", "Copy as Markdown", "", func() { a.copyMarkdown(fs) })
		if name := a.clientLabel(f); name != "" {
			add("Flow", "Block "+name, "", func() { a.blockApp(f, false) })
		}
		add("Flow", "Delete", "⌘⌫", func() { a.deleteFlows(fs) })
	}
	add("Session", "Clear Session", "⌘K", a.clearFlows)
	add("Session", "New Session", "⌘N", a.newSession)
	add("Session", "Open Session…", "⌘O", func() { a.openSessionDialog(false) })
	add("Session", "Import HAR or Session…", "⇧⌘O", func() { a.openSessionDialog(true) })
	add("Session", "Save Session", "⌘S", a.saveSession)
	add("Session", "Export as HAR…", "⇧⌘E", func() { a.exportDialog("har", false) })
	add("Session", "Export as CSV…", "", func() { a.exportDialog("csv", false) })
	for _, f := range []string{"postman", "openapi", "openapi-html", "raw"} {
		add("Session", "Export as "+exportFormats[f].title+"…", "", func() { a.exportDialog(f, false) })
	}
	add("Session", "Open in New Window…", "⌥⌘O", a.openSessionWindowDialog)
	add("Recording", map[bool]string{true: "Resume Recording", false: "Pause Recording"}[a.paused], "⇧⌘R", func() { a.setPaused(!a.paused) })
	add("Recording", map[bool]string{true: "Stop Overriding macOS Proxy", false: "Override macOS Proxy"}[a.systemProxyOn()], "", func() { a.setSystemProxy(!a.systemProxyOn()) })
	add("Recording", "Copy Proxy Address", "", func() { a.copy(a.proxyAddress(), "the proxy address") })
	add("Tools", "Compose New Request", "⇧⌘N", func() { a.composeFrom(nil) })
	add("Tools", "Import from cURL", "", func() { a.composeFrom(nil); a.openCurlSheet() })
	for _, w := range []struct{ kind, name, keys string }{
		{"ssl", "SSL Proxying List", "⌥⌘P"}, {"breakpoint", "Breakpoint Rules", "⌥⌘B"}, {"bpedit", "Breakpoint Editor", ""},
		{"maplocal", "Map Local", "⌥⌘L"}, {"mapremote", "Map Remote", "⌥⌘M"}, {"scripting", "Scripting", "⌥⌘J"},
		{"block", "Block List", ""}, {"allow", "Allow List", ""}, {"network", "Network Conditions", "⌥⌘N"},
		{"dns", "DNS Spoofing", ""}, {"reverse", "Reverse Proxy", ""}, {"clientcerts", "Client Certificates", ""},
		{"certificate", "Certificate", ""}, {"diff", "Diff", ""}, {"settings", "Settings", "⌘,"}, {"help", "Help", ""},
		{"bptemplates", "Breakpoint Templates", ""}, {"blockedapps", "Blocked Apps", ""}, {"protobuf", "Protobuf", ""},
		{"servercerts", "Custom Server Certificates", ""}, {"setup", "Automatic Setup", ""},
	} {
		add("Tools", "Open "+w.name, w.keys, func() { a.openWindow(w.kind) })
	}
	d := a.rules.Current()
	for _, t := range rules.AllTools {
		on := d.ToolOn(t.ID)
		add("Tools", map[bool]string{true: "Turn Off ", false: "Turn On "}[on]+t.Name, "", func() { a.setTool(t.ID, !on) })
	}
	add("Tools", map[bool]string{true: "Turn Off No Caching", false: "Turn On No Caching"}[d.NoCaching], "", func() { a.setNoCaching(!d.NoCaching) })
	add("View", "Toggle Sidebar", "⌥⌘S", func() { a.setSidebar(!a.set.ShowSidebar) })
	add("View", "Toggle Inspector", "⌥⌘I", func() { a.setDetail(!a.set.ShowDetail) })
	add("View", "Dock Inspector Right", "", func() { a.setDetailRight(true) })
	add("View", "Dock Inspector Below", "", func() { a.setDetailRight(false) })
	add("View", "Overview", "⌘0", func() { a.section = "overview" })
	add("View", "Advanced Filter", "⌥⌘F", func() { a.setAdvanced(true) })
	add("View", "Clear Filters", "", a.clearFilters)
	add("View", "Appearance: System", "", func() { a.setAppearance(settings.AppearanceSystem) })
	add("View", "Appearance: Light", "", func() { a.setAppearance(settings.AppearanceLight) })
	add("View", "Appearance: Dark", "", func() { a.setAppearance(settings.AppearanceDark) })
	add("Certificate", "Install Certificate on this Mac", "", a.installCertificate)
	add("Certificate", "Export Root Certificate as PEM", "", func() { a.exportCertificate("pem") })
	add("Certificate", "Use Your Own Root Certificate", "", func() { a.rootImport = rootImport{open: true}; a.certTab = 0; a.openWindow("certificate") })
	add("Settings", "MCP Server and Command-Line Tool", "", func() { a.settingsTab = 4; a.openWindow("settings") })
	add("Settings", "Check for Updates", "", updater.CheckForUpdates)
	for _, pr := range a.set.FilterPresets {
		add("Saved Filter", pr.Name, "", func() { a.applyPreset(pr) })
	}
	if a.folders != nil {
		for _, fd := range a.folders.Folders() {
			add("Saved Folder", fd.Path, "", func() { a.openFolder(fd.Path) })
		}
	}
	for i, name := range store.ByCount(store.Domains(a.flows)) {
		if i >= 50 {
			break
		}
		add("Go to Domain", name, "", func() { a.section = "domain:" + name })
	}
	for _, name := range store.ByCount(store.Apps(a.flows)) {
		add("Go to App", name, "", func() { a.section = "app:" + name })
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
				in := ui.TextInput(c.Key("paletteQuery"), &st.query).Placeholder("Type a command, a domain or an app").Label("Command").AutoFocus().Grow(1)
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
				ui.Text(c, "No commands match").TextColor(p.muted).Padding(16)
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
