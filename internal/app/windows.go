package app

import (
	"fmt"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/locales"
)

type windowSpec struct {
	title         func() string
	width, height int
}

var windowSpecs = map[string]windowSpec{
	"ssl":         {locales.SSLProxyingList, 760, 560},
	"maplocal":    {locales.ToolMapLocal, 980, 720},
	"mapremote":   {locales.ToolMapRemote, 860, 600},
	"breakpoint":  {locales.BreakpointRules, 820, 560},
	"bpedit":      {locales.ToolBreakpoint, 1000, 700},
	"scripting":   {locales.ToolScripting, 1100, 720},
	"network":     {locales.ToolNetworkConditions, 820, 560},
	"dns":         {locales.ToolDNSSpoofing, 760, 520},
	"reverse":     {locales.ToolReverseProxy, 780, 520},
	"block":       {locales.ToolBlockList, 780, 540},
	"allow":       {locales.ToolAllowList, 780, 540},
	"clientcerts": {locales.ClientCertificates, 780, 520},
	"certificate": {locales.Certificate, 820, 640},
	"settings":    {locales.Settings, 760, 620},
	"compose":     {locales.Compose, 1100, 720},
	"diff":        {locales.Diff, 1100, 720},
	"help":        {locales.ProxyGoHelp, 640, 620},
	"setup":       {locales.AutomaticSetup, 720, 640},
}

func (a *App) openWindow(kind string) {
	if win := a.windows[kind]; win != nil {
		win.Show()
		win.Focus()
		return
	}
	spec, ok := windowSpecs[kind]
	if !ok || a.win == nil {
		return
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:          spec.title(),
		Width:          spec.width,
		Height:         spec.height,
		UseContentSize: true,
		MinWidth:       560,
		MinHeight:      380,
		StateKey:       "tool-" + kind,
		AlwaysOnTop:    a.set.StayOnTop,
		Content:        ui.View(func(c *ui.Context) { a.toolWindow(c, kind) }),
	})
	a.windows[kind] = win
	win.OnClosed(func() {
		a.do(func() {
			a.forget(kind)
			if kind == "compose" {
				a.closeComposeSocket()
			}
		})
	})
	if kind == "certificate" {
		go a.refreshTrust()
		win.OnFocus(func() { go a.refreshTrust() })
	}
}

func (a *App) forget(key string) {
	delete(a.windows, key)
	if msgs := a.toasts[key]; len(msgs) > 0 {
		delete(a.toasts, key)
		a.toasts[""] = append(a.toasts[""], msgs...)
		a.invalidate()
	}
}

func (a *App) toolWindow(c *ui.Context, kind string) {
	a.runQueued()
	a.applyTheme(c)
	a.showToasts(c, kind)
	ui.Column(c).Fill().Background(a.pal.bg).Children(func() {
		switch kind {
		case "ssl":
			a.sslWindow(c)
		case "maplocal", "mapremote", "breakpoint", "network", "dns", "reverse", "block", "allow", "clientcerts", "bptemplates", "blockedapps", "protobuf", "servercerts":
			a.ruleWindow(c, kind)
		case "bpedit":
			a.breakpointEditor(c)
		case "scripting":
			a.scriptWindow(c)
		case "certificate":
			a.certificateWindow(c)
		case "settings":
			a.settingsWindow(c)
		case "compose":
			a.composeWindow(c)
		case "diff":
			a.diffWindow(c)
		case "help":
			a.helpWindow(c)
		case "setup":
			a.setupWindow(c)
		}
	})
}

func (a *App) openFlowWindow(f *flow.Flow) {
	if f == nil || a.win == nil {
		return
	}
	id := f.UniqueID
	key := "flow:" + id
	if win := a.windows[key]; win != nil {
		win.Focus()
		return
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title: fmt.Sprintf("%s %s", f.MethodName(), shorten(f.URL(), 80)), Width: 980, Height: 680, UseContentSize: true,
		MinWidth: 560, MinHeight: 380, AlwaysOnTop: a.set.StayOnTop,
		Content: ui.View(func(c *ui.Context) {
			a.applyTheme(c)
			a.showToasts(c, key)
			fl, _ := a.store.Lookup(id)
			if fl == nil {
				fl = f
			}
			a.inspector(c, fl, "window")
		}),
	})
	a.windows[key] = win
	win.OnClosed(func() { a.do(func() { a.forget(key) }) })
}

func (a *App) windowHeader(c *ui.Context, title, subtitle string, controls func()) {
	p := a.pal
	ui.Row(c).FillWidth().Padding(16, windowInset, 12, windowInset).Gap(12).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Gap(3).Children(func() {
			ui.Text(c, title).FontSize(17).FontWeight(650).TextColor(p.text)
			if subtitle != "" {
				ui.Text(c, subtitle).TextColor(p.muted).Wrap()
			}
		})
		if controls != nil {
			controls()
		}
	})
}

func (a *App) helpWindow(c *ui.Context) {
	p := a.pal
	a.windowHeader(c, locales.GettingStarted(), locales.InspectAndDebugHTTPAndHTTPSTraffic(), nil)
	section := func(title, body string) {
		ui.Text(c, title).FontSize(13).FontWeight(650).TextColor(p.text)
		ui.Text(c, body).TextColor(p.text2).Wrap()
	}
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(4, windowInset, windowInset, windowInset).Gap(10).Children(func() {
			section(locales.HelpStep1Title(), locales.HelpStep1(a.proxyAddress()))
			section(locales.HelpStep2Title(), locales.HelpStep2())
			section(locales.HelpStep3Title(), locales.HelpStep3())
			section(locales.HelpStep4Title(), locales.HelpStep4())
			section(locales.HelpStep5Title(), locales.HelpStep5())
			ui.Box(c).Height(6)
			ui.Text(c, locales.KeyboardShortcuts()).FontSize(13).FontWeight(650).TextColor(p.text)
			shortcuts := [][2]string{
				{"⇧⌘P", locales.CommandPalette()}, {"⌘F", locales.Filter()}, {"⌥⌘F", locales.AdvancedFilter()}, {"⌘K", locales.ClearSession()},
				{"⇧⌘R", locales.PauseOrResumeRecording()}, {"⌘R", locales.Repeat()}, {"⌘E", locales.EditAndRepeat()}, {"⇧⌘N", locales.Compose()},
				{"⇧⌘C", locales.CopyAsCURL()}, {"⇧⌘U", locales.CopyURL()}, {"⌘D", locales.SaveRequest()}, {"⇧⌘M", locales.Comment()},
				{"⇧⌘D", locales.CompareTwoFlows()}, {"⌘⌫", locales.Delete()}, {"⌘O", locales.OpenSession()}, {"⌘S", locales.SaveSession()},
				{"⇧⌘E", locales.ExportHARShortcut()}, {"⌥⌘S", locales.ToggleSidebar()}, {"⌥⌘I", locales.ToggleInspector()}, {"⌘,", locales.Settings()},
				{"⌥⌘P", locales.SSLProxyingList()}, {"⌥⌘B", locales.Breakpoints()}, {"⌥⌘L", locales.ToolMapLocal()}, {"⌥⌘M", locales.ToolMapRemote()},
				{"⌥⌘J", locales.ToolScripting()}, {"⌥⌘N", locales.ToolNetworkConditions()}, {locales.ReturnDoubleClick(), locales.OpenFlowInAWindow()},
				{"⌥⌘O", locales.OpenSessionInAWindow()}, {"⌥⌘D", locales.SaveToFolder()}, {"⌘↩", locales.SendInCompose()},
			}
			ui.Grid(c).Columns(2).GapX(18).GapY(4).Children(func() {
				for _, s := range shortcuts {
					ui.Row(c).Gap(10).Children(func() {
						ui.Text(c, s[0]).FontWeight(600).TextColor(p.text).Width(110)
						ui.Text(c, s[1]).TextColor(p.text2)
					})
				}
			})
		})
	})
}
