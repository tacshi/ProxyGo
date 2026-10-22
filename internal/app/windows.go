package app

import (
	"fmt"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
)

type windowSpec struct {
	title         string
	width, height int
}

var windowSpecs = map[string]windowSpec{
	"ssl":         {"SSL Proxying List", 760, 560},
	"maplocal":    {"Map Local", 980, 720},
	"mapremote":   {"Map Remote", 860, 600},
	"breakpoint":  {"Breakpoint Rules", 820, 560},
	"bpedit":      {"Breakpoint", 1000, 700},
	"scripting":   {"Scripting", 1100, 720},
	"network":     {"Network Conditions", 820, 560},
	"dns":         {"DNS Spoofing", 760, 520},
	"reverse":     {"Reverse Proxy", 780, 520},
	"block":       {"Block List", 780, 540},
	"allow":       {"Allow List", 780, 540},
	"clientcerts": {"Client Certificates", 780, 520},
	"certificate": {"Certificate", 820, 640},
	"settings":    {"Settings", 760, 620},
	"compose":     {"Compose", 1100, 720},
	"diff":        {"Diff", 1100, 720},
	"help":        {"ProxyGo Help", 640, 620},
	"setup":       {"Automatic Setup", 720, 640},
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
		Title:          spec.title,
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
	a.windowHeader(c, "Getting Started", "Inspect and debug HTTP and HTTPS traffic.", nil)
	section := func(title, body string) {
		ui.Text(c, title).FontSize(13).FontWeight(650).TextColor(p.text)
		ui.Text(c, body).TextColor(p.text2).Wrap()
	}
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(4, windowInset, windowInset, windowInset).Gap(10).Children(func() {
			section("1. Send traffic to ProxyGo", fmt.Sprintf("Turn on Tools › Override macOS Proxy, or set a device's HTTP proxy to %s. Apps that ignore the system proxy can use SOCKS5 (Settings › Proxy).", a.proxyAddress()))
			section("2. Trust the certificate", "Certificate › Install Certificate on this Mac. For phones, open http://proxy.go on the device while it uses ProxyGo, then trust the profile.")
			section("3. Decrypt HTTPS", "Encrypted tunnels show a lock. Choose Enable only this domain in the response pane, or add domains in Tools › SSL Proxying List.")
			section("4. Debug", "Repeat (⌘R) and Compose (⌘E) requests; pause them with Breakpoints; serve local files with Map Local; send them elsewhere with Map Remote; change them with Scripts; slow them down with Network Conditions; block them with the Block List; and resolve hosts with DNS Spoofing.")
			section("5. Automate", "Settings › Automation serves MCP to AI assistants and installs proxygo-cli, which records, exports and adds rules from a terminal. Certificate › Automatic Setup opens a terminal, a browser or an Electron app already going through ProxyGo.")
			ui.Box(c).Height(6)
			ui.Text(c, "Keyboard Shortcuts").FontSize(13).FontWeight(650).TextColor(p.text)
			shortcuts := [][2]string{
				{"⇧⌘P", "Command Palette"}, {"⌘F", "Filter"}, {"⌥⌘F", "Advanced Filter"}, {"⌘K", "Clear Session"},
				{"⇧⌘R", "Pause or Resume Recording"}, {"⌘R", "Repeat"}, {"⌘E", "Edit and Repeat"}, {"⇧⌘N", "Compose"},
				{"⇧⌘C", "Copy as cURL"}, {"⇧⌘U", "Copy URL"}, {"⌘D", "Save Request"}, {"⇧⌘M", "Comment"},
				{"⇧⌘D", "Compare Two Flows"}, {"⌘⌫", "Delete"}, {"⌘O", "Open Session"}, {"⌘S", "Save Session"},
				{"⇧⌘E", "Export HAR"}, {"⌥⌘S", "Toggle Sidebar"}, {"⌥⌘I", "Toggle Inspector"}, {"⌘,", "Settings"},
				{"⌥⌘P", "SSL Proxying List"}, {"⌥⌘B", "Breakpoints"}, {"⌥⌘L", "Map Local"}, {"⌥⌘M", "Map Remote"},
				{"⌥⌘J", "Scripting"}, {"⌥⌘N", "Network Conditions"}, {"↩ (double click)", "Open Flow in a Window"},
				{"⌥⌘O", "Open Session in a Window"}, {"⌥⌘D", "Save to Folder"}, {"⌘↩", "Send in Compose"},
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
