package app

import (
	_ "embed"
	"fmt"
	"strconv"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/rules"
	"proxygo/internal/settings"
)

//go:embed menubar.png
var menuBarIcon []byte

const issuesURL = "https://github.com/tacshi/ProxyGo/issues/new"

type trayItems struct {
	record, systemProxy, listen *mygo.MenuItem
	tools                       map[string]*mygo.MenuItem
	listenText                  string
}

func (a *App) setMenuBarIcon(on bool) {
	switch {
	case on && a.tray == nil:
		t, err := mygo.NewTray(mygo.TrayOptions{Icon: menuBarIcon, IconIsTemplate: true, ToolTip: "ProxyGo", Menu: a.trayMenu()})
		if err != nil {
			a.toast("Menu bar icon: " + err.Error())
			return
		}
		a.tray = t
	case !on && a.tray != nil:
		a.tray.Destroy()
		a.tray, a.trayItems = nil, trayItems{}
	}
}

func (a *App) trayMenu() *mygo.Menu {
	t := &a.trayItems
	t.tools = map[string]*mygo.MenuItem{}
	check := func(label string, on bool, fn func(bool)) *mygo.MenuItem {
		return &mygo.MenuItem{Label: label, Type: mygo.MenuItemCheckbox, Checked: on,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) {
				on := it.IsChecked()
				a.do(func() {
					fn(on)
					a.syncTray()
				})
			}}
	}
	t.record = check("Record Traffic", !a.paused, func(on bool) { a.setPaused(!on) })
	t.systemProxy = check("Override macOS Proxy", a.systemProxyOn(), a.setSystemProxy)
	t.listenText = a.listenLabel()
	t.listen = &mygo.MenuItem{Label: t.listenText, Submenu: []*mygo.MenuItem{
		{Label: "Copy Address", Click: a.on(func() { a.copy(a.proxyAddress(), "the address") })},
		{Label: "Copy IP Address", Click: a.on(func() { a.copy(a.proxyHost(), "the IP address") })},
		{Label: "Copy Port", Click: a.on(func() { a.copy(strconv.Itoa(a.proxy.Port()), "the port") })},
		{Label: "Copy Proxy URL", Click: a.on(func() { a.copy("http://"+a.proxyAddress(), "the proxy URL") })},
		{Label: "Copy Shell Command", ToolTip: "export http_proxy and https_proxy, for a terminal", Click: a.on(func() {
			url := "http://" + a.proxyAddress()
			a.copy(fmt.Sprintf("export http_proxy=%s https_proxy=%s", url, url), "the shell command")
		})},
		mygo.Separator(),
		{Label: "Proxy Settings…", Click: a.on(func() { a.showSettings(1) })},
	}}
	d := a.rules.Current()
	var tools []*mygo.MenuItem
	for _, tool := range rules.AllTools {
		it := check(tool.Name, d.ToolOn(tool.ID), func(on bool) { a.setTool(tool.ID, on) })
		t.tools[tool.ID] = it
		tools = append(tools, it)
	}
	return mygo.NewMenu([]*mygo.MenuItem{
		{Label: "Show ProxyGo", Click: a.on(a.showMain)},
		mygo.Separator(),
		t.record,
		t.systemProxy,
		mygo.Separator(),
		t.listen,
		mygo.Separator(),
		{Label: "Enable / Disable Tools", Submenu: tools},
		mygo.Separator(),
		{Label: "Send Feedback…", Click: a.on(func() { openPath(issuesURL) })},
		{Label: "Manual…", Click: a.on(func() { a.showMain(); a.openWindow("help") })},
		updater.MenuItem(),
		mygo.Separator(),
		{Label: "Quit ProxyGo", Click: a.on(mygo.App.Quit)},
	})
}

func (a *App) listenLabel() string { return "Listen on " + a.proxyAddress() }

func (a *App) syncTray() {
	t := &a.trayItems
	if a.tray == nil || t.record == nil {
		return
	}
	set := func(it *mygo.MenuItem, on bool) {
		if it.IsChecked() != on {
			it.SetChecked(on)
		}
	}
	set(t.record, !a.paused)
	set(t.systemProxy, a.systemProxyOn())
	if label := a.listenLabel(); t.listenText != label {
		t.listenText = label
		t.listen.SetLabel(label)
	}
	d := a.rules.Current()
	for id, it := range t.tools {
		set(it, d.ToolOn(id))
	}
}

func (a *App) showMain() {
	mygo.App.Focus()
	if a.win != nil {
		a.win.Show()
		a.win.Focus()
	}
}

func (a *App) showSettings(tab int) {
	a.settingsTab = tab
	a.openWindow("settings")
	mygo.App.Focus()
}

func (a *App) menuBarSettings(c *ui.Context) {
	a.settingSwitch(c, "Show ProxyGo in the menu bar", "Record, override the macOS proxy and copy the address from there.", !a.set.HideMenuBarIcon, func(on bool) {
		a.updateSettings(func(s *settings.Settings) { s.HideMenuBarIcon = !on })
		a.setMenuBarIcon(on)
	})
}
