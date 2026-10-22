package app

import (
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/locales"
)

func remoteIP(f *flow.Flow) string {
	if f == nil || f.Client.Path != "" || f.Client.PID > 0 {
		return ""
	}
	ip := net.ParseIP(f.Client.Name)
	if ip == nil || ip.IsLoopback() {
		return ""
	}
	return f.Client.Name
}

func (a *App) deviceName(ip string) string {
	if name := a.set.DeviceNames[ip]; name != "" {
		return name
	}
	return ip
}

func (a *App) clientLabel(f *flow.Flow) string {
	if ip := remoteIP(f); ip != "" {
		return a.deviceName(ip)
	}
	return clientName(f)
}

type deviceSheet struct {
	open     bool
	ip, name string
}

func (a *App) renameDevice(ip string) {
	a.deviceEdit = deviceSheet{open: true, ip: ip, name: a.set.DeviceNames[ip]}
}

func (a *App) setDeviceName(ip, name string) {
	name = strings.TrimSpace(name)
	a.updateSettings(func(s *settings.Settings) {
		names := maps.Clone(s.DeviceNames)
		if names == nil {
			names = map[string]string{}
		}
		if name == "" || name == ip {
			delete(names, ip)
		} else {
			names[ip] = name
		}
		s.DeviceNames = names
	})
}

func (a *App) deviceSheetView(c *ui.Context) {
	s := &a.deviceEdit
	if !s.open {
		return
	}
	ui.Modal(c, &s.open, func() {
		ui.Column(c).Width(sheetWidth(c, 400)).Gap(10).Children(func() {
			ui.Text(c, locales.SetDeviceNickname()).FontSize(15).FontWeight(650)
			ui.Text(c, locales.ProxyGoShowsByThisName(s.ip)).TextColor(a.pal.muted).Wrap()
			in := ui.TextInput(c, &s.name).Placeholder(locales.MyIPhone()).Label(locales.Nickname()).AutoFocus()
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					s.open = false
				}
				if ui.PrimaryButton(c, locales.Save()).Clicked() || in.Submitted() || c.Shortcut(ui.Cmd, ui.KeyEnter) {
					a.setDeviceName(s.ip, s.name)
					s.open = false
				}
			})
		})
	})
}

func (a *App) deviceMenu(m *ui.Menu, ip string) {
	if m.Item(locales.SetDeviceNicknameEllipsis()).Chosen() {
		a.renameDevice(ip)
	}
	key := "app:" + ip
	if m.Item(map[bool]string{true: locales.Unpin(), false: locales.Pin()}[a.pinned(key)]).Chosen() {
		a.togglePin(key)
	}
	if m.Item(locales.CopyIPAddress()).Chosen() {
		a.copy(ip, locales.CopiedTheAddress())
	}
	m.Separator()
	if m.Item(locales.DeleteAllFrom(a.deviceName(ip))).Chosen() {
		a.deleteMatching(func(f *flow.Flow) bool { return remoteIP(f) == ip })
	}
}

func (a *App) askDevice(ip string) bool {
	if a.win == nil {
		return false
	}
	a.askMu.Lock()
	defer a.askMu.Unlock()
	if a.rules.Current().Access.Allowed(net.ParseIP(ip)) {
		return true
	}
	name := ip
	if n := a.prefs.Get().DeviceNames[ip]; n != "" {
		name = n + " (" + ip + ")"
	}
	a.win.FlashFrame(true)
	r, err := mygo.Dialog.Message(mygo.MessageOptions{
		Type:    mygo.MessageQuestion,
		Message: locales.AllowToConnect(name),
		Detail:  locales.ADeviceOnYourNetworkWants(),
		Buttons: []string{locales.Allow(), locales.Deny()}, DefaultButton: 1, CancelButton: 1,
	})
	a.win.FlashFrame(false)
	if err != nil || r.Button != 0 {
		a.do(func() { a.toast(locales.TurnedAway(name)) })
		return false
	}
	a.rules.Update(func(d *rules.Data) {
		if !slices.Contains(d.Access.IPs, ip) {
			d.Access.IPs = append(d.Access.IPs, ip)
		}
	})
	a.do(func() { a.toast(locales.AllowedOnList(name)) })
	return true
}
