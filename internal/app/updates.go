package app

import (
	"cmp"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
	"github.com/egoist/mygo/plugins/updater/native"
	ui "github.com/egoist/mygo/proxygoui"
)

type updatePrefs struct {
	loaded       bool
	enabled      bool
	automatic    bool
	autoDownload bool
	lastCheck    time.Time
}

func updaterPlugin(icon string) mygo.Plugin {
	png, _ := appIconFiles.ReadFile("appicons/" + cmp.Or(icon, appIcons[0].id) + ".png")
	return native.New(updater.Options{Icon: png})
}

func (a *App) watchUpdates() {
	a.updates.enabled = mygo.Updater.Enabled()
	a.readUpdatePrefs()
	updater.OnChange(func() { a.do(a.readUpdatePrefs) })
}

func (a *App) readUpdatePrefs() {
	u := &a.updates
	u.automatic = updater.AutomaticChecks()
	u.autoDownload = updater.AutomaticDownloads()
	u.lastCheck = updater.LastCheck()
	u.loaded = true
}

func (a *App) updatesGroup(c *ui.Context, p palette) {
	u := &a.updates
	group(c, p, "Updates", func() {
		a.settingRow(c, "ProxyGo "+mygo.App.Version(), a.updateStatus(), func() {
			if ui.Button(c, "Check Now").Disabled(!u.enabled).Clicked() {
				updater.CheckForUpdates()
			}
		})
		if !u.enabled || !u.loaded {
			return
		}
		a.settingSwitch(c, "Check for updates automatically", "Once a day, while ProxyGo runs.", u.automatic, func(on bool) {
			u.automatic = on
			updater.SetAutomaticChecks(on)
		})
		ui.Column(c).FillWidth().Disabled(!u.automatic).Children(func() {
			a.settingSwitch(c, "Download and install updates automatically", "They take over the next time ProxyGo opens.", u.autoDownload, func(on bool) {
				u.autoDownload = on
				updater.SetAutomaticDownloads(on)
			})
		})
	})
}

func (a *App) updateStatus() string {
	u := &a.updates
	switch {
	case !u.enabled && mygo.IsDev():
		return "Debug builds don't update themselves."
	case !u.enabled:
		return "ProxyGo can't write where it's installed. Move it to Applications to get updates."
	case u.lastCheck.IsZero():
		return "Not checked for updates yet."
	}
	return "Last checked " + sinceText(u.lastCheck) + "."
}

func sinceText(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute", "minutes") + " ago"
	case d < 24*time.Hour:
		return plural(int(d/time.Hour), "hour", "hours") + " ago"
	case d < 48*time.Hour:
		return "yesterday"
	}
	return t.Format("January 2")
}
