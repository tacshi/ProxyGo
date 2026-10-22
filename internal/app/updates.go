package app

import (
	"cmp"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
	"github.com/egoist/mygo/plugins/updater/native"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/locales"
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
	group(c, p, locales.Updates(), func() {
		a.settingRow(c, "ProxyGo "+mygo.App.Version(), a.updateStatus(), func() {
			if ui.Button(c, locales.CheckNow()).Disabled(!u.enabled).Clicked() {
				updater.CheckForUpdates()
			}
		})
		if !u.enabled || !u.loaded {
			return
		}
		a.settingSwitch(c, locales.CheckForUpdatesAutomatically(), locales.OnceADayWhileProxyGoRuns(), u.automatic, func(on bool) {
			u.automatic = on
			updater.SetAutomaticChecks(on)
		})
		ui.Column(c).FillWidth().Disabled(!u.automatic).Children(func() {
			a.settingSwitch(c, locales.DownloadAndInstallUpdatesAutomatically(), locales.TheyTakeOverTheNextTime(), u.autoDownload, func(on bool) {
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
		return locales.DebugBuildsDontUpdateThemselves()
	case !u.enabled:
		return locales.ProxyGoCantWriteWhereItsInstalled()
	case u.lastCheck.IsZero():
		return locales.NotCheckedForUpdatesYet()
	}
	return locales.LastChecked(sinceText(u.lastCheck))
}

func sinceText(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return locales.JustNow()
	case d < time.Hour:
		return locales.MinutesAgo(int(d / time.Minute))
	case d < 24*time.Hour:
		return locales.HoursAgo(int(d / time.Hour))
	case d < 48*time.Hour:
		return locales.Yesterday()
	}
	return locales.MonthDay(t)
}
