package app

import (
	"cmp"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/i18n"
	"github.com/egoist/mygo/netproxy"
	"github.com/egoist/mygo/plugins/updater"
	"github.com/egoist/mygo/plugins/updater/native"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/proxy"
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

func (a *App) keepUpdatesOffOwnProxy() {
	netproxy.Transport().Proxy = func(r *http.Request) (*url.URL, error) {
		u, err := netproxy.Proxy(r)
		if u != nil && ownProxy(u, a.serving.Load()) {
			return nil, err
		}
		return u, err
	}
}

func ownProxy(u *url.URL, s *proxy.Server) bool {
	if s == nil {
		return false
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port != 0 && (port == s.Port() || port == s.SocksPort())
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
	ago := func(n time.Duration, unit i18n.RelativeTimeUnit) string {
		return i18n.FormatRelativeTime(i18n.Locale(), -float64(n), unit, i18n.RelativeTimeOptions{Auto: unit == i18n.RelativeDay})
	}
	switch {
	case d < time.Minute:
		return locales.JustNow()
	case d < time.Hour:
		return ago(d/time.Minute, i18n.RelativeMinute)
	case d < 24*time.Hour:
		return ago(d/time.Hour, i18n.RelativeHour)
	case d < 48*time.Hour:
		return ago(1, i18n.RelativeDay)
	}
	return locales.MonthDay(t)
}

func sinceSeconds(d time.Duration) string {
	return i18n.FormatRelativeTime(i18n.Locale(), -float64(d/time.Second), i18n.RelativeSecond, i18n.RelativeTimeOptions{})
}
