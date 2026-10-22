package app

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/settings"
	"proxygo/locales"
)

var appIcons = []struct{ id, name string }{
	{"sunset", "Sunset"}, {"neon", "Neon"}, {"lime", "Lime"}, {"mint", "Mint"},
	{"grape", "Grape"}, {"paper", "Paper"}, {"graphite", "Graphite"}, {"sakura", "Sakura"},
}

//go:embed appicons
var appIconFiles embed.FS

type appIconState struct {
	mu        sync.Mutex
	want      string
	applying  sync.Mutex
	done      string
	applied   bool
	thumbnail map[string]*ui.Bitmap
}

func (a *App) setAppIcon(id string) {
	if id == appIcons[0].id {
		id = ""
	}
	a.updateSettings(func(s *settings.Settings) { s.AppIcon = id })
	a.applyAppIcon()
}

func (a *App) applyAppIcon() {
	st := &a.bundleIcon
	st.mu.Lock()
	st.want = a.set.AppIcon
	st.mu.Unlock()
	go func() {
		st.applying.Lock()
		defer st.applying.Unlock()
		st.mu.Lock()
		id := st.want
		st.mu.Unlock()
		if st.applied && id == st.done {
			return
		}
		icns, _ := appIconFiles.ReadFile("appicons/" + id + ".icns")
		ok := true
		if bundle := appBundle(); bundle != "" && (icns != nil || hasCustomIcon(bundle)) {
			ok = setBundleIcon(bundle, icns)
		}
		if mygo.App.IsReady() {
			_ = mygo.App.Dock.SetIcon(icns)
		}
		st.done, st.applied = id, true
		if !ok {
			a.do(func() { a.toast(locales.MacOSDidNotLetProxyGoChangeItsIcon()) })
		}
	}()
}

func (a *App) appIconThumbnail(id string) *ui.Bitmap {
	st := &a.bundleIcon
	if b, ok := st.thumbnail[id]; ok {
		return b
	}
	if st.thumbnail == nil {
		st.thumbnail = map[string]*ui.Bitmap{}
	}
	data, err := appIconFiles.ReadFile("appicons/" + id + ".png")
	var b *ui.Bitmap
	if err == nil {
		b, _ = ui.DecodeBitmap(data)
	}
	st.thumbnail[id] = b
	return b
}

func appBundle() string {
	if !mygo.App.IsPackaged() {
		return ""
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	bundle := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
	if !strings.HasSuffix(bundle, ".app") {
		return ""
	}
	return bundle
}

func hasCustomIcon(bundle string) bool {
	_, err := os.Stat(filepath.Join(bundle, "Icon\r"))
	return err == nil
}
