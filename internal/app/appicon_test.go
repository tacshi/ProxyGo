package app

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	ui "github.com/egoist/mygo/proxygoui"
)

func TestAppIconFiles(t *testing.T) {
	data, err := os.ReadFile("../../assets/icon/variants.json")
	if err != nil {
		t.Fatal(err)
	}
	var variants map[string]any
	if err := json.Unmarshal(data, &variants); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i, icon := range appIcons {
		ids = append(ids, icon.id)
		if _, ok := variants[icon.id]; ok == (i == 0) {
			t.Errorf("%s: in variants.json %v", icon.id, ok)
		}
		if b := (&App{}).appIconThumbnail(icon.id); b == nil {
			t.Errorf("%s: no thumbnail", icon.id)
		}
		if _, err := appIconFiles.ReadFile("appicons/" + icon.id + ".icns"); (err == nil) == (i == 0) {
			t.Errorf("%s.icns: %v", icon.id, err)
		}
	}
	if len(variants) != len(appIcons)-1 {
		t.Errorf("variants.json has %d variants, the picker %d", len(variants), len(appIcons)-1)
	}
	files, err := appIconFiles.ReadDir("appicons")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if id, _, _ := strings.Cut(f.Name(), "."); !slices.Contains(ids, id) {
			t.Errorf("appicons/%s is no icon of the picker", f.Name())
		}
	}
}

func TestAppIconPicker(t *testing.T) {
	a, _ := testApp(t)
	tt := ui.NewTester(a.settingsWindow, windowSpecs["settings"].width, 1400)
	mustClick(t, tt, "Mint")
	if a.set.AppIcon != "mint" || a.prefs.Get().AppIcon != "mint" {
		t.Fatalf("chose %q, saved %q", a.set.AppIcon, a.prefs.Get().AppIcon)
	}
	mustClick(t, tt, "Sunset")
	if a.set.AppIcon != "" || a.prefs.Get().AppIcon != "" {
		t.Fatalf("chose %q, saved %q, not ProxyGo's own", a.set.AppIcon, a.prefs.Get().AppIcon)
	}
}
