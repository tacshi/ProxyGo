package app

import (
	"maps"
	"slices"
	"strings"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/internal/store"
	"proxygo/locales"
)

type presetSheet struct {
	open bool
	name string
}

func (a *App) currentPreset(name string) store.Preset {
	var conds []store.Condition
	for _, c := range a.conditions {
		if c.Active() {
			conds = append(conds, c)
		}
	}
	kinds := slices.Sorted(maps.Keys(a.kinds))
	return store.Preset{ID: rules.NewID(), Name: name, Query: a.query, Deep: a.deep, Kinds: kinds, Conditions: conds, Any: a.matchAny}
}

func (a *App) applyPreset(p store.Preset) {
	f := p.Filter()
	a.query, a.deep, a.matchAny = f.Query, f.Deep, f.Any
	a.kinds = f.Kinds
	a.conditions = f.Conditions
	a.advanced = len(f.Conditions) > 0
	if a.section == "overview" {
		a.section = "all"
	}
}

func (a *App) presetsButton(c *ui.Context) {
	p := a.pal
	presets := a.set.FilterPresets
	b := ui.Button(c, "").Label(locales.SavedFilters()).Tooltip(locales.SavedFilters())
	b.Children(func() { glyph(c, "bookmark", 13, p.text2) })
	b.Menu(func(m *ui.Menu) {
		if len(presets) == 0 {
			m.Item(locales.NoSavedFilters()).Disabled(true)
		}
		for _, pr := range presets {
			if m.Item(pr.Name).Chosen() {
				a.applyPreset(pr)
			}
		}
		m.Separator()
		if m.Item(locales.SaveCurrentFilterEllipsis()).Disabled(!a.filtering()).Chosen() {
			a.presetSave = presetSheet{open: true}
		}
		if len(presets) > 0 {
			m.Submenu(locales.Delete(), func(m *ui.Menu) {
				for _, pr := range presets {
					if m.Item(pr.Name).Chosen() {
						id := pr.ID
						a.updateSettings(func(s *settings.Settings) {
							s.FilterPresets = slices.DeleteFunc(s.FilterPresets, func(x store.Preset) bool { return x.ID == id })
						})
					}
				}
			})
		}
	})
}

func (a *App) filtering() bool {
	if a.query != "" || len(a.kinds) > 0 {
		return true
	}
	return slices.ContainsFunc(a.conditions, store.Condition.Active)
}

func (a *App) presetSheetView(c *ui.Context) {
	s := &a.presetSave
	if !s.open {
		return
	}
	ui.Modal(c, &s.open, func() {
		ui.Column(c).Width(sheetWidth(c, 400)).Gap(10).Children(func() {
			ui.Text(c, locales.SaveFilter()).FontSize(15).FontWeight(650)
			ui.Text(c, locales.KeepTheSearchTheCategoriesAnd()).TextColor(a.pal.muted).Wrap()
			in := ui.TextInput(c, &s.name).Placeholder(locales.ColumnName()).Label(locales.FilterName()).AutoFocus()
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					s.open = false
				}
				name := strings.TrimSpace(s.name)
				if ui.PrimaryButton(c, locales.Save()).Disabled(name == "").Clicked() || name != "" && (in.Submitted() || c.Shortcut(ui.Cmd, ui.KeyEnter)) {
					pr := a.currentPreset(name)
					a.updateSettings(func(s *settings.Settings) {
						s.FilterPresets = slices.DeleteFunc(s.FilterPresets, func(x store.Preset) bool { return x.Name == name })
						s.FilterPresets = append(s.FilterPresets, pr)
					})
					s.open = false
					a.toast(locales.SavedTheFilter(name))
				}
			})
		})
	})
}
