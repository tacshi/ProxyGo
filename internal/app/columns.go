package app

import (
	"slices"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/settings"
	"proxygo/locales"
)

type columnEditor struct {
	open  bool
	col   settings.Column
	named bool
}

func (a *App) columnSheet(c *ui.Context) {
	e := &a.colEdit
	if !e.open {
		return
	}
	p := a.pal
	ui.Modal(c, &e.open, func() {
		ui.Column(c).Width(sheetWidth(c, 480)).Gap(12).Children(func() {
			ui.Text(c, locales.NewColumn()).FontSize(15).FontWeight(650)
			ui.Text(c, locales.ShowAHeaderAQueryParameter()).TextColor(p.muted).Wrap()
			names := make([]string, len(settings.Sources))
			source := ""
			for i, s := range settings.Sources {
				names[i] = columnSourceName(s.ID, s.Name)
				if s.ID == e.col.Source {
					source = names[i]
				}
			}
			side := map[bool]int{true: 1}[e.col.Response]
			submitted := false
			ui.Form(c, func() {
				ui.Field(c, locales.Value(), func() {
					if ui.Select(c, &source, names).Label(locales.Source()).Width(220).Changed() {
						for i, s := range settings.Sources {
							if names[i] == source {
								e.col.Source = s.ID
							}
						}
					}
				})
				if e.col.Source != settings.SourceQuery {
					ui.Field(c, locales.OfThe(), func() {
						if ui.Segmented(c, &side, locales.PhaseRequest(), locales.PhaseResponse()).Label(locales.Side()).Changed() {
							e.col.Response = side == 1
						}
					})
				}
				placeholder := map[string]string{
					settings.SourceHeader:   "X-Request-Id",
					settings.SourceQuery:    "page",
					settings.SourceKeyPath:  "data.user.name",
					settings.SourceJQ:       ".data.items | length",
					settings.SourceJSONPath: "$.data.items[0].id",
				}[e.col.Source]
				ui.Field(c, keyLabel(e.col.Source), func() {
					in := ui.TextInput(c, &e.col.Key).Placeholder(placeholder).Label(locales.ColumnKey()).AutoFocus()
					if in.Changed() && !e.named {
						e.col.Name = e.col.Key
					}
					submitted = submitted || in.Submitted()
				})
				ui.Field(c, locales.ColumnNameLabel(), func() {
					in := ui.TextInput(c, &e.col.Name).Placeholder(locales.ShownInTheTablesHeader()).Label(locales.ColumnNameAlt())
					if in.Changed() {
						e.named = true
					}
					submitted = submitted || in.Submitted()
				})
				if f := a.selectedFlow(); f != nil && e.col.Key != "" {
					ui.Field(c, locales.SelectedFlow(), func() {
						v := e.col.Value(f)
						if v == "" {
							v = locales.NoneParenthesized()
						}
						ui.Text(c, shorten(v, 200)).TextColor(p.text2).Selectable().Wrap()
					})
				}
			})
			invalid := columnProblem(e.col.Valid())
			if invalid == "" && slices.ContainsFunc(a.set.Columns, func(x settings.Column) bool { return x.ID() == e.col.ID() }) {
				invalid = locales.AColumnShowsThisValueAlready()
			}
			if invalid != "" && e.col.Key != "" {
				ui.Text(c, invalid).FontSize(11).TextColor(p.red)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					e.open = false
				}
				add := ui.PrimaryButton(c, locales.AddColumn()).Disabled(invalid != "")
				if add.Clicked() || invalid == "" && (submitted || c.Shortcut(ui.Cmd, ui.KeyEnter)) {
					a.addColumn(e.col)
					e.open = false
				}
			})
		})
	})
}

func keyLabel(source string) string {
	switch source {
	case settings.SourceHeader:
		return locales.TabHeader()
	case settings.SourceQuery:
		return locales.Parameter()
	case settings.SourceKeyPath:
		return locales.KeyPath()
	}
	return locales.TabQuery()
}
