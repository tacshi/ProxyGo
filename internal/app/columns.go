package app

import (
	"slices"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/settings"
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
			ui.Text(c, "New Column").FontSize(15).FontWeight(650)
			ui.Text(c, "Show a header, a query parameter or a value of the JSON body of every flow.").TextColor(p.muted).Wrap()
			names := make([]string, len(settings.Sources))
			source := ""
			for i, s := range settings.Sources {
				names[i] = s.Name
				if s.ID == e.col.Source {
					source = s.Name
				}
			}
			side := map[bool]int{true: 1}[e.col.Response]
			submitted := false
			ui.Form(c, func() {
				ui.Field(c, "Value", func() {
					if ui.Select(c, &source, names).Label("Source").Width(220).Changed() {
						for _, s := range settings.Sources {
							if s.Name == source {
								e.col.Source = s.ID
							}
						}
					}
				})
				if e.col.Source != settings.SourceQuery {
					ui.Field(c, "Of the", func() {
						if ui.Segmented(c, &side, "Request", "Response").Label("Side").Changed() {
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
				ui.Field(c, map[string]string{settings.SourceHeader: "Header", settings.SourceQuery: "Parameter"}[e.col.Source]+keyLabel(e.col.Source), func() {
					in := ui.TextInput(c, &e.col.Key).Placeholder(placeholder).Label("Key").AutoFocus()
					if in.Changed() && !e.named {
						e.col.Name = e.col.Key
					}
					submitted = submitted || in.Submitted()
				})
				ui.Field(c, "Column Name", func() {
					in := ui.TextInput(c, &e.col.Name).Placeholder("Shown in the table's header").Label("Column name")
					if in.Changed() {
						e.named = true
					}
					submitted = submitted || in.Submitted()
				})
				if f := a.selectedFlow(); f != nil && e.col.Key != "" {
					ui.Field(c, "Selected Flow", func() {
						v := e.col.Value(f)
						if v == "" {
							v = "(none)"
						}
						ui.Text(c, shorten(v, 200)).TextColor(p.text2).Selectable().Wrap()
					})
				}
			})
			invalid := e.col.Valid()
			if invalid == "" && slices.ContainsFunc(a.set.Columns, func(x settings.Column) bool { return x.ID() == e.col.ID() }) {
				invalid = "A column shows this value already."
			}
			if invalid != "" && e.col.Key != "" {
				ui.Text(c, invalid).FontSize(11).TextColor(p.red)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "Cancel").Clicked() {
					e.open = false
				}
				add := ui.PrimaryButton(c, "Add Column").Disabled(invalid != "")
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
	case settings.SourceHeader, settings.SourceQuery:
		return ""
	case settings.SourceKeyPath:
		return "Key Path"
	}
	return "Query"
}
