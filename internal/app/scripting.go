package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"
	"github.com/egoist/mygo/proxygoui/editor"

	"proxygo/internal/rules"
	"proxygo/internal/script"
)

type scriptState struct {
	selected  string
	drafts    map[string]*scriptDraft
	err       string
	console   bool
	logs      ui.ListState
	level     int
	reference bool
	listWidth float32
}

type scriptDraft struct {
	rule *rules.ScriptRule
	code *editor.State
}

func scriptTemplate() string { return script.Template }

func (a *App) scriptDraft(r *rules.ScriptRule) *scriptDraft {
	s := &a.scriptUI
	if s.drafts == nil {
		s.drafts = map[string]*scriptDraft{}
	}
	d := s.drafts[r.ID]
	if d == nil {
		buf := editor.NewBuffer(r.Script)
		buf.SetLanguage(editor.LanguageNamed("JavaScript"))
		d = &scriptDraft{rule: clone(r), code: &editor.State{Buffer: buf, Label: "Script", TabSize: 2}}
		s.drafts[r.ID] = d
	}
	return d
}

func (d *scriptDraft) changed(saved *rules.ScriptRule) bool {
	r := *d.rule
	r.Script = d.code.Buffer.String()
	return r != *saved
}

func (a *App) saveScript(d *scriptDraft) {
	code := d.code.Buffer.String()
	if err := script.Check(d.rule.Name, code); err != nil {
		a.scriptUI.err = err.Error()
		return
	}
	a.scriptUI.err = ""
	r := *d.rule
	r.Script = code
	a.rules.Update(func(data *rules.Data) {
		data.Scripts = putByID(data.Scripts, &r, func(s *rules.ScriptRule) string { return s.ID })
		delete(data.DisabledTools, rules.ToolScripting)
	})
	a.toast("Saved " + r.Name)
}

func (a *App) saveOpenScript() {
	s := &a.scriptUI
	saved := byID(a.rules.Current().Scripts, s.selected, func(r *rules.ScriptRule) string { return r.ID })
	if saved == nil {
		return
	}
	if d := s.drafts[saved.ID]; d != nil && d.changed(saved) {
		a.saveScript(d)
	}
}

func (a *App) scriptWindow(c *ui.Context) {
	p := a.pal
	s := &a.scriptUI
	d := a.rules.Current()
	sid := func(r *rules.ScriptRule) string { return r.ID }
	a.windowHeader(c, "Scripting", "Change requests and responses with JavaScript: onRequest runs before the request goes to the server, onResponse before the response reaches the client.", func() {
		on := d.ToolOn(rules.ToolScripting)
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, map[bool]string{true: "On", false: "Off"}[on]).FontWeight(600).TextColor(map[bool]ui.Color{true: p.green, false: p.muted}[on])
			if ui.Switch(c, &on).Label("Enable Scripting").Changed() {
				a.setTool(rules.ToolScripting, on)
			}
		})
	})
	ui.Divider(c)
	a.referenceSheet(c)
	if s.listWidth == 0 {
		s.listWidth = 270
	}
	ui.Split(c, &s.listWidth, func() {
		ui.Column(c).Fill().Background(p.sidebar).Children(func() {
			ui.Row(c).FillWidth().Padding(8, 6, 8, 14).Gap(6).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Scripts").FontWeight(650).Grow(1)
				ui.Button(c, "").Label("Scripting Options").Tooltip("Options").Children(func() { glyph(c, "ellipsis", 13, p.text2) }).Menu(func(m *ui.Menu) {
					a.scriptOptions(m)
				})
				if iconButton(c, "plus", "New Script", p.text2).Clicked() {
					r := &rules.ScriptRule{ID: rules.NewID(), Enabled: true, Name: fmt.Sprintf("Script %d", len(d.Scripts)+1), Matcher: rules.Matcher{URL: "https://example.com/*"}, OnRequest: true, OnResponse: true, Script: script.Template}
					a.rules.Update(func(data *rules.Data) { data.Scripts = append(data.Scripts, r) })
					s.selected = r.ID
				}
			})
			ui.Scroll(c).Grow(1).Children(func() {
				ui.Column(c).FillWidth().Padding(4, 6).Gap(2).Children(func() {
					if len(d.Scripts) == 0 {
						ui.Text(c, "No scripts yet.").TextColor(p.muted).Padding(8)
					}
					for _, r := range d.Scripts {
						row := ui.Row(c.Key(r.ID)).FillWidth().Padding(6, 8).Gap(8).Radius(6).AlignItems(ui.Center)
						if r.ID == s.selected {
							row.Background(p.accent.Alpha(0.15))
						} else if row.Hovered() {
							row.Background(p.hover)
						}
						if row.Clicked() {
							s.selected, s.err = r.ID, ""
						}
						row.Children(func() {
							on := r.Enabled
							if ui.Checkbox(c, &on, "").Label("Enabled").Changed() {
								id := r.ID
								a.rules.Update(func(data *rules.Data) {
									if x := byID(data.Scripts, id, sid); x != nil {
										x.Enabled = on
									}
								})
							}
							ui.Column(c).Grow(1).Gap(1).Children(func() {
								ui.Text(c, r.Name).FontWeight(600).SingleLine()
								ui.Text(c, r.URL).FontSize(10.5).TextColor(p.muted).SingleLine()
							})
						})
						row.ContextMenu(func(m *ui.Menu) {
							id := r.ID
							if m.Item("Duplicate").Chosen() {
								cp := *r
								cp.ID, cp.Name = rules.NewID(), r.Name+" copy"
								a.rules.Update(func(data *rules.Data) { data.Scripts = append(data.Scripts, &cp) })
							}
							if m.Item("Delete").Chosen() {
								a.rules.Update(func(data *rules.Data) { data.Scripts = dropByID(data.Scripts, id, sid) })
								delete(s.drafts, id)
							}
						})
					}
				})
			})
		})
	}, func() {
		saved := byID(d.Scripts, s.selected, sid)
		if saved == nil && len(d.Scripts) > 0 {
			saved = d.Scripts[0]
			s.selected = saved.ID
		}
		if saved == nil {
			ui.Column(c).Fill().Center().Gap(10).Children(func() {
				glyph(c, "script", 28, p.faint)
				ui.Text(c, "No script chosen").FontSize(14).FontWeight(600).TextColor(p.text2)
				if ui.PrimaryButton(c, "New Script").Clicked() {
					r := &rules.ScriptRule{ID: rules.NewID(), Enabled: true, Name: "Script 1", Matcher: rules.Matcher{URL: "https://example.com/*"}, OnRequest: true, OnResponse: true, Script: script.Template}
					a.rules.Update(func(data *rules.Data) { data.Scripts = append(data.Scripts, r) })
					s.selected = r.ID
				}
			})
			return
		}
		a.scriptEditor(c, a.scriptDraft(saved), saved)
	}).Grow(1)
}

func (a *App) scriptEditor(c *ui.Context, dr *scriptDraft, saved *rules.ScriptRule) {
	p := a.pal
	s := &a.scriptUI
	r := dr.rule
	ui.Column(c.Key(r.ID)).Fill().Children(func() {
		ui.Column(c).FillWidth().Padding(10, inset).Gap(8).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.TextInput(c, &r.Name).Label("Name").Width(200)
				ui.TextInput(c, &r.URL).Placeholder("https://api.example.com/*").Label("Matching URL").Grow(1)
				method := methodLabel(r.Method)
				if ui.Select(c, &method, methods).Label("Method").Width(100).Changed() {
					if method == "ANY" {
						r.Method = ""
					} else {
						r.Method = method
					}
				}
				regex := r.Match == "regex"
				if ui.Checkbox(c, &regex, "Regex").Changed() {
					r.Match = map[bool]string{true: "regex", false: "wildcard"}[regex]
				}
			})
			ui.Row(c).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Checkbox(c, &r.OnRequest, "Run on Request")
				ui.Checkbox(c, &r.OnResponse, "Run on Response")
				ui.Checkbox(c, &r.MockResponse, "Mock API").Tooltip("Answer from onResponse without sending the request to the server")
				ui.Spacer(c)
				ui.MenuButton(c, "Snippets", func(m *ui.Menu) {
					for _, sn := range script.Snippets {
						if m.Item(sn.Name).Chosen() {
							dr.code.Insert(sn.Code + "\n")
						}
					}
				})
				changed := dr.changed(saved)
				if ui.Button(c, "Revert").Disabled(!changed).Clicked() {
					delete(s.drafts, r.ID)
					s.err = ""
				}
				if ui.PrimaryButton(c, "Save").Disabled(!changed).Tooltip("Save and apply (⌘S)").Clicked() || (changed && c.Shortcut(ui.Cmd, ui.KeyS)) {
					a.saveScript(dr)
				}
			})
			if msg := (rules.Matcher{URL: r.URL, Match: r.Match}).Valid(); msg != "" {
				ui.Text(c, msg).FontSize(11).TextColor(p.yellow)
			}
		})
		if s.err != "" {
			ui.Row(c).FillWidth().Padding(6, inset).Gap(6).Background(p.redSoft).Children(func() {
				glyph(c, "warning", 12, p.red)
				ui.Text(c, s.err).TextColor(p.red).Wrap().Grow(1)
			})
		}
		ui.Divider(c)
		ui.SplitVerticalPercent(c, &a.scriptSplit, func() {
			editor.View(c.Key("code"), dr.code).Fill()
		}, func() {
			a.console(c)
		}).Grow(1)
	})
}

func (a *App) console(c *ui.Context) {
	p := a.pal
	s := &a.scriptUI
	all := a.scripts.Logs()
	logs := all
	if s.level > 0 {
		logs = nil
		for _, l := range all {
			if l.Level == "error" || s.level == 1 && l.Level == "warn" {
				logs = append(logs, l)
			}
		}
	}
	ui.Column(c).Fill().Children(func() {
		ui.Row(c).FillWidth().Padding(4, inset).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "Console").FontWeight(650)
			ui.Text(c, plural(len(logs), "line", "lines")).FontSize(11).TextColor(p.muted)
			ui.Spacer(c)
			ui.Segmented(c, &s.level, "All", "Warnings", "Errors").Label("Console level")
			if ui.Button(c, "Clear").Clicked() {
				a.scripts.ClearLogs()
			}
		})
		ui.Divider(c)
		if len(logs) == 0 {
			emptyState(c, p, map[bool]string{true: "console.log() output shows here", false: "No lines at this level"}[len(all) == 0])
			return
		}
		a.scriptUI.logs.FollowEnd = true
		ui.List(c.Key("logs"), &a.scriptUI.logs, len(logs), func(i int) {
			l := logs[i]
			color := p.text2
			switch l.Level {
			case "error":
				color = p.red
			case "warn":
				color = p.yellow
			}
			ui.Row(c).FillWidth().Padding(2, inset).Gap(8).Children(func() {
				ui.Text(c, l.Time.Format("15:04:05")).FontSize(10.5).TextColor(p.faint).FontFeatures("tnum")
				ui.Text(c, l.Script).FontSize(10.5).TextColor(p.purple).SingleLine().Width(90)
				ui.Text(c, l.Text).FontSize(11).TextColor(color).Selectable().Wrap().Grow(1).Font("Menlo")
			})
		}).Grow(1)
	})
}

func (a *App) scriptOptions(m *ui.Menu) {
	d := a.rules.Current()
	if m.Item("Run Only the First Matching Script").Checked(d.Scripting.FirstOnly).Chosen() {
		a.rules.Update(func(d *rules.Data) { d.Scripting.FirstOnly = !d.Scripting.FirstOnly })
	}
	if m.Item("Let Scripts Read Environment Variables").Checked(d.Scripting.AllowEnv).Chosen() {
		a.rules.Update(func(d *rules.Data) { d.Scripting.AllowEnv = !d.Scripting.AllowEnv })
	}
	m.Separator()
	if m.Item("Import Script File…").Chosen() {
		a.importScriptFile()
	}
	if m.Item("Open Scripts Folder").Chosen() {
		root := a.scripts.Root()
		_ = os.MkdirAll(root, 0o755)
		openPath(root)
	}
	if m.Item("Scripting Reference").Chosen() {
		a.scriptUI.reference = true
	}
}

func (a *App) importScriptFile() {
	parent := a.windows["scripting"]
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Title: "Import a Script", Filters: []mygo.FileFilter{{Name: "JavaScript", Extensions: []string{"js", "mjs", "cjs"}}}})
		if err != nil || len(paths) == 0 {
			return
		}
		path := paths[0]
		code, err := readCapped(path, 1<<20)
		a.do(func() {
			if err != nil {
				a.toast("Cannot read " + filepath.Base(path) + ": " + err.Error())
				return
			}
			name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			if err := script.Check(name, string(code)); err != nil {
				a.toast(err.Error())
				return
			}
			r := &rules.ScriptRule{ID: rules.NewID(), Enabled: false, Name: name, Matcher: rules.Matcher{URL: "https://example.com/*"}, OnRequest: true, OnResponse: true, Script: string(code)}
			a.rules.Update(func(data *rules.Data) { data.Scripts = append(data.Scripts, r) })
			a.scriptUI.selected = r.ID
			a.toast("Imported " + name + ", switched off: set its URL, then switch it on")
		})
	}()
}

func (a *App) referenceSheet(c *ui.Context) {
	s := &a.scriptUI
	if !s.reference {
		return
	}
	_, h := c.Size()
	ui.Modal(c, &s.reference, func() {
		ui.Column(c).Width(sheetWidth(c, 760)).Height(max(h-120, 240)).Gap(10).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Scripting Reference").FontSize(15).FontWeight(650).Grow(1)
				if ui.Button(c, "Done").Clicked() {
					s.reference = false
				}
			})
			ui.Column(c).Grow(1).FillWidth().Radius(6).Border(1, a.pal.border).Clip().Children(func() {
				a.textViewer(c, "scriptReference", script.Reference(), "Markdown", "Scripting reference")
			})
		})
	})
}
