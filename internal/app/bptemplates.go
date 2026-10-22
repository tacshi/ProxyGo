package app

import (
	"fmt"
	"net/url"
	"strings"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/locales"
)

type templateSheet struct {
	open  bool
	name  string
	pause string
}

func templateMessage(t *rules.BreakpointTemplate, pausedURL string) (proxy.Message, error) {
	tm, err := t.Parse()
	if err != nil {
		return proxy.Message{}, err
	}
	m := proxy.Message{Method: tm.Method, URL: pausedURL, StatusCode: tm.StatusCode, Body: tm.Body}
	for _, h := range tm.Header {
		m.Header.Entries = append(m.Header.Entries, flow.HeaderEntry{Enabled: true, Key: flow.HeaderKey{Name: h.Name, Lower: strings.ToLower(h.Name)}, Value: h.Value})
	}
	if !t.Response {
		base, err := url.Parse(pausedURL)
		if err != nil {
			return m, err
		}
		ref, err := url.Parse(tm.URL)
		if err != nil {
			return m, fmt.Errorf("the template's URL: %w", err)
		}
		m.URL = base.ResolveReference(ref).String()
	}
	if m.Header.Get("Content-Length") != "" {
		m.Header.Set("Content-Length", fmt.Sprint(len(m.Body)))
	}
	return m, nil
}

func (a *App) decide(id string, msg proxy.Message, ok bool) {
	for _, pd := range a.pauses {
		if pd.ID == id {
			pd.done <- decision{msg: msg, ok: ok}
			a.dropPause(id)
			return
		}
	}
}

func (a *App) answerWithTemplate(pd *pending, t *rules.BreakpointTemplate) {
	m, err := templateMessage(t, pd.Message.URL)
	if err != nil {
		a.toast(t.Name + ": " + err.Error())
		return
	}
	m.Method, m.URL = pd.Message.Method, pd.Message.URL
	m.Respond = !pd.Response
	a.decide(pd.ID, m, true)
}

func (a *App) applyTemplate(pd *pending, t *rules.BreakpointTemplate) {
	m, err := templateMessage(t, pd.Message.URL)
	if err != nil {
		a.toast(t.Name + ": " + err.Error())
		return
	}
	if pd.Response {
		m.Method, m.URL = pd.Message.Method, pd.Message.URL
	}
	tab := pd.edit.tab
	pd.edit = newMessageEditor(m, pd.Response)
	pd.edit.tab = tab
}

func (a *App) pauseActions(c *ui.Context, pd *pending) {
	templates := a.rules.Current().BreakpointTemplates
	ui.MenuButton(c, locales.Abort(), func(m *ui.Menu) {
		if m.Item(locales.AbortWith403Forbidden()).Chosen() {
			a.resolvePause(pd.ID, false, false)
		}
		if m.Item(locales.DropTheConnection()).Chosen() {
			a.decide(pd.ID, proxy.Message{Drop: true}, false)
		}
		verb := map[bool]func(string) string{true: locales.ReplaceWithTemplate, false: locales.AnswerWithTemplate}[pd.Response]
		first := true
		for _, t := range templates {
			if t == nil || !t.Response {
				continue
			}
			if first {
				m.Separator()
				first = false
			}
			if m.Item(verb(t.Name)).Chosen() {
				a.answerWithTemplate(pd, t)
			}
		}
	}).Tooltip(map[bool]string{true: locales.StopTheResponseOrReplaceIt(), false: locales.StopTheRequestOrAnswerIt()}[pd.Response])
	ui.MenuButton(c, locales.Templates(), func(m *ui.Menu) {
		n := 0
		for _, t := range templates {
			if t == nil || t.Response != pd.Response {
				continue
			}
			n++
			if m.Item(locales.ApplyTemplate(t.Name)).Chosen() {
				a.applyTemplate(pd, t)
			}
		}
		if n == 0 {
			m.Item(map[bool]string{true: locales.NoResponseTemplates(), false: locales.NoRequestTemplates()}[pd.Response]).Disabled(true)
		}
		m.Separator()
		if m.Item(locales.SaveAsTemplateEllipsis()).Chosen() {
			a.tplSave = templateSheet{open: true, pause: pd.ID, name: shorten(strings.TrimPrefix(strings.TrimPrefix(pd.Message.URL, "https://"), "http://"), 50)}
		}
		if m.Item(locales.ManageTemplatesEllipsis()).Chosen() {
			a.openWindow("bptemplates")
		}
	})
}

func (a *App) templateSheetView(c *ui.Context) {
	s := &a.tplSave
	if !s.open {
		return
	}
	var pd *pending
	for _, x := range a.pauses {
		if x.ID == s.pause {
			pd = x
		}
	}
	if pd == nil {
		s.open = false
		return
	}
	ui.Modal(c, &s.open, func() {
		ui.Column(c).Width(sheetWidth(c, 420)).Gap(10).Children(func() {
			ui.Text(c, locales.SaveAsTemplate()).FontSize(15).FontWeight(650)
			ui.Text(c, map[bool]string{true: locales.KeepThisResponse(), false: locales.KeepThisRequest()}[pd.Response]).TextColor(a.pal.muted).Wrap()
			in := ui.TextInput(c, &s.name).Placeholder(locales.ColumnName()).Label(locales.TemplateName()).AutoFocus()
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					s.open = false
				}
				name := strings.TrimSpace(s.name)
				if ui.PrimaryButton(c, locales.Save()).Disabled(name == "").Clicked() || name != "" && (in.Submitted() || c.Shortcut(ui.Cmd, ui.KeyEnter)) {
					m := pd.edit.message()
					var header []rules.Pair
					for _, h := range m.Header.Entries {
						if h.Enabled {
							header = append(header, rules.Pair{Name: h.Key.Name, Value: h.Value})
						}
					}
					t := &rules.BreakpointTemplate{ID: rules.NewID(), Name: name, Response: pd.Response, Raw: rules.RawOf(pd.Response, m.Method, m.URL, m.StatusCode, header, m.Body)}
					a.rules.Update(func(d *rules.Data) { d.BreakpointTemplates = append(d.BreakpointTemplates, t) })
					s.open = false
					a.toast(locales.SavedTheTemplate(name))
				}
			})
		})
	})
}
