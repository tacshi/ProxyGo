package app

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/session"
	"proxygo/internal/store"
	"proxygo/locales"
)

type sessionView struct {
	title, path string
	flows       []*flow.Flow
	visible     []*flow.Flow
	query       string
	shownQuery  string
	row         int
	list        ui.ListState
	selected    string
	height      float32
}

func (a *App) openSessionWindowDialog() {
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent: a.win, Title: locales.OpenInNewWindow(),
			Filters: []mygo.FileFilter{
				{Name: locales.SessionsAndArchives(), Extensions: session.Extensions},
				{Name: locales.AllFiles(), Extensions: []string{"*"}},
			},
		})
		if err != nil || len(paths) == 0 {
			return
		}
		b, err := session.Open(paths[0])
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotOpen(filepath.Base(paths[0]), err.Error()))
				return
			}
			a.loadIcons(b.Icons)
			a.openSessionWindow(filepath.Base(paths[0]), paths[0], b.Flows)
		})
	}()
}

func (a *App) openSessionWindow(title, path string, flows []*flow.Flow) {
	key := "session:" + path
	if a.sessions == nil {
		a.sessions = map[string]*sessionView{}
	}
	v := &sessionView{title: title, path: path, flows: flows, visible: flows, row: -1}
	a.sessions[key] = v
	if win := a.windows[key]; win != nil {
		win.Show()
		win.Focus()
		return
	}
	if a.win == nil {
		return
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title: title + " — ProxyGo", Width: 1180, Height: 780, UseContentSize: true,
		MinWidth: 700, MinHeight: 440, AlwaysOnTop: a.set.StayOnTop, StateKey: "session-window",
		Content: ui.View(func(c *ui.Context) { a.sessionWindow(c, key) }),
	})
	a.windows[key] = win
	win.OnClosed(func() {
		a.do(func() {
			a.forget(key)
			delete(a.sessions, key)
		})
	})
}

func (a *App) sessionWindow(c *ui.Context, key string) {
	a.runQueued()
	a.applyTheme(c)
	a.showToasts(c, key)
	p := a.pal
	v := a.sessions[key]
	if v == nil {
		return
	}
	if v.query != v.shownQuery || v.visible == nil {
		v.shownQuery = v.query
		v.visible = store.Apply(v.flows, store.Filter{Query: v.query})
	}
	ui.Column(c).Fill().Background(p.bg).Children(func() {
		ui.Row(c).FillWidth().Padding(14, windowInset, 10, windowInset).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Shrink(1).Gap(2).Children(func() {
				ui.Text(c, v.title).FontSize(15).FontWeight(650).TextColor(p.text).SingleLine()
				ui.Text(c, locales.FlowsSavedNewTraffic(len(v.flows))).FontSize(11).TextColor(p.muted).SingleLine()
			})
			box, _ := a.searchField(c, "q", &v.query, locales.Filter(), locales.FilterFlows())
			box.Width(220)
			if ui.Button(c, locales.ImportIntoSession()).Tooltip(locales.AddTheseFlowsToTheMain()).Clicked() {
				a.store.Append(v.flows)
				a.toast(locales.ImportedFlows(len(v.flows)))
			}
			ui.MenuButton(c, locales.Export(), func(m *ui.Menu) {
				for _, f := range []string{"har", "postman", "openapi", "openapi-html", "csv", "raw"} {
					if m.Item(locales.AsFormatEllipsis(exportTitle(f))).Chosen() {
						a.exportFlows(f, v.flows, strings.TrimSuffix(v.title, filepath.Ext(v.title)))
					}
				}
			})
		})
		ui.Divider(c)
		if v.height == 0 {
			v.height = 300
		}
		ui.SplitVertical(c, &v.height, func() {
			a.sessionTable(c, v)
		}, func() {
			var f *flow.Flow
			for _, x := range v.flows {
				if x.UniqueID == v.selected {
					f = x
				}
			}
			a.inspector(c, f, "session")
		}).Grow(1)
	})
}

func (a *App) sessionTable(c *ui.Context, v *sessionView) {
	p := a.pal
	if len(v.visible) == 0 {
		emptyState(c, p, map[bool]string{true: locales.NoFlows(), false: locales.NoFlowsMatch()}[len(v.flows) == 0])
		return
	}
	cols := []ui.TableColumn{
		{Title: "", ID: "dot", Width: 24, Fixed: true, Align: ui.Center},
		{Title: "#", Width: 44, Align: ui.End},
		{Title: locales.URL(), MinWidth: 240},
		{Title: locales.ColumnMethod(), Width: 80},
		{Title: locales.Status(), Width: 66},
		{Title: locales.Duration(), Width: 72, Align: ui.End},
		{Title: locales.PhaseResponse(), Width: 74, Align: ui.End},
	}
	v.list.Selected = &v.row
	v.list.Key = func(row int) any {
		if row >= 0 && row < len(v.visible) {
			return v.visible[row].UniqueID
		}
		return row
	}
	t := ui.Table(c.Key("sessionFlows"), &v.list, cols, len(v.visible), func(row, col int) {
		if row >= len(v.visible) {
			return
		}
		f := v.visible[row]
		sel := row == v.row
		fg := func(normal ui.Color) ui.Color {
			if sel {
				return p.onAccent
			}
			return normal
		}
		switch col {
		case 0:
			ui.Box(c).Size(7, 7).Radius(4).Background(statusDot(p, f))
		case 1:
			ui.Text(c, fmt.Sprint(row+1)).FontSize(11).TextColor(fg(p.muted)).FontFeatures("tnum")
		case 2:
			ui.Text(c, displayURL(f)).TextColor(fg(map[bool]ui.Color{true: p.link, false: p.text2}[f.IsHTTPS()])).SingleLine()
		case 3:
			mbg, mfg := p.methodColors(f.MethodName())
			ui.Text(c, f.MethodName()).FontSize(10).FontWeight(650).TextColor(mfg).Background(mbg).Padding(1, 5).Radius(4).SingleLine()
		case 4:
			if label := statusLabel(f); label != "" {
				bg, tc := p.flowColors(f)
				ui.Text(c, label).FontSize(10).FontWeight(650).TextColor(tc).Background(bg).Padding(1, 5).Radius(4).SingleLine()
			}
		case 5:
			ui.Text(c, flowDuration(f)).FontSize(11).TextColor(fg(p.muted)).FontFeatures("tnum")
		case 6:
			ui.Text(c, formatSize(f.ResponseBodySize())).FontSize(11).TextColor(fg(p.muted)).FontFeatures("tnum")
		}
	}).Grow(1).Label(locales.SavedFlows())
	if t.Changed() && v.row >= 0 && v.row < len(v.visible) {
		v.selected = v.visible[v.row].UniqueID
	}
}
