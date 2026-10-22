package app

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/codegen"
	"proxygo/internal/flow"
	"proxygo/internal/preview"
	"proxygo/internal/settings"
	"proxygo/internal/store"
	"proxygo/locales"
)

var flowColumns = []ui.TableColumn{
	{Title: "", ID: "dot", Width: 24, Fixed: true, Align: ui.Center},
	{Title: "#", ID: store.SortRow, Width: 44, Align: ui.End, Sortable: true},
	{Title: "URL", ID: store.SortURL, MinWidth: 240, Sortable: true},
	{Title: "Client", ID: store.SortClient, Width: 130, Sortable: true},
	{Title: "Method", ID: store.SortMethod, Width: 86, Sortable: true},
	{Title: "Status", ID: store.SortStatus, Width: 66, Sortable: true},
	{Title: "Code", ID: "code", Width: 120},
	{Title: "Time", ID: store.SortTime, Width: 92, Sortable: true},
	{Title: "Duration", ID: store.SortDuration, Width: 72, Align: ui.End, Sortable: true},
	{Title: "Request", ID: store.SortRequest, Width: 68, Align: ui.End, Sortable: true},
	{Title: "Response", ID: store.SortResponse, Width: 74, Align: ui.End, Sortable: true},
	{Title: "Protocol", ID: "protocol", Width: 64},
	{Title: "Host", ID: "host", Width: 160},
	{Title: "Path", ID: "path", Width: 200},
	{Title: "Content Type", ID: "contentType", Width: 140},
	{Title: "Server IP", ID: "serverIP", Width: 110},
	{Title: "SSL", ID: "ssl", Width: 42},
	{Title: "Edited", ID: "edited", Width: 56},
	{Title: "Comment", ID: store.SortComment, Width: 130, Sortable: true},
}

func (a *App) columnHidden(id string) bool {
	return slices.Contains(a.set.HiddenColumns, id)
}

func (a *App) toggleColumn(id string) {
	a.updateSettings(func(s *settings.Settings) {
		if i := slices.Index(s.HiddenColumns, id); i >= 0 {
			s.HiddenColumns = slices.Delete(s.HiddenColumns, i, i+1)
		} else {
			s.HiddenColumns = append(s.HiddenColumns, id)
		}
	})
}

func (a *App) columns() []ui.TableColumn {
	var cols []ui.TableColumn
	for _, col := range flowColumns {
		if a.columnHidden(col.ID) {
			continue
		}
		col.Title = flowColumnTitle(col)
		if col.ID == "dot" && !a.set.ShowSidebar {
			col.Width = 40
		}
		cols = append(cols, col)
	}
	for _, c := range a.set.Columns {
		cols = append(cols, ui.TableColumn{Title: c.Name, ID: c.ID(), Width: 140})
	}
	return cols
}

func (a *App) jwtExpired(f *flow.Flow) bool {
	key := "jwt|" + f.UniqueID
	if v, ok := a.colValues[key]; ok {
		return v != ""
	}
	v := ""
	if t := preview.FlowJWT(f); t != nil {
		at := f.RequestTime()
		if at.IsZero() {
			at = time.Now()
		}
		if t.Expired(at) {
			v = "expired"
		}
	}
	if a.colValues == nil || len(a.colValues) > 20000 {
		a.colValues = map[string]string{}
	}
	a.colValues[key] = v
	return v != ""
}

func (a *App) columnValue(f *flow.Flow, id string) string {
	key := fmt.Sprint(f.UniqueID, "|", id, "|", f.RequestSize(), "|", f.ResponseSize())
	if v, ok := a.colValues[key]; ok {
		return v
	}
	v := ""
	for _, c := range a.set.Columns {
		if c.ID() == id {
			v = c.Value(f)
			break
		}
	}
	if a.colValues == nil || len(a.colValues) > 20000 {
		a.colValues = map[string]string{}
	}
	a.colValues[key] = v
	return v
}

func (a *App) table(c *ui.Context) {
	p := a.pal
	cols := a.columns()
	a.list.Key = func(row int) any {
		if row >= 0 && row < len(a.visible) {
			return a.visible[row].UniqueID
		}
		return row
	}
	a.list.Label = func(row int) string {
		if row >= 0 && row < len(a.visible) {
			return a.visible[row].URL()
		}
		return ""
	}
	a.list.Selected = &a.row
	a.list.Selection = &a.chosen
	a.list.Sort = &a.sort
	a.list.FollowEnd = (a.sort.Column == "" || a.sort.Column == store.SortRow) && !a.sort.Descending
	a.list.HeaderMenu = func(m *ui.Menu, col int) { a.headerMenu(m) }

	t := ui.Table(c.Key("flows"), &a.list, cols, len(a.visible), func(row, col int) {
		a.cell(c, row, cols[col].ID)
	}).Grow(1).Label(locales.Flows())
	if t.Changed() {
		if a.row >= 0 && a.row < len(a.visible) {
			a.selected = a.visible[a.row].UniqueID
		}
		if !a.chosen.Has(a.selected) {
			a.selected = ""
			if i := slices.IndexFunc(a.visible, func(f *flow.Flow) bool { return a.chosen.Has(f.UniqueID) }); i >= 0 {
				a.selected = a.visible[i].UniqueID
			}
		}
		a.filterKey = ""
	}
	if t.Submitted() {
		if f := a.selectedFlow(); f != nil {
			a.openFlowWindow(f)
		}
	}
	if t.Shortcut(0, ui.KeyBackspace) || t.Shortcut(0, ui.KeyDelete) {
		a.deleteFlows(a.chosenFlows())
	}
	if t.Shortcut(ui.Cmd, ui.KeyC) {
		a.copyURLs(a.chosenFlows())
	}
	if len(a.visible) == 0 {
		a.emptyTable(c)
	}
	_ = p
}

func (a *App) emptyTable(c *ui.Context) {
	p := a.pal
	ui.Column(c).Absolute().Top(60).Left(0).Right(0).Bottom(0).Padding(0, 24).AlignItems(ui.Center).Gap(8).PassThrough().Children(func() {
		switch {
		case len(a.flows) > 0:
			glyph(c, "filter", 26, p.faint)
			ui.Text(c, locales.NoFlowsMatchTheFilters()).FontSize(14).FontWeight(600).TextColor(p.muted)
			if ui.Button(c, locales.ClearFilters()).Clicked() {
				a.clearFilters()
			}
		case a.proxyErr != "":
			glyph(c, "warning", 26, p.red)
			ui.Text(c, locales.ProxyGoIsNotListening()).FontSize(14).FontWeight(600).TextColor(p.text2)
			ui.Text(c, a.proxyErr).TextColor(p.muted).MaxWidth(520).TextAlign(ui.Center)
			if ui.Button(c, locales.ProxySettingsEllipsis()).Clicked() {
				a.settingsTab = 1
				a.openWindow("settings")
			}
		default:
			glyph(c, "network", 28, p.faint)
			ui.Text(c, locales.WaitingForTraffic()).FontSize(15).FontWeight(600).TextColor(p.text2)
			ui.Text(c, locales.PointAnAppOrDeviceAt(a.proxyAddress())).TextColor(p.muted)
			ui.Row(c).Gap(8).Children(func() {
				if !a.systemProxyOn() && ui.PrimaryButton(c, locales.OverrideMacOSProxy()).Clicked() {
					a.setSystemProxy(true)
				}
				if ui.Button(c, locales.InstallCertificateEllipsis()).Clicked() {
					a.openWindow("certificate")
				}
			})
			if a.paused {
				ui.Text(c, locales.RecordingIsPaused()).TextColor(p.yellow)
			}
		}
	})
}

func (a *App) headerMenu(m *ui.Menu) {
	m.Submenu(locales.Columns(), func(m *ui.Menu) {
		for _, col := range flowColumns {
			if col.ID == "dot" || col.ID == store.SortURL {
				continue
			}
			name := flowColumnTitle(col)
			if col.ID == store.SortRow {
				name = locales.IDColumn()
			}
			if m.Item(name).Checked(!a.columnHidden(col.ID)).Chosen() {
				a.toggleColumn(col.ID)
			}
		}
	})
	m.Submenu(locales.CustomColumns(), func(m *ui.Menu) {
		for i, c := range a.set.Columns {
			if m.Item(locales.RemoveColumn(columnLabel(c))).Chosen() {
				a.updateSettings(func(s *settings.Settings) { s.Columns = slices.Delete(s.Columns, i, i+1) })
			}
		}
		if len(a.set.Columns) > 0 {
			m.Separator()
		}
		if m.Item(locales.NewColumnEllipsis()).Chosen() {
			a.newColumn()
		}
		if f := a.selectedFlow(); f != nil && f.Request != nil {
			m.Submenu(locales.AddRequestHeader(), func(m *ui.Menu) {
				for _, e := range f.Request.Header.Entries {
					if m.Item(e.Key.Name).Chosen() {
						a.addHeaderColumn(e.Key.Name, false)
					}
				}
			})
			if f.Response != nil {
				m.Submenu(locales.AddResponseHeader(), func(m *ui.Menu) {
					for _, e := range f.Response.Header.Entries {
						if m.Item(e.Key.Name).Chosen() {
							a.addHeaderColumn(e.Key.Name, true)
						}
					}
				})
			}
		} else {
			m.Item(locales.SelectAFlowToAddIts()).Disabled(true)
		}
	})
	m.Separator()
	if m.Item(locales.ResetColumns()).Chosen() {
		a.updateSettings(func(s *settings.Settings) {
			s.HiddenColumns = slices.Clone(settings.DefaultHiddenColumns)
			s.HeaderColumns = nil
		})
		a.list.Columns = ui.TableLayout{}
	}
}

func (a *App) addHeaderColumn(name string, response bool) {
	a.addColumn(settings.Column{Name: name, Response: response, Source: settings.SourceHeader, Key: name})
}

func (a *App) addColumn(c settings.Column) bool {
	added := false
	a.updateSettings(func(s *settings.Settings) {
		if !slices.ContainsFunc(s.Columns, func(x settings.Column) bool { return x.ID() == c.ID() }) {
			s.Columns = append(s.Columns, c)
			added = true
		}
	})
	return added
}

func (a *App) cell(c *ui.Context, row int, col string) {
	if row < 0 || row >= len(a.visible) {
		return
	}
	p := a.pal
	f := a.visible[row]
	sel := a.chosen.Has(f.UniqueID)
	fg := func(normal ui.Color) ui.Color {
		if sel {
			return p.onAccent
		}
		return normal
	}
	dim := func(normal ui.Color) ui.Color {
		if sel {
			return p.onAccentMuted
		}
		return normal
	}
	hit := ui.Box(c).Absolute().Top(-6).Bottom(-6).Left(-8).Right(-8)
	if f.Highlight != "" && !sel {
		hit.Background(p.highlight(f.Highlight))
	}
	hit.ContextMenu(func(m *ui.Menu) { a.flowMenu(m, a.menuFlows(f)) })
	text := func(s string, color ui.Color) ui.Element {
		t := ui.Text(c, s).TextColor(color).SingleLine()
		if f.Strikethrough {
			t.Strikethrough()
		}
		return t
	}
	switch col {
	case "dot":
		dot := statusDot(p, f)
		if f.Highlight != "" {
			dot = p.swatch(f.Highlight)
		}
		ui.Box(c).Size(7, 7).Radius(4).Background(dot)
	case store.SortRow:
		text(f.ID, dim(p.muted)).FontSize(11).FontFeatures("tnum")
	case store.SortURL:
		ui.Row(c).Gap(5).AlignItems(ui.Center).Grow(1).Clip().Children(func() {
			if op := f.GraphQLOperation(); op != "" {
				chip(c, "GraphQL", fg(p.purple), sel, p.purpleSoft)
				text(op, fg(p.purple)).FontWeight(600)
			}
			if f.IsWebSocket() {
				chip(c, "WS", fg(p.blue), sel, p.blueSoft)
			}
			if a.jwtExpired(f) {
				chip(c, locales.JWTExpired(), fg(p.red), sel, p.redSoft)
			}
			color := p.text2
			if f.IsHTTPS() {
				color = p.link
			}
			text(displayURL(f), fg(color)).Grow(1)
		})
	case store.SortClient:
		ui.Row(c).AlignItems(ui.Center).Gap(5).Children(func() {
			switch bmp := a.appIcon(f.Client.Path); {
			case remoteIP(f) != "":
				ui.Icon(c, icon("device")).Size(13, 13).TextColor(dim(p.muted))
			case bmp != nil:
				ui.Image(c, bmp).Size(14, 14)
			default:
				ui.Icon(c, icon("appWindow")).Size(13, 13).TextColor(dim(p.faint))
			}
			text(a.clientLabel(f), fg(p.text2))
		})
	case store.SortMethod:
		mbg, mfg := p.methodColors(f.MethodName())
		ui.Text(c, f.MethodName()).FontSize(10).FontWeight(650).TextColor(mfg).Background(mbg).Padding(1, 5).Radius(4).SingleLine()
	case store.SortStatus:
		if label := statusLabel(f); label != "" {
			bg, tc := p.flowColors(f)
			if paused(f) != "" {
				bg, tc = p.purpleSoft, p.purple
			}
			ui.Text(c, label).FontSize(10).FontWeight(650).TextColor(tc).Background(bg).Padding(1, 5).Radius(4).SingleLine().Tooltip(f.StatusLine())
		}
	case "code":
		text(f.StatusLine(), dim(p.muted)).FontSize(11)
	case store.SortTime:
		text(flowTime(f), dim(p.muted)).FontSize(11).FontFeatures("tnum")
	case store.SortDuration:
		text(flowDuration(f), dim(p.muted)).FontSize(11).FontFeatures("tnum")
	case store.SortRequest:
		text(formatSize(f.RequestBodySize()), dim(p.muted)).FontSize(11).FontFeatures("tnum")
	case store.SortResponse:
		text(formatSize(f.ResponseBodySize()), dim(p.muted)).FontSize(11).FontFeatures("tnum")
	case "protocol":
		text(f.HTTPVersionLabel(), dim(p.muted)).FontSize(11)
	case "host":
		text(f.Host(), dim(p.text2)).FontSize(11)
	case "path":
		text(f.URLPath(), dim(p.text2)).FontSize(11)
	case "contentType":
		text(f.MIME(), dim(p.muted)).FontSize(11)
	case "serverIP":
		text(f.Summary.ServerIPAddress, dim(p.muted)).FontSize(11).FontFeatures("tnum")
	case "ssl":
		switch {
		case f.IsTunnel():
			ui.Icon(c, icon("lock")).Size(11, 11).TextColor(dim(p.faint)).Tooltip(locales.EncryptedSSLProxyingIsOffFor())
		case f.IsSSL:
			ui.Icon(c, icon("lockOpen")).Size(11, 11).TextColor(dim(p.green)).Tooltip(locales.DecryptedByProxyGo())
		}
	case "edited":
		ui.Row(c).Gap(3).AlignItems(ui.Center).Children(func() {
			for _, t := range tools(f) {
				ui.Icon(c, icon(toolIcon(t))).Size(11, 11).TextColor(dim(p.orange)).Tooltip(t)
			}
			if f.Saved {
				ui.Icon(c, icon("bookmark")).Size(11, 11).TextColor(dim(p.accent)).Tooltip(locales.Saved())
			}
		})
	case store.SortComment:
		text(f.Comment, dim(p.muted)).FontSize(11)
	default:
		if strings.HasPrefix(col, "header:") || strings.HasPrefix(col, "col:") {
			text(a.columnValue(f, col), dim(p.text2)).FontSize(11)
		}
	}
}

func chip(c *ui.Context, label string, color ui.Color, sel bool, bg ui.Color) {
	t := ui.Text(c, label).FontSize(9.5).FontWeight(700).TextColor(color).Padding(0, 4).Radius(3).SingleLine()
	if !sel {
		t.Background(bg)
	}
}

func statusDot(p palette, f *flow.Flow) ui.Color {
	code := f.StatusCode()
	switch {
	case paused(f) != "":
		return p.purple
	case f.IsActive():
		return p.yellow
	case f.IsIncomplete():
		return p.faint
	case f.IsError():
		return p.faint
	case code >= 500:
		return p.red
	case code >= 400:
		return p.orange
	case code >= 300:
		return p.blue
	case code >= 200, code == http.StatusSwitchingProtocols:
		return p.green
	}
	return p.faint
}

func (a *App) menuFlows(f *flow.Flow) []*flow.Flow {
	if a.chosen.Has(f.UniqueID) || a.selected == f.UniqueID {
		if fs := a.chosenFlows(); len(fs) > 0 {
			return fs
		}
	}
	a.selectFlow(f.UniqueID)
	return []*flow.Flow{f}
}

func (a *App) flowMenu(m *ui.Menu, fs []*flow.Flow) {
	f := fs[0]
	one := len(fs) == 1
	if m.Item(locales.CopyURL()).Shortcut(ui.Cmd|ui.Shift, ui.KeyU).Chosen() {
		a.copyURLs(fs)
	}
	if m.Item(locales.CopyAsCURL()).Shortcut(ui.Cmd|ui.Shift, ui.KeyC).Chosen() {
		a.copyCode(fs, "cURL")
	}
	m.Submenu(locales.CopyAs(), func(m *ui.Menu) {
		for _, l := range codegen.Languages {
			if m.Item(l.Name).Chosen() {
				a.copyCode(fs, l.Name)
			}
		}
		m.Separator()
		if m.Item("Markdown").Chosen() {
			a.copyMarkdown(fs)
		}
		m.Submenu(locales.ExportCodeToFile(), func(m *ui.Menu) {
			for _, l := range codegen.Languages {
				if m.Item(l.Name + "…").Disabled(!one).Chosen() {
					a.exportCode(f, l.Name)
				}
			}
		})
		m.Separator()
		if m.Item(locales.RawRequestLabel()).Disabled(!one).Chosen() {
			a.copyRaw(f, false)
		}
		if m.Item(locales.RawResponseLabel()).Disabled(!one || f.Response == nil).Chosen() {
			a.copyRaw(f, true)
		}
		if m.Item(locales.ResponseBodyLabel()).Disabled(!one || f.Response == nil).Chosen() {
			a.copy(string(f.DecodedResponseBody()), locales.CopiedTheResponseBody())
		}
	})
	m.Separator()
	if m.Item(locales.Repeat()).Shortcut(ui.Cmd, ui.KeyR).Chosen() {
		a.repeatFlows(fs)
	}
	if m.Item(locales.EditAndRepeatEllipsis()).Shortcut(ui.Cmd, ui.KeyE).Disabled(!one).Chosen() {
		a.composeFrom(f)
	}
	if m.Item(locales.AdvancedRepeatEllipsis()).Chosen() {
		a.advancedRepeat(fs)
	}
	m.Separator()
	if f.IsHTTPS() && (f.IsTunnel() || !a.rules.Current().ShouldMITM(f.Host())) {
		if m.Item(locales.EnableSSLProxyingForHost(f.Host())).Chosen() {
			a.enableSSL(f.Host(), false)
		}
	}
	m.Submenu(locales.Tools(), func(m *ui.Menu) {
		if m.Item(locales.BreakpointEllipsis()).Chosen() {
			a.breakpointFromFlow(f)
		}
		if m.Item(locales.MapLocalEllipsis()).Chosen() {
			a.mapLocalFromFlow(f)
		}
		if m.Item(locales.MapRemoteEllipsis()).Chosen() {
			a.mapRemoteFromFlow(f)
		}
		if m.Item(locales.ScriptingEllipsis()).Chosen() {
			a.scriptFromFlow(f)
		}
		if m.Item(locales.NetworkConditionsEllipsis()).Chosen() {
			a.throttleFromFlow(f)
		}
		m.Separator()
		if m.Item(locales.ToolBlockList()).Chosen() {
			a.blockFromFlow(f, false)
		}
		if m.Item(locales.ToolAllowList()).Chosen() {
			a.blockFromFlow(f, true)
		}
		if m.Item(map[bool]string{true: locales.BlockThisDevice(a.clientLabel(f)), false: locales.BlockThisApp(a.clientLabel(f))}[remoteIP(f) != ""]).Disabled(f.Client.Name == "" || f.Client.Name == "System").Chosen() {
			a.blockApp(f, false)
		}
		if m.Item(locales.ProtobufMessageTypesEllipsis()).Chosen() {
			a.openWindow("protobuf")
		}
	})
	m.Submenu(locales.Filter(), func(m *ui.Menu) {
		if m.Item(locales.OnlyValue(f.Host())).Chosen() {
			a.filterBy(store.Condition{Enabled: true, Field: store.FieldHost, Op: store.OpEquals, Value: f.Host()})
		}
		if m.Item(locales.OnlyValue(a.clientLabel(f))).Chosen() {
			a.filterBy(store.Condition{Enabled: true, Field: store.FieldClient, Op: store.OpEquals, Value: f.Client.Name})
		}
		if m.Item(locales.OnlyMethodRequests(f.MethodName())).Chosen() {
			a.filterBy(store.Condition{Enabled: true, Field: store.FieldMethod, Op: store.OpEquals, Value: f.MethodName()})
		}
		if code := f.StatusCode(); code > 0 && m.Item(locales.OnlyStatus(strconv.Itoa(code))).Chosen() {
			a.filterBy(store.Condition{Enabled: true, Field: store.FieldStatus, Op: store.OpEquals, Value: fmt.Sprint(code)})
		}
	})
	m.Submenu(locales.Pin(), func(m *ui.Menu) {
		host, app := "host:"+f.Host(), "app:"+clientName(f)
		if m.Item(map[bool]string{true: locales.UnpinValue(f.Host()), false: locales.PinHost(f.Host())}[a.pinned(host)]).Chosen() {
			a.togglePin(host)
		}
		if m.Item(map[bool]string{true: locales.UnpinValue(a.clientLabel(f)), false: locales.PinHost(a.clientLabel(f))}[a.pinned(app)]).Chosen() {
			a.togglePin(app)
		}
	})
	m.Separator()
	if m.Item(locales.AddCommentEllipsis()).Shortcut(ui.Cmd|ui.Shift, ui.KeyM).Chosen() {
		a.editComment(fs)
	}
	m.Submenu(locales.Highlight(), func(m *ui.Menu) {
		for _, color := range highlightColors {
			if m.Item(colorName(color)).Checked(f.Highlight == color).Chosen() {
				a.setHighlight(fs, color)
			}
		}
		m.Separator()
		if m.Item(locales.Strikethrough()).Checked(f.Strikethrough).Chosen() {
			a.setStrike(fs, !f.Strikethrough)
		}
		if m.Item(locales.Reset()).Chosen() {
			a.resetStyle(fs)
		}
	})
	if m.Item(locales.SaveRequest()).Checked(f.Saved).Shortcut(ui.Cmd, ui.KeyD).Chosen() {
		a.setSaved(fs, !f.Saved)
	}
	m.Separator()
	if len(fs) == 2 {
		if m.Item(locales.Compare()).Shortcut(ui.Cmd|ui.Shift, ui.KeyD).Chosen() {
			a.compare(fs[0], fs[1])
		}
	} else {
		m.Submenu(locales.Compare(), func(m *ui.Menu) {
			if m.Item(locales.SetAsLeftSide()).Disabled(!one).Chosen() {
				a.setDiffSide(f, false)
			}
			if m.Item(locales.SetAsRightSide()).Disabled(!one).Chosen() {
				a.setDiffSide(f, true)
			}
		})
	}
	if m.Item(locales.OpenInNewWindow()).Disabled(!one).Chosen() {
		a.openFlowWindow(f)
	}
	m.Submenu(locales.Export(), func(m *ui.Menu) {
		if m.Item(locales.AsProxyGoSessionEllipsis()).Chosen() {
			a.saveSessionDialog(true)
		}
		if m.Item(locales.AsHAREllipsis()).Chosen() {
			a.exportDialog("har", true)
		}
		if m.Item(locales.AsCSVEllipsis()).Chosen() {
			a.exportDialog("csv", true)
		}
		if m.Item(locales.RequestBodyEllipsis()).Disabled(!one).Chosen() {
			a.exportBody(f, false)
		}
		if m.Item(locales.ResponseBodyEllipsis()).Disabled(!one || f.Response == nil).Chosen() {
			a.exportBody(f, true)
		}
		m.Separator()
		for _, fm := range []string{"postman", "openapi", "openapi-html", "raw"} {
			if m.Item(locales.AsFormatEllipsis(exportTitle(fm))).Chosen() {
				a.exportFlows(fm, fs, "ProxyGo_"+time.Now().Format("2006-01-02_15-04-05"))
			}
		}
	})
	if m.Item(locales.SaveToFolderEllipsis()).Shortcut(ui.Cmd|ui.Alt, ui.KeyD).Chosen() {
		a.saveToFolder(fs)
	}
	if m.Item(locales.AddToDiffPool()).Chosen() {
		a.addToDiffPool(fs)
	}
	m.Separator()
	if m.Item(locales.DeleteFlowsMenu(len(fs))).Shortcut(0, ui.KeyBackspace).Chosen() {
		a.deleteFlows(fs)
	}
}

func (a *App) newColumn() {
	a.colEdit = columnEditor{open: true, col: settings.Column{Source: settings.SourceHeader}}
}
