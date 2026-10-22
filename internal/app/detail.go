package app

import (
	"cmp"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/preview"
	"proxygo/locales"
)

var (
	reqTabs  = []string{"Header", "Query", "Body", "Raw", "Cookies", "Summary", "Comment", "Timing"}
	respTabs = []string{"Header", "Body", "Raw", "Set-Cookie", "TLS"}
	wsTabs   = []string{"Messages", "Header", "Raw", "TLS"}
)

func requestTabs(f *flow.Flow) []string {
	tabs := slices.Clone(reqTabs)
	if preview.FlowJWT(f) != nil {
		tabs = slices.Insert(tabs, 2, "JWT")
	}
	if f.Request == nil || f.Request.Header.Get("Cookie") == "" {
		tabs = slices.DeleteFunc(tabs, func(t string) bool { return t == "Cookies" })
	}
	return tabs
}

func responseTabs(base []string, f *flow.Flow) []string {
	return slices.DeleteFunc(slices.Clone(base), func(t string) bool {
		return t == "TLS" && f.TLS == nil || t == "Set-Cookie" && (f.Response == nil || f.Response.Header.Get("Set-Cookie") == "")
	})
}

func (a *App) detail(c *ui.Context) {
	f := a.selectedFlow()
	a.inspector(c, f, "main")
}

func (a *App) inspector(c *ui.Context, f *flow.Flow, scope string) {
	p := a.pal
	ui.Column(c.Key(scope)).Fill().Background(p.bg).Children(func() {
		if f == nil {
			centered(c, 6, func() {
				glyph(c, "inspect", 26, p.faint)
				ui.Text(c, locales.SelectAFlowToInspectIt()).FontSize(13).TextColor(p.muted)
			})
			return
		}
		a.summaryBar(c, f)
		ui.Divider(c)
		req := func() { a.requestPane(c, f) }
		resp := func() { a.responsePane(c, f) }
		if a.set.StackedDetail || a.set.DetailRight {
			ui.SplitVerticalPercent(c, &a.set.DetailPercent, req, resp).Grow(1)
		} else {
			ui.SplitPercent(c, &a.set.DetailPercent, req, resp).Grow(1)
		}
	})
}

func (a *App) summaryBar(c *ui.Context, f *flow.Flow) {
	p := a.pal
	ui.Row(c).Height(38).FillWidth().Padding(0, inset).Gap(8).AlignItems(ui.Center).Children(func() {
		mbg, mfg := p.methodColors(f.MethodName())
		ui.Text(c, f.MethodName()).FontSize(10.5).FontWeight(650).TextColor(mfg).Background(mbg).Padding(2, 7).Radius(5).SingleLine()
		bg, tc := p.flowColors(f)
		label, tip := f.StatusLine(), ""
		if f.IsError() && !f.IsIncomplete() {
			label, tip = locales.Failed(), f.ErrorText()
		}
		ui.Text(c, label).Tooltip(tip).FontSize(10.5).FontWeight(650).TextColor(tc).Background(bg).Padding(2, 7).Radius(5).SingleLine()
		if op := f.GraphQLOperation(); op != "" {
			ui.Text(c, locales.GraphQLChip(op)).FontSize(10.5).FontWeight(650).TextColor(p.purple).Background(p.purpleSoft).Padding(2, 7).Radius(5).SingleLine()
		}
		ui.Text(c, displayURL(f)).TextColor(p.link).SingleLine().Selectable().Grow(1).Shrink(1).ClipX()
		for _, t := range tools(f) {
			ui.Row(c).Gap(3).AlignItems(ui.Center).Padding(2, 6).Radius(5).Background(p.surface).Tooltip(locales.ChangedBy(flowToolName(t))).Children(func() {
				glyph(c, toolIcon(t), 11, p.orange)
				ui.Text(c, flowToolName(t)).FontSize(10.5).TextColor(p.text2).SingleLine()
			})
		}
		if !f.IsTunnel() && !f.IsWebSocket() {
			if iconButton(c, "repeat", locales.RepeatShortcut(), p.text2).Clicked() {
				a.repeatFlows([]*flow.Flow{f})
			}
			if iconButton(c, "compose", locales.EditAndRepeatShortcut(), p.text2).Clicked() {
				a.composeFrom(f)
			}
		}
		saved := iconButton(c, map[bool]string{true: "bookmarkFill", false: "bookmark"}[f.Saved], locales.SaveRequestShortcut(), map[bool]ui.Color{true: p.accent, false: p.text2}[f.Saved])
		if saved.Clicked() {
			a.setSaved([]*flow.Flow{f}, !f.Saved)
		}
		more := iconButton(c, "ellipsis", locales.More(), p.text2)
		more.Menu(func(m *ui.Menu) { a.flowMenu(m, []*flow.Flow{f}) })
	})
	if f.Comment != "" {
		ui.Row(c).FillWidth().Padding(0, inset, 6, inset).Gap(6).AlignItems(ui.Center).Children(func() {
			glyph(c, "comment", 12, p.muted)
			ui.Text(c, f.Comment).TextColor(p.muted).SingleLine().Grow(1)
		})
	}
}

func tabNamed(name *string, tabs []string) *int {
	i := max(slices.Index(tabs, *name), 0)
	return &i
}

func paneHeader(c *ui.Context, p palette, title string, tab *int, tabs []string, extra func()) {
	row := ui.Row(c).Height(34).FillWidth().Padding(0, inset).Gap(10).AlignItems(ui.Center)
	row.Children(func() {
		ui.Text(c, title).FontWeight(650).TextColor(p.text).Width(62).Shrink(0)
		if len(tabs) > 0 {
			if *tab >= len(tabs) {
				*tab = 0
			}
			scroll := ui.Local(row, "tabs", func() ui.ScrollState { return ui.ScrollState{} })
			ui.ScrollHorizontal(c).TrackScroll(scroll).Shrink(1).Children(func() {
				ui.Tabs(c, tab, inspectorTabLabels(tabs)...).Label(locales.PaneTabs(title))
			})
			if scroll.MaxX > 0 {
				more := plainIconButton(c, "chevronDown", locales.AllPaneTabs(title), 10, p.muted, p.hover)
				more.Menu(func(m *ui.Menu) {
					for i, name := range tabs {
						if m.Item(inspectorTabLabel(name)).Checked(i == *tab).Chosen() {
							*tab = i
							x := scroll.MaxX * float32(i) / float32(max(len(tabs)-1, 1))
							if i == len(tabs)-1 {
								x = math.MaxFloat32
							}
							scroll.ScrollTo(x, 0, ui.Smooth)
						}
					}
				})
			}
		}
		ui.Spacer(c)
		if extra != nil {
			extra()
		}
	})
	ui.Divider(c)
}

func (a *App) requestPane(c *ui.Context, f *flow.Flow) {
	p := a.pal
	ui.Column(c.Key("request")).Fill().Children(func() {
		tabs := requestTabs(f)
		tab := tabNamed(&a.reqTabName, tabs)
		paneHeader(c, p, locales.PhaseRequest(), tab, tabs, nil)
		a.reqTabName = tabs[*tab]
		switch a.reqTabName {
		case "JWT":
			a.jwtView(c, f.UniqueID+":jwt", preview.BearerToken(f.Request.Header))
		case "Header":
			a.headerTable(c, f.Request.Header, "request")
		case "Query":
			a.pairsTable(c, f.QueryItems(), locales.Parameter(), locales.Value(), locales.NoQueryParameters(), "")
		case "Body":
			a.bodyView(c, f, false, "")
		case "Raw":
			a.textViewer(c, f.UniqueID+":rawreq", rawRequest(f), "HTTP", locales.RawRequest())
		case "Cookies":
			var rows [][2]string
			for _, ck := range f.Cookies() {
				rows = append(rows, [2]string{ck.Name, ck.Value})
			}
			a.pairsTable(c, rows, locales.ColumnName(), locales.Value(), locales.NoCookies(), "")
		case "Summary":
			a.summary(c, f)
		case "Comment":
			a.commentTab(c, f)
		case "Timing":
			a.timing(c, f)
		}
	})
}

func (a *App) responsePane(c *ui.Context, f *flow.Flow) {
	p := a.pal
	tabs := responseTabs(respTabs, f)
	if f.IsWebSocket() && f.Response != nil && f.StatusCode() == http.StatusSwitchingProtocols {
		tabs = responseTabs(wsTabs, f)
	}
	ui.Column(c.Key("response")).Fill().Children(func() {
		show := f.Response != nil && !f.IsTunnel() && !f.IsError() && paused(f) == ""
		tab := tabNamed(&a.respTabName, tabs)
		if show {
			paneHeader(c, p, locales.PhaseResponse(), tab, tabs, nil)
			a.respTabName = tabs[*tab]
		} else {
			paneHeader(c, p, locales.PhaseResponse(), tab, nil, nil)
		}
		switch {
		case paused(f) != "":
			a.pausedPane(c, f)
			return
		case f.IsTunnel() && (!f.IsError() || f.IsIncomplete()):
			a.encryptedPane(c, f)
			return
		case f.IsError():
			a.errorPane(c, f)
			return
		case f.IsActive():
			centered(c, 8, func() {
				ui.Spinner(c)
				ui.Text(c, locales.WaitingForTheResponse()).TextColor(p.muted)
				ui.Text(c, locales.StartedAgo(time.Since(f.RequestTime()).Round(time.Second).String())).FontSize(11).TextColor(p.faint)
			})
			c.After(time.Second)
			return
		}
		switch tabs[*tab] {
		case "Messages":
			a.messages(c, f)
		case "Header":
			a.headerTable(c, f.Response.Header, "response")
		case "Body":
			a.bodyView(c, f, true, "")
		case "Raw":
			a.textViewer(c, f.UniqueID+":rawres:"+fmt.Sprint(len(f.Response.BodyData)), rawResponse(f), "HTTP", locales.RawResponse())
		case "Set-Cookie":
			a.setCookies(c, f)
		case "TLS":
			a.tlsView(c, f)
		}
	})
}

func (a *App) headerTable(c *ui.Context, h flow.Header, side string) {
	var rows [][2]string
	for _, e := range h.Entries {
		if e.Enabled {
			rows = append(rows, [2]string{e.Key.Name, e.Value})
		}
	}
	a.pairsTable(c, rows, locales.ColumnKey(), locales.Value(), locales.NoHeaders(), side)
}

func (a *App) pairsTable(c *ui.Context, rows [][2]string, keyTitle, valueTitle, empty, side string) {
	p := a.pal
	if len(rows) == 0 {
		emptyState(c, p, empty)
		return
	}
	ui.Table(c, nil, []ui.TableColumn{{Title: keyTitle, Width: 200}, {Title: valueTitle}}, len(rows), func(row, col int) {
		r := rows[row]
		ui.Box(c).Absolute().Top(-6).Bottom(-6).Left(-8).Right(-8).ContextMenu(func(m *ui.Menu) {
			if m.Item(locales.CopyValue()).Chosen() {
				a.copy(r[1], locales.CopiedTheValue())
			}
			if m.Item(locales.CopyKey()).Chosen() {
				a.copy(r[0], locales.CopiedTheKey())
			}
			if m.Item(locales.CopyAsKeyValue()).Chosen() {
				a.copy(r[0]+": "+r[1], locales.CopiedTheLine())
			}
			if side != "" {
				m.Separator()
				if m.Item(locales.ShowAsAColumn(r[0])).Chosen() {
					a.addHeaderColumn(r[0], side == "response")
				}
			}
		})
		if col == 0 {
			ui.Text(c, r[0]).TextColor(p.text2).FontWeight(500).SingleLine()
		} else {
			ui.Text(c, r[1]).TextColor(p.text).Selectable().Wrap().MinWidth(0).Shrink(1)
		}
	}).Grow(1).Label(keyTitle)
}

func maxAgeText(sec int) string {
	switch {
	case sec < 60:
		return locales.DurationSeconds(sec)
	case sec < 3600:
		return locales.DurationMinutes(sec / 60)
	case sec < 86400:
		return locales.DurationHours(sec / 3600)
	}
	return locales.DurationDays(sec / 86400)
}

func (a *App) setCookies(c *ui.Context, f *flow.Flow) {
	p := a.pal
	cookies := f.SetCookies()
	if len(cookies) == 0 {
		emptyState(c, p, locales.NoCookiesSet())
		return
	}
	cols := []ui.TableColumn{{Title: locales.ColumnName(), Width: 130}, {Title: locales.Value()}, {Title: locales.Expires(), Width: 130}, {Title: locales.Attributes()}}
	ui.Table(c, nil, cols, len(cookies), func(row, col int) {
		ck := cookies[row]
		var s string
		color := p.text
		switch col {
		case 0:
			s = ck.Name
		case 1:
			s = ck.Value
		case 2:
			switch {
			case !ck.Expires.IsZero():
				s = ck.Expires.Local().Format("2006-01-02 15:04")
			case ck.MaxAge > 0:
				s = locales.InDuration(maxAgeText(ck.MaxAge))
			default:
				s = locales.SessionCookie()
			}
		case 3:
			var attrs []string
			if ck.Domain != "" {
				attrs = append(attrs, "Domain="+ck.Domain)
			}
			if ck.Path != "" {
				attrs = append(attrs, "Path="+ck.Path)
			}
			if ck.HttpOnly {
				attrs = append(attrs, "HttpOnly")
			}
			if ck.Secure {
				attrs = append(attrs, "Secure")
			}
			switch ck.SameSite {
			case http.SameSiteLaxMode:
				attrs = append(attrs, "SameSite=Lax")
			case http.SameSiteStrictMode:
				attrs = append(attrs, "SameSite=Strict")
			case http.SameSiteNoneMode:
				attrs = append(attrs, "SameSite=None")
			}
			s, color = strings.Join(attrs, "; "), p.text2
		}
		ui.Text(c, s).TextColor(color).SingleLine().Selectable()
	}).Grow(1).Label("Set-Cookie")
}

func (a *App) summary(c *ui.Context, f *flow.Flow) {
	p := a.pal
	type row struct{ k, v string }
	addr := func(ip string, port int) string {
		if ip == "" {
			return ""
		}
		if port == 0 {
			return ip
		}
		return fmt.Sprintf("%s:%d", ip, port)
	}
	tls := locales.No()
	switch {
	case f.IsTunnel():
		tls = locales.EncryptedTunnelNotDecrypted()
	case f.IsSSL:
		tls = locales.DecryptedByProxyGo()
	}
	dns := ""
	if f.Summary.HostDNS != nil {
		dns = *f.Summary.HostDNS
	}
	rows := []row{
		{"URL", displayURL(f)},
		{locales.ColumnMethod(), f.MethodName()},
		{locales.Status(), f.StatusLine()},
		{locales.Protocol(), f.Request.Version.HTTPVersion()},
		{locales.Client(), a.clientLabel(f) + cmp.Or(map[bool]string{true: fmt.Sprintf(" (PID %d)", f.Client.PID)}[f.Client.PID > 0], "")},
		{locales.Source(), map[bool]string{true: locales.RemoteDevice(remoteIP(f))}[remoteIP(f) != ""]},
		{locales.ClientPath(), f.Client.Path},
		{locales.ClientAddress(), addr(f.Summary.ClientIPAddress, f.Summary.ClientPort)},
		{locales.ServerAddress(), addr(f.Summary.ServerIPAddress, f.Summary.ServerPort)},
		{locales.Resolved(), dns},
		{"TLS", tls},
		{locales.Started(), f.RequestTime().Local().Format("2006-01-02 15:04:05.000")},
		{locales.Duration(), flowDuration(f)},
		{locales.RequestSize(), formatSize(f.RequestSize())},
		{locales.ResponseSize(), formatSize(f.ResponseSize())},
		{locales.ContentType(), f.ContentType()},
		{locales.Tools(), strings.Join(flowToolNames(tools(f)), ", ")},
		{locales.GraphQLOperation(), f.GraphQLOperation()},
		{locales.Error(), f.ErrorText()},
	}
	if f.ConnectionRecord != nil && f.ConnectionRecord.Exchange.Truncated {
		rows = append(rows, row{locales.Note(), locales.TheBodyWasTruncated()})
	}
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(inset).Children(func() {
			ui.Form(c, func() {
				for _, r := range rows {
					if r.v == "" || r.v == "–" && r.k != locales.Duration() {
						continue
					}
					ui.Field(c, r.k, func() {
						ui.Text(c, r.v).TextColor(p.text).Selectable().Wrap()
					})
				}
			})
		})
	})
}

func (a *App) commentTab(c *ui.Context, f *flow.Flow) {
	p := a.pal
	if a.comment.draftFor != f.UniqueID {
		a.comment.draftFor = f.UniqueID
		a.comment.draft = f.Comment
	}
	ui.Column(c).Fill().Padding(inset).Gap(8).Children(func() {
		ui.TextArea(c, &a.comment.draft).Placeholder(locales.WriteANoteAboutThisFlow()).Grow(1).Label(locales.Comment())
		ui.Row(c).Gap(8).Children(func() {
			ui.Text(c, locales.CommentsAreSavedWithTheSession()).FontSize(11).TextColor(p.muted).Grow(1)
			if ui.PrimaryButton(c, locales.SaveComment()).Disabled(a.comment.draft == f.Comment).Clicked() {
				text := strings.TrimSpace(a.comment.draft)
				a.store.Update(f.UniqueID, func(s *flow.Flow) { s.Comment = text })
			}
		})
	})
}

func (a *App) timing(c *ui.Context, f *flow.Flow) {
	p := a.pal
	t := f.Timing
	if t.RequestStartedAt == nil {
		emptyState(c, p, locales.NoTimingForThisFlow())
		return
	}
	start := *t.RequestStartedAt
	type phase struct {
		name       string
		from, to   *float64
		color      ui.Color
		annotation string
	}
	phases := []phase{
		{locales.ClientTLSHandshake(), t.ClientTLSStartedAt, t.ClientTLSEndedAt, p.purple, ""},
		{locales.ConnectToServer(), t.UpstreamConnectStartedAt, t.UpstreamConnectEndedAt, p.orange, ""},
		{locales.TLSHandshakeWithServer(), t.UpstreamTLSStartedAt, t.UpstreamTLSEndedAt, p.purple, ""},
		{locales.RequestSent(), t.RequestStartedAt, t.RequestEndedAt, p.blue, ""},
		{locales.WaitingTTFB(), t.RequestEndedAt, t.ResponseStartedAt, p.green, ""},
		{locales.ContentDownload(), t.ResponseStartedAt, t.ResponseEndedAt, p.accent, ""},
	}
	end := start
	if t.ResponseEndedAt != nil {
		end = *t.ResponseEndedAt
	}
	for _, ph := range phases {
		if ph.to != nil {
			end = max(end, *ph.to)
		}
	}
	total := max(end-start, 0.000001)
	if t.ClientTLSStartedAt != nil && *t.ClientTLSStartedAt < start {
		start = *t.ClientTLSStartedAt
		total = max(end-start, 0.000001)
	}
	reused := f.ConnectionRecord != nil && f.ConnectionRecord.Exchange.Reused
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(inset).Gap(10).Children(func() {
			for _, ph := range phases {
				if ph.from == nil || ph.to == nil || *ph.to < *ph.from {
					continue
				}
				dur := time.Duration((*ph.to - *ph.from) * float64(time.Second))
				left := float32((*ph.from - start) / total)
				width := max(float32((*ph.to-*ph.from)/total), 0.004)
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, ph.name).TextColor(p.text2).Width(170).SingleLine()
					ui.Box(c).Height(10).Grow(1).Radius(3).Background(p.surface).Children(func() {
						ui.Box(c).Absolute().Top(0).Bottom(0).LeftPercent(left * 100).WidthPercent(min(width, 1-left) * 100).Radius(3).Background(ph.color)
					})
					ui.Text(c, formatDuration(dur)).TextColor(p.muted).FontFeatures("tnum").Width(70).TextAlign(ui.End)
				})
			}
			ui.Divider(c)
			ui.Row(c).Gap(10).Children(func() {
				ui.Text(c, locales.Total()).FontWeight(600).Width(170)
				ui.Spacer(c)
				ui.Text(c, flowDuration(f)).FontWeight(600).FontFeatures("tnum")
			})
			note := locales.NewConnectionToTheServer()
			switch by := answeredBy(f); {
			case by != "":
				note = locales.AnsweredBy(by)
			case reused:
				note = locales.ReusedAnOpenConnection()
			}
			if ms, ok := toolMeta(f, "dnsLookup").(float64); ok {
				note += " · " + locales.DNSLookupMs(fmt.Sprintf("%.1f", ms))
			}
			ui.Text(c, note).FontSize(11).TextColor(p.muted)
		})
	})
}

func answeredBy(f *flow.Flow) string {
	for _, t := range []struct{ key, name string }{
		{"mapLocal", locales.ToolMapLocal()}, {"mockAPI", locales.AScriptsMock()}, {"breakpointResponse", locales.ABreakpoint()},
		{"block", locales.TheBlockList()}, {"blockedApp", locales.BlockedApps()},
	} {
		if toolMeta(f, t.key) != nil {
			return t.name
		}
	}
	return ""
}

func toolMeta(f *flow.Flow, key string) any {
	m, _ := f.ToolMetadata.(map[string]any)
	return m[key]
}

func (a *App) encryptedPane(c *ui.Context, f *flow.Flow) {
	p := a.pal
	host := f.Host()
	centered(c, 10, func() {
		glyph(c, "lock", 26, p.faint)
		ui.Text(c, locales.EncryptedHTTPS()).FontSize(16).FontWeight(650).TextColor(p.text2)
		if a.rules.Current().ShouldMITM(host) {
			ui.Text(c, locales.SSLProxyingIsNowOnFor(host)).TextColor(p.muted).TextAlign(ui.Center).MaxWidth(420)
			if ui.Button(c, locales.ComposeRequestEllipsis()).Clicked() {
				a.composeFrom(f)
			}
			return
		}
		ui.Text(c, locales.EnableSSLProxyingToSeeThe()).TextColor(p.muted).TextAlign(ui.Center)
		ui.Row(c).Gap(8).Wrap().Justify(ui.Center).AlignItems(ui.Center).Children(func() {
			only := ui.PrimaryButton(c, locales.EnableOnlyHost(host)).Tooltip(locales.EnableOnlyThisDomainShortcut())
			if only.Clicked() || c.Shortcut(ui.Alt, ui.KeyEnter) {
				a.enableSSL(host, false)
			}
			ui.Text(c, locales.Or()).TextColor(p.muted)
			if name := a.clientLabel(f); name != "System" {
				if ui.Button(c, locales.EnableAllDomainsFrom(name)).Clicked() {
					a.enableSSLForClient(f)
				}
			} else if ui.Button(c, locales.EnableAllDomains()).Clicked() {
				a.enableSSL(host, true)
			}
		})
		if !a.certTrusted {
			ui.Row(c).Gap(8).Wrap().Justify(ui.Center).AlignItems(ui.Center).Margin(4, 0, 0, 0).Children(func() {
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					glyph(c, "warning", 12, p.yellow)
					ui.Text(c, locales.ThisMacDoesNotTrustTheLabel()).FontSize(11).TextColor(p.yellow)
				})
				ui.Button(c, locales.InstallCertificateEllipsis()).OnClick(func() { a.openWindow("certificate") })
			})
		}
	})
}

func (a *App) errorPane(c *ui.Context, f *flow.Flow) {
	p := a.pal
	msg := f.ErrorText()
	centered(c, 10, func() {
		if f.IsIncomplete() {
			glyph(c, "clock", 26, p.faint)
			ui.Text(c, locales.Incomplete()).FontSize(16).FontWeight(650).TextColor(p.text2)
		} else {
			glyph(c, "warning", 26, p.red)
			ui.Text(c, locales.TheRequestFailed()).FontSize(16).FontWeight(650).TextColor(p.text2)
		}
		ui.Text(c, msg).TextColor(p.muted).TextAlign(ui.Center).Selectable().MaxWidth(520)
		if t := f.TLS; t != nil && t.Client != nil && t.Client.Error != "" {
			details := []string{}
			if t.Client.ServerName != "" {
				details = append(details, locales.ServerName(t.Client.ServerName))
			}
			if len(t.Client.Offered) > 0 {
				details = append(details, "ALPN "+strings.Join(t.Client.Offered, ", "))
			}
			if len(details) > 0 {
				ui.Text(c, strings.Join(details, " · ")).FontSize(11).TextColor(p.faint).Selectable()
			}
			if t.Client.PinningLikely {
				ui.Row(c).Gap(8).Wrap().Justify(ui.Center).Children(func() {
					if ui.Button(c, locales.ExcludeFromSSLProxying(f.Host())).Tooltip(locales.TunnelThisHostWithoutDecryptingIt()).Clicked() {
						a.excludeSSL(f.Host())
					}
					if !a.certTrusted {
						ui.Button(c, locales.InstallCertificateEllipsis()).OnClick(func() { a.openWindow("certificate") })
					}
				})
			}
		}
		ui.Row(c).Gap(8).Children(func() {
			if !f.IsTunnel() && f.MethodName() != http.MethodConnect {
				if ui.Button(c, locales.Repeat()).Clicked() {
					a.repeatFlows([]*flow.Flow{f})
				}
			}
			if !f.IsIncomplete() && ui.Button(c, locales.CopyError()).Clicked() {
				a.copy(msg, locales.CopiedTheError())
			}
		})
	})
}

func (a *App) pausedPane(c *ui.Context, f *flow.Flow) {
	p := a.pal
	centered(c, 10, func() {
		glyph(c, "bug", 26, p.purple)
		ui.Text(c, map[bool]string{true: locales.PausedAtAResponseBreakpoint(), false: locales.PausedAtARequestBreakpoint()}[paused(f) == "response"]).FontSize(16).FontWeight(650).TextColor(p.text2)
		ui.Text(c, locales.EditItThenLetItGo()).TextColor(p.muted).TextAlign(ui.Center)
		if ui.PrimaryButton(c, locales.OpenBreakpointEditor()).Clicked() {
			a.openWindow("bpedit")
		}
	})
}

type wsView struct {
	showPings bool
	direction int
	query     string
	draft     string
	toClient  int
}

func (a *App) messages(c *ui.Context, f *flow.Flow) {
	p := a.pal
	v := &a.ws
	var all []flow.WebSocketMessage
	if f.WebSocketMessageStorage != nil {
		all = f.WebSocketMessageStorage.Messages
	}
	q := strings.ToLower(v.query)
	var msgs []flow.WebSocketMessage
	pings := 0
	for _, m := range all {
		if m.Type == "ping" || m.Type == "pong" {
			pings++
			if !v.showPings {
				continue
			}
		}
		if v.direction == 1 && m.From != "client" || v.direction == 2 && m.From != "server" {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(m.Data), q) {
			continue
		}
		msgs = append(msgs, m)
	}
	open := a.proxy.WebSocketOpen(f.UniqueID)
	ui.Row(c).Height(34).FillWidth().Padding(0, inset).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Segmented(c, &v.direction, locales.All(), locales.Sent(), locales.Received()).Label(locales.Direction())
		ui.Toggle(c, &v.showPings, locales.PingPongCount(pings)).Tooltip(locales.ShowPingAndPongFrames())
		box, _ := a.searchField(c, "wsSearch", &v.query, locales.SearchMessages(), locales.SearchMessagesLabel())
		box.Width(200).MinWidth(80).Shrink(1)
		ui.Spacer(c)
		if open {
			ui.Text(c, locales.Open()).FontSize(10.5).FontWeight(650).TextColor(p.green).Background(p.greenSoft).Padding(2, 7).Radius(5)
			if ui.Button(c, locales.SendPing()).Tooltip(locales.PingTheServer()).Clicked() {
				if err := a.proxy.SendWebSocket(f.UniqueID, true, "ping", []byte("ProxyGo")); err != nil {
					a.toast(locales.PingError(err.Error()))
				}
			}
		}
	})
	ui.Divider(c)
	if len(msgs) == 0 {
		if len(all) == 0 {
			emptyState(c, p, locales.NoMessagesYet())
		} else {
			emptyState(c, p, locales.NoMessagesMatch())
		}
		if open {
			a.wsComposer(c, f)
		}
		return
	}
	if a.wsRow >= len(msgs) {
		a.wsRow = len(msgs) - 1
	}
	start := f.RequestTime()
	cols := []ui.TableColumn{{Title: "", ID: "dir", Width: 18}, {Title: locales.Type(), Width: 56}, {Title: locales.Data()}, {Title: locales.Size(), Width: 64, Align: ui.End}, {Title: locales.Time(), Width: 80, Align: ui.End}}
	list := a.listState("ws:"+f.UniqueID, open || f.IsActive())
	list.Selected = &a.wsRow
	ui.SplitVerticalPercent(c, &a.listSplit, func() {
		ui.Table(c.Key("ws"), list, cols, len(msgs), func(row, col int) {
			m := msgs[row]
			sel := row == a.wsRow
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
			switch col {
			case 0:
				tip := map[string]string{"client": locales.FromTheClient(), "server": locales.FromTheServer()}[m.From]
				if m.Injected {
					tip = locales.SentByProxyGo(tip)
				}
				ui.Box(c).Tooltip(tip).Children(func() {
					if m.From == "client" {
						glyph(c, "arrowUp", 11, fg(map[bool]ui.Color{true: p.purple, false: p.green}[m.Injected]))
					} else {
						glyph(c, "arrowDown", 11, fg(map[bool]ui.Color{true: p.purple, false: p.red}[m.Injected]))
					}
				})
			case 1:
				ui.Text(c, m.Type).FontSize(11).TextColor(dim(p.muted))
			case 2:
				data := m.Data
				if m.Type == "binary" {
					data = locales.BytesOfBinary(len(m.RawData))
				}
				if m.Type == "close" {
					data = fmt.Sprintf("%d %s", m.CloseCode, data)
				}
				ui.Row(c).Gap(5).AlignItems(ui.Center).Clip().Children(func() {
					if m.Injected {
						chip(c, "ProxyGo", fg(p.purple), sel, p.purpleSoft)
					}
					ui.Text(c, shorten(strings.ReplaceAll(data, "\n", " "), 400)).SingleLine().FontSize(11.5).TextColor(fg(p.text))
				})
			case 3:
				ui.Text(c, formatSize(max(len(m.Data), len(m.RawData)))).FontSize(11).TextColor(dim(p.muted)).FontFeatures("tnum")
			case 4:
				if m.Time > 0 && !start.IsZero() {
					d := time.Unix(0, int64(m.Time*1e9)).Sub(start)
					ui.Text(c, formatDuration(d)).FontSize(11).TextColor(dim(p.muted)).FontFeatures("tnum")
				}
			}
		}).Grow(1).Label(locales.WebsocketMessages())
		if open {
			a.wsComposer(c, f)
		}
	}, func() {
		m := msgs[max(a.wsRow, 0)]
		body := []byte(m.Data)
		ct := ""
		if m.Type == "binary" {
			body, ct = m.RawData, "application/octet-stream"
			if f.Request != nil && a.rules.Current().ProtobufFor(f.MethodName(), f.URL()) != nil {
				ct = "application/x-protobuf"
			}
		}
		a.bodyContent(c, fmt.Sprintf("%s:ws:%d:%v", f.UniqueID, a.wsRow, m.Time), body, ct, "ws", bodySource{f: f, response: m.From == "server", ws: &m})
	}).Grow(1)
}

func (a *App) wsComposer(c *ui.Context, f *flow.Flow) {
	v := &a.ws
	ui.Divider(c)
	composed := a.proxy.Composed(f.UniqueID)
	ui.Row(c).FillWidth().Padding(6, inset).Gap(8).AlignItems(ui.Center).Children(func() {
		if !composed {
			ui.Segmented(c, &v.toClient, locales.ToServer(), locales.ToClient()).Label(locales.SendTo())
		}
		in := ui.TextInput(c.Key("wsDraft"), &v.draft).Placeholder(locales.ATextMessage()).Label(locales.Message()).Grow(1)
		send := ui.PrimaryButton(c, locales.Send()).Disabled(v.draft == "").Tooltip(locales.SendTheMessage()).Clicked() || in.Submitted() && v.draft != ""
		if send {
			if err := a.proxy.SendWebSocket(f.UniqueID, composed || v.toClient == 0, "text", []byte(v.draft)); err != nil {
				a.toast(locales.SendError(err.Error()))
			} else {
				v.draft = ""
			}
		}
	})
}

func emptyState(c *ui.Context, p palette, text string) {
	centered(c, 0, func() {
		ui.Text(c, text).TextColor(p.faint).TextAlign(ui.Center)
	})
}

func centered(c *ui.Context, gap float32, build func()) {
	ui.Column(c).Grow(1).FillWidth().Justify(ui.Center).Children(func() {
		ui.Scroll(c.Key("centered")).FillWidth().Shrink(1).Children(func() {
			ui.Column(c).FillWidth().Padding(20).Gap(gap).AlignItems(ui.Center).Children(build)
		})
	})
}

func rawRequest(f *flow.Flow) string {
	if f == nil || f.Request == nil {
		return ""
	}
	var b strings.Builder
	target := f.Request.URI
	if f.IsTunnel() {
		target = f.Request.URI
	}
	fmt.Fprintf(&b, "%s %s %s\n", f.MethodName(), cmp.Or(target, "/"), f.Request.Version.HTTPVersion())
	b.WriteString(headerLines(f.Request.Header))
	b.WriteString("\n")
	b.WriteString(bodyForRaw(f.DecodedRequestBody(), f.Request.Header.Get("Content-Type")))
	return b.String()
}

func rawResponse(f *flow.Flow) string {
	if f == nil || f.Response == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", f.Response.Version.HTTPVersion(), f.StatusLine())
	b.WriteString(headerLines(f.Response.Header))
	b.WriteString("\n")
	b.WriteString(bodyForRaw(f.DecodedResponseBody(), f.Response.Header.Get("Content-Type")))
	return b.String()
}

func bodyForRaw(body []byte, ct string) string {
	if len(body) == 0 {
		return ""
	}
	if !isTextual(ct, body) {
		return locales.SizeOfBinaryData(formatSize(len(body)))
	}
	const limit = 2 << 20
	if len(body) > limit {
		return string(body[:limit]) + "\n… " + locales.SizeMore(formatSize(len(body)-limit))
	}
	return string(body)
}
