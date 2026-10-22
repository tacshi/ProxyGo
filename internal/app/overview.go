package app

import (
	"fmt"
	"math"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
	"proxygo/internal/store"
	"proxygo/locales"
)

func (a *App) overview(c *ui.Context) {
	p := a.pal
	if len(a.flows) == 0 {
		ui.Column(c).Grow(1).Center().Gap(8).Children(func() {
			glyph(c, "chart", 30, p.faint)
			ui.Text(c, locales.NoTrafficYet()).FontSize(15).FontWeight(600).TextColor(p.text2)
			ui.Text(c, locales.TheOverviewFillsInAsRequests()).TextColor(p.muted)
		})
		return
	}
	s := a.overviewStats()
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(windowInset).Gap(12).Children(func() {
			a.overviewHeader(c, s)
			a.overviewTiles(c, s)
			cardRow(c, func() {
				panel(c, p, locales.RequestsOverTime(), func() {
					legend(c, p, locales.Succeeded(), p.accent)
					legend(c, p, locales.Errors(), p.red)
					legend(c, p, locales.StatusActive(), p.gray)
				}, func() { a.requestsChart(c, s) }).Grow(2).Basis(0).MinWidth(420)
				panel(c, p, locales.Status(), nil, func() { a.statusCard(c, s) }).Grow(1).Basis(0).MinWidth(260)
			})
			cardRow(c, func() {
				panel(c, p, locales.DataOverTime(), func() {
					legend(c, p, locales.Downloaded(), p.accent)
					legend(c, p, locales.Uploaded(), p.purple)
				}, func() { a.dataChart(c, s) }).Grow(2).Basis(0).MinWidth(420)
				panel(c, p, locales.ResponseTimes(), nil, func() { a.responseTimes(c, s) }).Grow(1).Basis(0).MinWidth(260)
			})
			cardRow(c, func() {
				panel(c, p, locales.TopDomains(), nil, func() {
					a.bars(c, s.domains, s.domainFails, s.domainBytes, s.total, 8, nil, func(name string) { a.section = "domain:" + name })
				}).Grow(1).Basis(0).MinWidth(260)
				panel(c, p, locales.TopApps(), nil, func() {
					a.bars(c, s.apps, s.appFails, s.appBytes, s.total, 8, nil, func(name string) { a.section = "app:" + name })
				}).Grow(1).Basis(0).MinWidth(260)
				panel(c, p, locales.ContentTypes(), nil, func() {
					a.bars(c, s.kinds, nil, s.kindBytes, s.total, len(s.kinds), kindLabel, func(name string) {
						if name != "Encrypted" {
							a.section = "all"
							clear(a.kinds)
							a.kinds[name] = true
						}
					})
				}).Grow(1).Basis(0).MinWidth(260)
			})
			cardRow(c, func() {
				panel(c, p, locales.HTTPSDecryption(), nil, func() { a.decryptionCard(c, s) }).Grow(1).Basis(0).MinWidth(320)
				panel(c, p, locales.Errors(), nil, func() { a.errorsCard(c, s) }).Grow(1).Basis(0).MinWidth(320)
			})
			cardRow(c, func() {
				panel(c, p, locales.Slowest(), nil, func() {
					a.topFlows(c, s.slow, flowDuration, locales.NoFinishedRequestsYet())
				}).Grow(1).Basis(0).MinWidth(320)
				panel(c, p, locales.LargestResponses(), nil, func() {
					a.topFlows(c, s.large, func(f *flow.Flow) string { return formatSize(f.ResponseBodySize()) }, locales.NoResponseBodiesYet())
				}).Grow(1).Basis(0).MinWidth(320)
			})
		})
	})
}

func (a *App) overviewHeader(c *ui.Context, s *overviewStats) {
	p := a.pal
	ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
		summary := locales.RequestsCount(s.total)
		if !s.first.IsZero() {
			from, to := s.first.Local(), s.last.Local()
			layout := "15:04:05"
			if from.YearDay() != to.YearDay() || from.Year() != to.Year() {
				layout = "Jan 2 15:04:05"
			}
			summary = locales.RequestsFromTo(s.total, formatClock(from, layout), formatClock(to, layout), formatDuration(max(s.span(), time.Millisecond)))
		}
		ui.Text(c, summary).FontSize(12).TextColor(p.muted).SingleLine().Shrink(1).MinWidth(0)
		ui.Spacer(c)
		b := ui.Button(c, locales.CopyAsMarkdown()).Tooltip(locales.CopyThisOverviewAsAMarkdown())
		if b.Clicked() {
			a.copy(s.markdown(), locales.CopiedTheOverviewAsMarkdown())
		}
	})
}

func (a *App) overviewTiles(c *ui.Context, s *overviewStats) {
	p := a.pal
	pct := func(n, of int) string { return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(max(of, 1))) }
	ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Stretch).Wrap().Children(func() {
		note := ""
		if peak, step := s.peakRequests(); peak > 1 {
			note = locales.PeakPerStep(peak, stepLabel(step))
		}
		stat(c, p, locales.Requests(), fmt.Sprint(s.total), note, p.text)
		errs := s.errors()
		color := p.text
		if errs > 0 {
			color = p.red
		}
		t := stat(c, p, locales.Errors(), fmt.Sprint(errs), locales.PercentOfRequests(pct(errs, s.total)), color)
		if errs > 0 {
			hoverTile(t, p)
			t.Tooltip(locales.ShowTheFailedRequests())
			if t.Clicked() {
				a.filterBy(store.Condition{Enabled: true, Field: store.FieldStatus, Op: store.OpRegex, Value: `^([45]\d\d|999)$`})
			}
		}
		if len(s.durations) > 0 {
			stat(c, p, locales.MedianTime(), formatDuration(s.percentile(0.5)), "P95 "+formatDuration(s.percentile(0.95)), p.text)
		} else {
			stat(c, p, locales.MedianTime(), "–", locales.NoFinishedRequests(), p.text)
		}
		stat(c, p, locales.DataTransferred(), formatBytes(s.up+s.down), "↑ "+formatBytes(s.up)+"  ↓ "+formatBytes(s.down), p.text)
		if s.https() > 0 {
			color := p.text
			if s.decrypted == s.https() {
				color = p.green
			}
			stat(c, p, locales.HTTPSDecrypted(), pct(s.decrypted, s.https()), locales.DecryptedOfHTTPSRequests(s.decrypted, s.https()), color)
		} else {
			stat(c, p, locales.HTTPSDecrypted(), "–", locales.NoHTTPSRequests(), p.text)
		}
		stat(c, p, locales.AppsDomains(), fmt.Sprintf("%d · %d", len(s.apps), len(s.domains)), "", p.text)
	})
}

func stat(c *ui.Context, p palette, label, value, note string, color ui.Color) ui.Element {
	return ui.Column(c.Key(label)).Grow(1).Basis(0).MinWidth(150).Padding(12, 14).Gap(3).Radius(10).Background(p.surface).Children(func() {
		ui.Text(c, label).FontSize(11).TextColor(p.muted).SingleLine()
		ui.Text(c, value).FontSize(20).FontWeight(650).TextColor(color).SingleLine().FontFeatures("tnum")
		if note != "" {
			ui.Text(c, note).FontSize(10.5).TextColor(p.faint).SingleLine().FontFeatures("tnum")
		}
	})
}

func hoverTile(t ui.Element, p palette) {
	t.Cursor(ui.CursorPointer)
	if t.Hovered() {
		t.Background(p.hover)
	}
}

func cardRow(c *ui.Context, build func()) {
	ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Stretch).Wrap().Children(build)
}

func panel(c *ui.Context, p palette, title string, aside func(), build func()) ui.Element {
	return ui.Column(c.Key(title)).Padding(14).Gap(10).Radius(10).Border(1, p.border).Children(func() {
		ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Text(c, title).FontWeight(650).TextColor(p.text).SingleLine()
			ui.Spacer(c)
			if aside != nil {
				aside()
			}
		})
		build()
	})
}

func legend(c *ui.Context, p palette, label string, color ui.Color) {
	ui.Row(c.Key(label)).Gap(5).AlignItems(ui.Center).Children(func() {
		ui.Box(c).Size(8, 8).Radius(4).Background(color)
		ui.Text(c, label).FontSize(11).TextColor(p.muted).SingleLine()
	})
}

func placeholder(c *ui.Context, p palette, text string) {
	ui.Column(c).FillWidth().Grow(1).MinHeight(60).Center().Children(func() {
		ui.Text(c, text).FontSize(11.5).TextColor(p.faint).TextAlign(ui.Center).Wrap()
	})
}

func listRow(c *ui.Context, key string, padY float32) ui.Element {
	return ui.Row(c.Key(key)).AlignSelf(ui.Stretch).Margin(0, -6).Padding(padY, 6).Gap(8).AlignItems(ui.Center).Radius(5)
}

func (a *App) bars(c *ui.Context, counts, fails map[string]int, bytes map[string]int64, total, limit int, label func(string) string, choose func(string)) {
	p := a.pal
	names := store.ByCount(counts)
	for i, name := range names {
		if i >= limit {
			ui.Text(c, locales.MoreCount(len(names)-limit)).FontSize(11).TextColor(p.muted).Padding(2, 2)
			break
		}
		n, bad := counts[name], fails[name]
		row := listRow(c, name, 2)
		if row.Hovered() {
			row.Background(p.hover)
		}
		if row.Clicked() {
			choose(name)
		}
		tip := locales.RequestsCount(n)
		if bad > 0 {
			tip += " · " + locales.FailedCount(bad)
		}
		if b := bytes[name]; b > 0 {
			tip += " · " + formatBytes(b)
		}
		row.Tooltip(tip)
		row.Children(func() {
			shown := name
			if label != nil {
				shown = label(name)
			}
			ui.Text(c, shown).FontSize(11.5).TextColor(p.text2).SingleLine().Width(150)
			ui.Row(c).Height(6).Grow(1).Radius(3).Clip().Background(p.hover).Children(func() {
				share := max(2, 100*float32(n)/float32(max(total, 1)))
				ui.Row(c).Height(6).WidthPercent(share).Children(func() {
					if good := n - bad; good > 0 {
						ui.Box(c).Height(6).Grow(float32(good)).Basis(0).Background(p.accent)
					}
					if bad > 0 {
						ui.Box(c).Height(6).Grow(float32(bad)).Basis(0).Background(p.red)
					}
				})
			})
			ui.Text(c, fmt.Sprint(n)).FontSize(11).TextColor(p.muted).FontFeatures("tnum").Width(40).TextAlign(ui.End)
		})
	}
}

func (a *App) openFlow(f *flow.Flow) {
	a.section = "all"
	a.filterKey = ""
	a.applyFilter()
	a.selectFlow(f.UniqueID)
}

func (a *App) topFlows(c *ui.Context, flows []*flow.Flow, value func(*flow.Flow) string, empty string) {
	p := a.pal
	if len(flows) == 0 {
		placeholder(c, p, empty)
		return
	}
	for i, f := range flows {
		if i >= 6 {
			break
		}
		row := listRow(c, f.UniqueID, 3)
		if row.Hovered() {
			row.Background(p.hover)
		}
		if row.Clicked() {
			a.openFlow(f)
		}
		row.Children(func() {
			mbg, mfg := p.methodColors(f.MethodName())
			ui.Text(c, f.MethodName()).FontSize(10).FontWeight(650).TextColor(mfg).Background(mbg).Padding(1, 5).Radius(4)
			ui.Text(c, f.URL()).FontSize(11.5).TextColor(p.text2).SingleLine().Grow(1).Shrink(1).MinWidth(0)
			ui.Text(c, value(f)).FontSize(11).TextColor(p.muted).FontFeatures("tnum")
		})
	}
}

type statusPart struct {
	label string
	n     int
	color ui.Color
	cond  store.Condition
}

func (a *App) statusCard(c *ui.Context, s *overviewStats) {
	p := a.pal
	status := func(op store.Op, v string) store.Condition {
		return store.Condition{Enabled: true, Field: store.FieldStatus, Op: op, Value: v}
	}
	parts := []statusPart{
		{locales.Status2xxSuccess(), s.ok, p.green, status(store.OpRegex, `^2\d\d$`)},
		{locales.Status3xxRedirect(), s.redirect, p.blue, status(store.OpRegex, `^3\d\d$`)},
		{locales.Status4xxClientError(), s.client, p.orange, status(store.OpRegex, `^4\d\d$`)},
		{locales.Status5xxServerError(), s.server, p.red, status(store.OpRegex, `^5\d\d$`)},
		{locales.Failed(), s.failed, p.purple, status(store.OpEquals, "999")},
		{locales.StatusActive(), s.active, p.gray, status(store.OpEquals, "Active")},
	}
	ui.Row(c).FillWidth().Height(10).Radius(5).Clip().Background(p.hover).Gap(2).Children(func() {
		for _, part := range parts {
			if part.n > 0 {
				ui.Box(c.Key(part.label)).Height(10).Grow(float32(part.n)).Basis(0).Background(part.color)
			}
		}
	})
	ui.Column(c).FillWidth().Gap(0).Children(func() {
		for _, part := range parts {
			row := listRow(c, part.label, 3)
			if part.n > 0 {
				if row.Hovered() {
					row.Background(p.hover)
				}
				if row.Clicked() {
					a.filterBy(part.cond)
				}
			}
			row.Children(func() {
				ui.Box(c).Size(8, 8).Radius(4).Background(part.color)
				color := p.text2
				if part.n == 0 {
					color = p.faint
				}
				ui.Text(c, part.label).FontSize(11.5).TextColor(color).SingleLine().Grow(1)
				ui.Text(c, fmt.Sprint(part.n)).FontSize(11.5).TextColor(color).FontFeatures("tnum")
				ui.Text(c, fmt.Sprintf("%.0f%%", 100*float64(part.n)/float64(max(s.total, 1)))).FontSize(11).TextColor(p.faint).FontFeatures("tnum").Width(36).TextAlign(ui.End)
			})
		}
	})
	codes := make(map[string]int, len(s.codes))
	for code, n := range s.codes {
		if code < 600 {
			codes[fmt.Sprint(code)] = n
		}
	}
	if len(codes) == 0 {
		return
	}
	ui.Row(c).FillWidth().Gap(6).Wrap().Children(func() {
		for i, code := range store.ByCount(codes) {
			if i >= 8 {
				break
			}
			chip := ui.Row(c.Key("code"+code)).Gap(4).Padding(2, 7).Radius(5).Background(p.surface).Cursor(ui.CursorPointer)
			if chip.Hovered() {
				chip.Background(p.hover)
			}
			if chip.Clicked() {
				a.filterBy(status(store.OpEquals, code))
			}
			var n int
			_, _ = fmt.Sscan(code, &n)
			chip.Tooltip(errorReasonText(n))
			chip.Children(func() {
				ui.Text(c, code).FontSize(11).FontWeight(600).TextColor(codeColor(p, n)).FontFeatures("tnum")
				ui.Text(c, "×"+fmt.Sprint(codes[code])).FontSize(11).TextColor(p.muted).FontFeatures("tnum")
			})
		}
	})
}

func errorReasonText(code int) string {
	return errorReason(&flow.Flow{Response: &flow.Response{Status: &flow.Status{Code: code}}})
}

func codeColor(p palette, code int) ui.Color {
	switch {
	case code >= 500:
		return p.red
	case code >= 400:
		return p.orange
	case code >= 300:
		return p.blue
	}
	return p.green
}

func (a *App) responseTimes(c *ui.Context, s *overviewStats) {
	p := a.pal
	if len(s.durations) == 0 {
		msg := locales.NoFinishedRequestsYetDot()
		if s.tunnels > 0 {
			msg += " " + locales.EncryptedTunnelsHaveNoResponseTime()
		}
		placeholder(c, p, msg)
		return
	}
	ui.Row(c).FillWidth().Gap(8).Children(func() {
		for _, q := range []struct {
			label string
			v     float64
		}{{locales.Median(), 0.5}, {"P95", 0.95}, {"P99", 0.99}} {
			ui.Column(c.Key(q.label)).Grow(1).Basis(0).Gap(1).Children(func() {
				ui.Text(c, q.label).FontSize(10.5).TextColor(p.muted)
				ui.Text(c, formatDuration(s.percentile(q.v))).FontSize(15).FontWeight(650).TextColor(p.text).FontFeatures("tnum").SingleLine()
			})
		}
	})
	ms := time.Millisecond
	ranges := []struct {
		label  string
		lo, hi time.Duration
		color  ui.Color
	}{
		{locales.Under100Ms(), 0, 100 * ms, p.green},
		{"100–300 ms", 100 * ms, 300 * ms, p.green},
		{"300 ms – 1 s", 300 * ms, time.Second, p.yellow},
		{"1–3 s", time.Second, 3 * time.Second, p.orange},
		{locales.ThreeSOrMore(), 3 * time.Second, 0, p.red},
	}
	counts := make([]int, len(ranges))
	for _, d := range s.durations {
		for i, r := range ranges {
			if d >= r.lo && (r.hi == 0 || d < r.hi) {
				counts[i]++
				break
			}
		}
	}
	peak := 1
	for _, n := range counts {
		peak = max(peak, n)
	}
	ui.Column(c).FillWidth().Gap(0).Children(func() {
		for i, r := range ranges {
			n := counts[i]
			row := listRow(c, r.label, 2)
			if n > 0 {
				if row.Hovered() {
					row.Background(p.hover)
				}
				if row.Clicked() {
					a.filterDuration(r.lo, r.hi)
				}
				row.Tooltip(locales.RequestsCount(n) + " · " + locales.PercentOfFinishedRequests(fmt.Sprintf("%.0f%%", 100*float64(n)/float64(len(s.durations)))))
			}
			row.Children(func() {
				ui.Text(c, r.label).FontSize(11.5).TextColor(p.text2).SingleLine().Width(92)
				ui.Box(c).Height(6).Grow(1).Radius(3).Background(p.hover).Children(func() {
					if n > 0 {
						ui.Box(c).Height(6).WidthPercent(max(2, 100*float32(n)/float32(peak))).Radius(3).Background(r.color)
					}
				})
				ui.Text(c, fmt.Sprint(n)).FontSize(11).TextColor(p.muted).FontFeatures("tnum").Width(32).TextAlign(ui.End)
			})
		}
	})
}

func (a *App) filterDuration(lo, hi time.Duration) {
	cond := func(op store.Op, d time.Duration) store.Condition {
		return store.Condition{Enabled: true, Field: store.FieldDuration, Op: op, Value: fmt.Sprint(d.Milliseconds())}
	}
	a.filterBy(store.Condition{Enabled: true, Field: store.FieldMethod, Op: store.OpNotEquals, Value: "CONNECT"})
	if lo > 0 {
		a.filterBy(cond(store.OpGreater, lo-time.Millisecond))
	}
	if hi > 0 {
		a.filterBy(cond(store.OpLess, hi))
	}
}

func (a *App) decryptionCard(c *ui.Context, s *overviewStats) {
	p := a.pal
	if s.https() == 0 {
		placeholder(c, p, locales.NoHTTPSRequestsYet())
		return
	}
	share := float64(s.decrypted) / float64(s.https())
	ui.Row(c).FillWidth().Gap(10).AlignItems(ui.End).Children(func() {
		ui.Text(c, fmt.Sprintf("%.0f%%", 100*share)).FontSize(22).FontWeight(650).TextColor(p.text).FontFeatures("tnum")
		ui.Text(c, locales.OfHTTPSRequestsDecrypted(s.tunnels)).FontSize(11.5).TextColor(p.muted).Padding(0, 0, 4, 0).SingleLine().Shrink(1).MinWidth(0)
	})
	ui.Row(c).FillWidth().Height(8).Radius(4).Clip().Background(p.hover).Gap(2).Children(func() {
		if s.decrypted > 0 {
			ui.Box(c).Height(8).Grow(float32(s.decrypted)).Basis(0).Background(p.green)
		}
		if s.tunnels > 0 {
			ui.Box(c).Height(8).Grow(float32(s.tunnels)).Basis(0).Background(p.gray.Alpha(0.6))
		}
	})
	d := a.rules.Current()
	var hosts []string
	for _, h := range store.ByCount(s.tunnelHosts) {
		if !d.ShouldMITM(h) {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		ui.Row(c).Gap(6).AlignItems(ui.Center).Padding(4, 0).Children(func() {
			glyph(c, "check", 13, p.green)
			msg := locales.EveryHTTPSRequestIsDecrypted()
			if s.tunnels > 0 {
				msg = locales.SSLProxyingNowCoversEveryEncrypted()
			}
			ui.Text(c, msg).FontSize(11.5).TextColor(p.text2).Wrap().Shrink(1).MinWidth(0)
		})
		return
	}
	ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
		ui.Text(c, locales.EncryptedDomains()).FontSize(11).FontWeight(600).TextColor(p.muted)
		ui.Spacer(c)
		if len(hosts) > 1 && ui.Button(c, locales.EnableAllCount(len(hosts))).Tooltip(locales.TurnOnSSLProxyingForEvery()).Clicked() {
			a.enableSSLHosts(hosts)
		}
	})
	for i, h := range hosts {
		if i >= 6 {
			ui.Text(c, locales.MoreDomains(len(hosts)-6)).FontSize(11).TextColor(p.muted).Padding(2, 0)
			break
		}
		row := listRow(c, "tls:"+h, 2)
		if row.Hovered() {
			row.Background(p.hover)
		}
		if row.Clicked() {
			a.section = "domain:" + h
		}
		row.Children(func() {
			glyph(c, "lock", 11, p.faint)
			ui.Text(c, h).FontSize(11.5).TextColor(p.text2).SingleLine().Grow(1).Shrink(1).MinWidth(0)
			ui.Text(c, fmt.Sprint(s.tunnelHosts[h])).FontSize(11).TextColor(p.muted).FontFeatures("tnum")
			b := ui.ButtonBase(c).Padding(1, 8).Radius(5).Background(p.surface).Border(1, p.border).Label(locales.EnableSSLProxyingForHost(h))
			if b.Hovered() {
				b.Background(p.hover)
			}
			b.Children(func() { ui.Text(c, locales.Enable()).FontSize(11).TextColor(p.text2) })
			if b.Clicked() {
				a.enableSSL(h, false)
			}
		})
	}
}

func (a *App) enableSSLHosts(hosts []string) {
	a.rules.Update(func(d *rules.Data) {
		for _, h := range hosts {
			includeSSL(d, h)
		}
	})
	a.toast(locales.SSLProxyingIsOnForDomains(len(hosts)))
}

func (a *App) errorsCard(c *ui.Context, s *overviewStats) {
	p := a.pal
	if s.errors() == 0 {
		ui.Row(c).Gap(6).AlignItems(ui.Center).Padding(4, 0).Children(func() {
			glyph(c, "check", 13, p.green)
			ui.Text(c, locales.NoFailedRequests()).FontSize(11.5).TextColor(p.text2)
		})
		return
	}
	ui.Text(c, locales.MostCommon()).FontSize(11).FontWeight(600).TextColor(p.muted)
	reasons := store.ByCount(s.reasons)
	peak := s.reasons[reasons[0]]
	for i, r := range reasons {
		if i >= 4 {
			break
		}
		n := s.reasons[r]
		row := listRow(c, "why:"+r, 2)
		var code int
		if _, err := fmt.Sscanf(r, "%d", &code); err == nil && code >= 400 {
			if row.Hovered() {
				row.Background(p.hover)
			}
			if row.Clicked() {
				a.filterBy(store.Condition{Enabled: true, Field: store.FieldStatus, Op: store.OpEquals, Value: fmt.Sprint(code)})
			}
		}
		row.Tooltip(r)
		row.Children(func() {
			ui.Text(c, r).FontSize(11.5).TextColor(p.text2).SingleLine().Grow(3).Basis(0).MinWidth(0)
			ui.Box(c).Height(6).Grow(2).Basis(0).Radius(3).Background(p.hover).Children(func() {
				ui.Box(c).Height(6).WidthPercent(max(2, 100*float32(n)/float32(peak))).Radius(3).Background(p.red)
			})
			ui.Text(c, fmt.Sprint(n)).FontSize(11).TextColor(p.muted).FontFeatures("tnum").Width(32).TextAlign(ui.End)
		})
	}
	ui.Text(c, locales.ByDomain()).FontSize(11).FontWeight(600).TextColor(p.muted).Padding(4, 0, 0, 0)
	for i, h := range store.ByCount(s.domainFails) {
		if i >= 4 {
			break
		}
		bad, all := s.domainFails[h], s.domains[h]
		row := listRow(c, "fail:"+h, 2)
		if row.Hovered() {
			row.Background(p.hover)
		}
		if row.Clicked() {
			a.section = "domain:" + h
		}
		row.Children(func() {
			ui.Text(c, h).FontSize(11.5).TextColor(p.text2).SingleLine().Grow(1).Shrink(1).MinWidth(0)
			ui.Text(c, locales.CountOf(bad, all)).FontSize(11).TextColor(p.muted).FontFeatures("tnum")
			rate := float64(bad) / float64(max(all, 1))
			color := p.orange
			if rate >= 0.5 {
				color = p.red
			}
			ui.Text(c, fmt.Sprintf("%.0f%%", 100*rate)).FontSize(11).FontWeight(600).TextColor(color).FontFeatures("tnum").Width(36).TextAlign(ui.End)
		})
	}
}

func stepLabel(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d == time.Second:
		return locales.UnitSecond()
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d == time.Minute:
		return locales.UnitMinute()
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d == time.Hour:
		return locales.UnitHour()
	}
	return fmt.Sprintf("%d h", int(d.Hours()))
}

func niceCeil(v float64) float64 {
	if v <= 0 {
		return 1
	}
	e := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if m*e >= v {
			return m * e
		}
	}
	return 10 * e
}

func niceBytes(v float64) float64 {
	unit := 1.0
	for niceCeil(v/unit) >= 1000 {
		unit *= 1024
	}
	return niceCeil(v/unit) * unit
}

func tickLayout(s *overviewStats) string {
	switch {
	case s.span() >= 24*time.Hour:
		return "Jan 2 15:04"
	case s.step >= time.Minute:
		return "15:04"
	}
	return "15:04:05"
}

type chartPlot struct {
	rect  ui.Rect
	n     int
	hover int
}

func (cp chartPlot) slot() float32 { return cp.rect.W / float32(max(cp.n, 1)) }

func (a *App) chart(c *ui.Context, key string, s *overviewStats, top string, draw func(p *ui.Painter, cp chartPlot), tip func(i int) string) {
	pal := a.pal
	n := len(s.buckets)
	el := ui.Box(c.Key(key)).FillWidth().Height(160)
	hover := -1
	if x, _, over := el.PointerPosition(); over && n > 0 {
		if w := el.Bounds().W; w > 0 {
			hover = min(max(int(x/(w/float32(n))), 0), n-1)
		}
	}
	if hover >= 0 {
		el.Tooltip(tip(hover))
	}
	layout := tickLayout(s)
	el.Draw(func(p *ui.Painter, r ui.Rect) {
		const labelH, axisH = 16, 20
		plot := ui.Rect{X: r.X, Y: r.Y + labelH, W: r.W, H: r.H - labelH - axisH}
		p.Text(plot.X, r.Y, top, 10, pal.faint)
		p.Line(plot.X, plot.Y, plot.X+plot.W, plot.Y, 1, pal.hairline)
		p.Line(plot.X, plot.Y+plot.H/2, plot.X+plot.W, plot.Y+plot.H/2, 1, pal.hairline)
		cp := chartPlot{rect: plot, n: n, hover: hover}
		if hover >= 0 {
			p.Fill(ui.Rect{X: plot.X + float32(hover)*cp.slot(), Y: plot.Y, W: cp.slot(), H: plot.H}, pal.hover.Alpha(0.7), 3)
		}
		draw(p, cp)
		p.Line(plot.X, plot.Y+plot.H, plot.X+plot.W, plot.Y+plot.H, 1, pal.border)
		ticks := min(max(int(plot.W/110), 2), 7, max(n, 2))
		y := plot.Y + plot.H + 5
		for j := range ticks {
			i := int(math.Round(float64(j) * float64(n-1) / float64(ticks-1)))
			if n == 1 && j > 0 {
				break
			}
			label := s.first.Add(time.Duration(i) * s.step).Local().Format(layout)
			w, _ := p.MeasureText(0, ui.Span{Text: label, Size: 10})
			x := plot.X + (float32(i)+0.5)*cp.slot() - w/2
			x = min(max(x, plot.X), plot.X+plot.W-w)
			p.Text(x, y, label, 10, pal.faint)
		}
	})
}

func (a *App) requestsChart(c *ui.Context, s *overviewStats) {
	pal := a.pal
	peak := 0
	for _, b := range s.buckets {
		peak = max(peak, b.ok+b.failed+b.active)
	}
	top := niceCeil(float64(peak))
	a.chart(c, "requests-chart", s, locales.ValuePerStep(fmt.Sprintf("%g", top), stepLabel(s.step)), func(p *ui.Painter, cp chartPlot) {
		r := cp.rect
		bw := min(cp.slot()*0.7, 22)
		for i, b := range s.buckets {
			total := b.ok + b.failed + b.active
			if total == 0 {
				continue
			}
			h := r.H * float32(float64(total)/top)
			x := r.X + float32(i)*cp.slot() + (cp.slot()-bw)/2
			stack := ui.Rect{X: x, Y: r.Y + r.H - h, W: bw, H: h}
			p.Clip(stack, min(3, bw/2), func() {
				y := r.Y + r.H
				for _, seg := range []struct {
					n     int
					color ui.Color
				}{{b.ok, pal.accent}, {b.failed, pal.red}, {b.active, pal.gray.Alpha(0.55)}} {
					if seg.n == 0 {
						continue
					}
					sh := h * float32(seg.n) / float32(total)
					y -= sh
					p.Fill(ui.Rect{X: x, Y: y, W: bw, H: sh}, seg.color, 0)
				}
			})
		}
	}, func(i int) string {
		b := s.buckets[i]
		from := s.first.Add(time.Duration(i) * s.step).Local()
		tip := formatClock(from, tickLayout(s)) + " · " + locales.RequestsCount(b.ok+b.failed+b.active)
		if b.failed > 0 {
			tip += " · " + locales.ErrorsCount(b.failed)
		}
		if b.active > 0 {
			tip += " · " + locales.ActiveCount(b.active)
		}
		return tip
	})
}

func (a *App) dataChart(c *ui.Context, s *overviewStats) {
	pal := a.pal
	sec := s.step.Seconds()
	var peak int64
	for _, b := range s.buckets {
		peak = max(peak, b.up, b.down)
	}
	top := niceBytes(float64(peak) / sec)
	a.chart(c, "data-chart", s, formatRate(int64(top)), func(p *ui.Painter, cp chartPlot) {
		r := cp.rect
		point := func(i int, v int64) (float32, float32) {
			return r.X + (float32(i)+0.5)*cp.slot(), r.Y + r.H - r.H*float32(float64(v)/sec/top)
		}
		series := func(get func(overviewBucket) int64, color ui.Color, fill float32) {
			var line [][2]float32
			area := &ui.Path{}
			for i, b := range s.buckets {
				x, y := point(i, get(b))
				if i == 0 {
					area.MoveTo(x, r.Y+r.H)
				}
				area.LineTo(x, y)
				line = append(line, [2]float32{x, y})
			}
			if len(line) == 1 {
				line = [][2]float32{{r.X, line[0][1]}, {r.X + r.W, line[0][1]}}
				area.Reset().MoveTo(r.X, r.Y+r.H).LineTo(r.X, line[0][1]).LineTo(r.X+r.W, line[0][1])
			}
			area.LineTo(line[len(line)-1][0], r.Y+r.H).Close()
			p.FillPathGradient(area, ui.LinearGradient{From: color.Alpha(fill), To: color.Alpha(0), Angle: 180})
			p.StrokePolyline(line, 1.5, color)
		}
		series(func(b overviewBucket) int64 { return b.down }, pal.accent, 0.28)
		series(func(b overviewBucket) int64 { return b.up }, pal.purple, 0.12)
		if cp.hover >= 0 && len(s.buckets) > 1 {
			b := s.buckets[cp.hover]
			for _, v := range []struct {
				n     int64
				color ui.Color
			}{{b.down, pal.accent}, {b.up, pal.purple}} {
				x, y := point(cp.hover, v.n)
				p.FillPath((&ui.Path{}).Circle(x, y, 3.5), pal.bg)
				p.FillPath((&ui.Path{}).Circle(x, y, 2.5), v.color)
			}
		}
	}, func(i int) string {
		b := s.buckets[i]
		from := s.first.Add(time.Duration(i) * s.step).Local()
		return fmt.Sprintf("%s · ↓ %s · ↑ %s", formatClock(from, tickLayout(s)), formatRate(int64(float64(b.down)/sec)), formatRate(int64(float64(b.up)/sec)))
	})
}
