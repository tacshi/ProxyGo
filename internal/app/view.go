package app

import (
	"fmt"
	"slices"
	"strings"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/internal/store"
	"proxygo/locales"
)

func (a *App) view(c *ui.Context) {
	a.runQueued()
	p := a.applyTheme(c)
	a.showToasts(c, "")
	a.refreshFlows()
	a.applyFilter()
	a.syncMenu()

	if a.set.ShowSidebar {
		ui.Split(c, &a.set.SidebarWidth, func() { a.sidebar(c) }, func() { a.main(c) }).Fill()
	} else {
		a.main(c)
	}
	a.paletteOverlay(c)
	a.commentSheet(c)
	a.repeatSheet(c)
	a.columnSheet(c)
	a.folderSheetView(c)
	a.presetSheetView(c)
	a.deviceSheetView(c)
	_ = p
}

func (a *App) main(c *ui.Context) {
	p := a.pal
	ui.Column(c).Fill().Background(p.bg).Children(func() {
		a.toolbar(c)
		if a.section != "overview" {
			a.filterBar(c)
			if a.advanced {
				a.conditionsBar(c)
			}
		}
		if a.sysKnown && !a.systemProxyOn() && !a.routeHintClosed && a.proxyErr == "" {
			a.routeBanner(c)
		}
		if len(a.pauses) > 0 {
			a.pauseBanner(c)
		}
		winW, winH := c.Size()
		roomW, roomH := winW-a.splitChrome.W, winH-a.splitChrome.H
		var sp ui.Element
		switch {
		case a.section == "overview":
			a.overview(c)
		case !a.set.ShowDetail:
			a.table(c)
		case a.set.DetailRight:
			adoptShare(&a.set.TableWidthShare, a.set.TableWidth, roomW)
			w := keepRoom(shareOf(a.set.TableWidthShare, a.set.TableWidth, roomW), roomW, 380)
			sp = ui.Split(c.Key("right"), &w, func() { a.table(c) }, func() { a.detail(c) }).Grow(1)
			if sp.Changed() && roomW > 0 {
				a.set.TableWidth, a.set.TableWidthShare = w, min(max(w/roomW, 0.1), 0.9)
			}
		default:
			adoptShare(&a.set.TableShare, a.set.TableHeight, roomH)
			h := keepRoom(shareOf(a.set.TableShare, a.set.TableHeight, roomH), roomH, 280)
			sp = ui.SplitVertical(c.Key("below"), &h, func() { a.table(c) }, func() { a.detail(c) }).Grow(1)
			if sp.Changed() && roomH > 0 {
				a.set.TableHeight, a.set.TableShare = h, min(max(h/roomH, 0.1), 0.9)
			}
		}
		if b := sp.Bounds(); b != (ui.Rect{}) {
			a.splitChrome = ui.Rect{W: a.lastWin.W - b.W, H: a.lastWin.H - b.H}
		}
		a.lastWin = ui.Rect{W: winW, H: winH}
		a.statusBar(c)
	})
}

func adoptShare(share *float32, size, room float32) {
	if *share == 0 && room > 400 {
		*share = min(max(size/room, 0.1), 0.9)
	}
}

func shareOf(share, size, room float32) float32 {
	if share > 0 && room > 0 {
		return share * room
	}
	return size
}

func keepRoom(size, room, inspector float32) float32 {
	return min(size, max(room-inspector, 160))
}

func (a *App) toolbar(c *ui.Context) {
	p := a.pal
	bar := c.TitleBar()
	left := float32(inset)
	if !a.set.ShowSidebar {
		left = bar.Left + inset
	}
	ui.Toolbar(c, func() {
		if !a.set.ShowSidebar {
			if iconButton(c, "sidebar", locales.ShowSidebar(), p.text2).Clicked() {
				a.setSidebar(true)
			}
		}
		rec := ui.Button(c, "").Label(map[bool]string{true: locales.ResumeRecording(), false: locales.PauseRecording()}[a.paused]).
			Tooltip(map[bool]string{true: locales.ResumeRecordingShortcut(), false: locales.PauseRecordingShortcut()}[a.paused])
		rec.Children(func() {
			if a.paused {
				glyph(c, "record", 15, p.red)
			} else {
				glyph(c, "pause", 15, p.text2)
			}
		})
		if rec.Clicked() {
			a.setPaused(!a.paused)
		}
		if iconButton(c, "compose", locales.ComposeARequestN(), p.text2).Clicked() {
			a.composeFrom(nil)
		}
		if iconButton(c, "trash", locales.ClearSessionK(), p.text2).Clicked() {
			a.clearFlows()
		}
		ui.Spacer(c)
		a.statusPill(c)
		ui.Spacer(c)
		if iconButton(c, "command", locales.CommandPaletteP(), p.text2).Clicked() {
			a.openPalette()
		}
		if iconButton(c, "gear", locales.SettingsLabel(), p.text2).Clicked() {
			a.openWindow("settings")
		}
		ui.ToggleGroup(c, func() {
			side := a.set.ShowSidebar
			if layoutToggle(c, &side, "sidebar", locales.ToggleSidebarS(), p).Changed() {
				a.setSidebar(side)
			}
			bottom := a.set.ShowDetail && !a.set.DetailRight
			if layoutToggle(c, &bottom, "dockBottom", locales.InspectorBelow(), p).Changed() {
				a.updateSettings(func(s *settings.Settings) { s.ShowDetail, s.DetailRight = bottom || !s.ShowDetail, false })
			}
			right := a.set.ShowDetail && a.set.DetailRight
			if layoutToggle(c, &right, "dockRight", locales.InspectorOnTheRight(), p).Changed() {
				a.updateSettings(func(s *settings.Settings) { s.ShowDetail, s.DetailRight = right || !s.ShowDetail, right })
			}
		}).Label(locales.Layout())
	}).Height(52).Padding(0, inset, 0, left).Background(p.bg).DragWindow()
	ui.Divider(c)
}

func layoutToggle(c *ui.Context, on *bool, icon, tip string, p palette) ui.Element {
	t := ui.Toggle(c, on, "").Label(tip).Tooltip(tip)
	t.Children(func() { glyph(c, icon, 14, p.text2) })
	return t
}

func (a *App) statusPill(c *ui.Context) {
	p := a.pal
	dot, status := p.green, locales.ListeningOn(a.proxyAddress())
	switch {
	case a.proxyErr != "":
		dot, status = p.red, locales.ProxyUnavailable()
	case a.paused:
		dot, status = p.faint, locales.RecordingPausedAt(a.proxyAddress())
	}
	pill := ui.Button(c, "").Label(locales.ProxyStatus()).Tooltip(a.proxyErr).Padding(5, 12).Radius(14).Background(p.surface)
	pill.Children(func() {
		ui.Box(c).Size(8, 8).Radius(4).Background(dot)
		ui.Box(c).Width(6)
		ui.Text(c, "ProxyGo").FontWeight(600).TextColor(p.text).SingleLine()
		ui.Text(c, "  │  ").TextColor(p.border)
		ui.Text(c, status).TextColor(p.text2).SingleLine().FontFeatures("tnum")
		if a.systemProxyOn() {
			ui.Box(c).Width(8)
			ui.Text(c, locales.MacOSProxy()).FontSize(10).FontWeight(600).TextColor(p.green).Background(p.greenSoft).Padding(1, 6).Radius(4)
		}
	})
	pill.Menu(func(m *ui.Menu) {
		if m.Item(locales.CopyProxyAddress()).Chosen() {
			a.copy(a.proxyAddress(), locales.CopiedTheProxyAddress())
		}
		if m.Item(locales.OverrideMacOSProxy()).Checked(a.systemProxyOn()).Chosen() {
			a.setSystemProxy(!a.systemProxyOn())
		}
		m.Separator()
		if m.Item(locales.ProxySettingsEllipsis()).Chosen() {
			a.settingsTab = 1
			a.openWindow("settings")
		}
		if m.Item(locales.SSLProxyingListEllipsis()).Chosen() {
			a.openWindow("ssl")
		}
		if m.Item(locales.InstallCertificateEllipsis()).Chosen() {
			a.openWindow("certificate")
		}
		if m.Item(locales.OpenCertificatePageInBrowser()).Chosen() {
			c.OpenURL(fmt.Sprintf("http://127.0.0.1:%d/", a.proxy.Port()))
		}
	})
}

var kindGroups = [][]string{store.ProtocolKinds, store.ContentKinds, store.VersionKinds}

func (a *App) filterBar(c *ui.Context) {
	p := a.pal
	ui.Row(c).Height(36).FillWidth().Padding(0, inset).Gap(4).AlignItems(ui.Center).Children(func() {
		ui.ScrollHorizontal(c).Grow(1).Shrink(1).Basis(0).Gap(1).AlignItems(ui.Center).MarginEnd(4).Children(func() {
			if ok, _ := a.kindChip(c, locales.All(), len(a.kinds) == 0); ok {
				clear(a.kinds)
			}
			for _, group := range kindGroups {
				ui.Box(c).Size(1, 14).Background(p.border).Margin(0, 4)
				for _, k := range group {
					if ok, mods := a.kindChip(c, kindLabel(k), a.kinds[k]); ok {
						if mods&ui.Cmd == 0 {
							only := !a.kinds[k] || len(a.kinds) > 1
							clear(a.kinds)
							if only {
								a.kinds[k] = true
							}
						} else if a.kinds[k] {
							delete(a.kinds, k)
						} else {
							a.kinds[k] = true
						}
					}
				}
			}
		})
		box, search := a.searchField(c, "filter", &a.query, locales.FilterF(), locales.FilterFlows())
		box.Width(240).Shrink(0).Tooltip(locales.FiltersByURLMethodStatusClient())
		search.Bind(&a.filterHandle)
		if a.filterFocus {
			a.filterFocus = false
			a.filterHandle.Focus(c)
		}
		deep := ui.Toggle(c, &a.deep, "").Label(locales.SearchHeadersAndBodies()).Tooltip(locales.AlsoSearchHeadersAndBodies())
		deep.Children(func() { glyph(c, "deepSearch", 13, p.text2) })
		a.presetsButton(c)
		n := 0
		for _, cond := range a.conditions {
			if cond.Active() {
				n++
			}
		}
		adv := ui.Toggle(c, &a.advanced, "").Label(locales.AdvancedFilter()).Tooltip(locales.AdvancedFilterF())
		adv.Children(func() {
			glyph(c, "filter", 13, p.text2)
			if n > 0 {
				ui.Text(c, fmt.Sprint(n)).FontSize(10).FontWeight(700).TextColor(p.accent)
			}
		})
		if adv.Changed() {
			a.setAdvanced(a.advanced)
		}
	})
	ui.Divider(c)
}

func (a *App) kindChip(c *ui.Context, label string, on bool) (bool, ui.Modifiers) {
	p := a.pal
	b := ui.ButtonBase(c).Label(label).Padding(3, 7).Radius(5)
	color := p.muted
	if on {
		b.Background(p.accent.Alpha(0.14))
		color = p.accent
	} else if b.Hovered() {
		b.Background(p.hover)
		color = p.text2
	}
	b.Children(func() {
		ui.Text(c, label).FontSize(11.5).FontWeight(map[bool]int{true: 600, false: 500}[on]).TextColor(color).SingleLine()
	})
	return b.Clicked(), b.ClickModifiers()
}

func (a *App) conditionsBar(c *ui.Context) {
	p := a.pal
	fields := make([]string, len(store.Fields))
	for i, f := range store.Fields {
		fields[i] = fieldLabel(f)
	}
	ops := make([]string, len(store.Ops))
	for i, o := range store.Ops {
		ops[i] = opLabel(o)
	}
	ui.Column(c).FillWidth().Padding(6, inset).Gap(4).Background(p.surface).Children(func() {
		remove := -1
		for i := range a.conditions {
			cond := &a.conditions[i]
			ui.Row(c.Key(i)).Gap(6).AlignItems(ui.Center).Children(func() {
				ui.Checkbox(c, &cond.Enabled, "").Label(locales.UseThisCondition())
				field := fieldLabel(cond.Field)
				if ui.Select(c, &field, fields).Label(locales.Field()).Width(170).Changed() {
					if i := slices.Index(fields, field); i >= 0 {
						cond.Field = store.Fields[i]
					}
				}
				if cond.Field.NeedsKey() {
					placeholder := map[bool]string{true: "$.data.items[0].id", false: ".data.items[].id"}[cond.Field == store.FieldRequestJSONPath || cond.Field == store.FieldResponseJSONPath]
					key := ui.TextInput(c, &cond.Key).Placeholder(placeholder).Label(locales.Query()).Width(200)
					if msg := store.ValidKey(cond.Field, cond.Key); msg != "" && cond.Key != "" {
						key.Error(msg)
					}
				}
				op := opLabel(cond.Op)
				if ui.Select(c, &op, ops).Label(locales.Comparison()).Width(140).Changed() {
					if i := slices.Index(ops, op); i >= 0 {
						cond.Op = store.Ops[i]
					}
				}
				placeholder := locales.Value()
				if cond.Field.NeedsKey() {
					placeholder = locales.ValueOrEmptyForAnyThe()
				}
				in := ui.TextInput(c, &cond.Value).Placeholder(placeholder).Label(locales.Value()).Grow(1)
				if cond.Op == store.OpRegex {
					if msg := store.ValidRegexp(cond.Value); msg != "" && cond.Value != "" {
						in.Error(msg)
					}
				}
				if iconButton(c, "minus", locales.RemoveCondition(), p.muted).Clicked() {
					remove = i
				}
			})
		}
		if remove >= 0 {
			a.conditions = slices.Delete(a.conditions, remove, remove+1)
		}
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			if ui.Button(c, locales.AddCondition()).Clicked() {
				a.conditions = append(a.conditions, store.Condition{Enabled: true, Field: store.FieldURL, Op: store.OpContains})
			}
			mode := 0
			if a.matchAny {
				mode = 1
			}
			if ui.Segmented(c, &mode, locales.MatchAll(), locales.MatchAny()).Label(locales.Match()).Changed() {
				a.matchAny = mode == 1
			}
			ui.Spacer(c)
			if ui.Button(c, locales.SaveFilterEllipsis()).Tooltip(locales.KeepThisFilterToApplyFrom()).Clicked() {
				a.presetSave = presetSheet{open: true}
			}
			if ui.Button(c, locales.ClearFilters()).Clicked() {
				a.clearFilters()
			}
		})
	})
	ui.Divider(c)
}

func (a *App) setAdvanced(on bool) {
	a.advanced = on
	if on && len(a.conditions) == 0 {
		a.conditions = append(a.conditions, store.Condition{Enabled: true, Field: store.FieldURL, Op: store.OpContains})
	}
}

func (a *App) clearFilters() {
	a.query = ""
	a.deep = false
	clear(a.kinds)
	a.conditions = nil
	a.matchAny = false
	a.setAdvanced(a.advanced)
	if a.section != "overview" {
		a.section = "all"
	}
}

func (a *App) focusFilter() {
	if a.section == "overview" {
		a.section = "all"
	}
	a.filterFocus = true
}

func (a *App) routeBanner(c *ui.Context) {
	p := a.pal
	text := locales.MacOSDoesNotSendItsTraffic()
	if a.sys.Enabled() {
		text = locales.MacOSSendsItsTrafficToAnotherProxy(fmt.Sprintf("%s:%d", a.sys.Host, a.sys.Port))
	}
	ui.Row(c).FillWidth().Padding(6, inset).Gap(8).AlignItems(ui.Center).Background(p.blueSoft).Children(func() {
		glyph(c, "network", 14, p.blue)
		ui.Text(c, text).TextColor(p.text).Grow(1).Shrink(1)
		if ui.PrimaryButton(c, locales.OverrideMacOSProxy()).Tooltip(locales.PointMacOSAtProxyGoItIs()).Clicked() {
			a.setSystemProxy(true)
		}
		if plainIconButton(c, "xmark", locales.Hide(), 11, p.muted, p.hover).Clicked() {
			a.routeHintClosed = true
		}
	})
}

func (a *App) pauseBanner(c *ui.Context) {
	p := a.pal
	ui.Row(c).FillWidth().Padding(6, inset).Gap(8).AlignItems(ui.Center).Background(p.yellowSoft).Children(func() {
		glyph(c, "bug", 14, p.yellow)
		ui.Text(c, locales.FlowsPausedAtABreakpoint(len(a.pauses))).FontWeight(600).TextColor(p.text)
		ui.Spacer(c)
		if ui.PrimaryButton(c, locales.OpenBreakpointEditor()).Clicked() {
			a.openWindow("bpedit")
		}
	})
}

func (a *App) statusBar(c *ui.Context) {
	p := a.pal
	left := float32(inset)
	if !a.set.ShowSidebar {
		left = 16
	}
	ui.Divider(c)
	ui.Row(c).Height(footerHeight).FillWidth().Padding(0, inset, 0, left).Gap(10).AlignItems(ui.Center).Background(p.bg).Children(func() {
		auto := a.set.AutoSelect
		if ui.Toggle(c, &auto, locales.AutoSelect()).Tooltip(locales.SelectEachNewRequestAsIt()).Changed() {
			a.updateSettings(func(s *settings.Settings) { s.AutoSelect = auto })
		}
		a.toolChips(c)
		ui.Spacer(c)
		shown := locales.FlowsCount(len(a.flows))
		if len(a.visible) != len(a.flows) && a.section != "overview" {
			shown = locales.FlowsShownOf(len(a.visible), len(a.flows))
		}
		if n := a.chosen.Len(); n > 1 {
			shown = locales.SelectedCount(n) + " · " + shown
		}
		ui.Text(c, shown).FontSize(11).TextColor(p.muted).FontFeatures("tnum")
		if a.memory > 0 {
			ui.Text(c, formatBytes(a.memory)).FontSize(11).TextColor(p.muted).FontFeatures("tnum").
				Tooltip(locales.MemoryProxyGoUsesSettingsGeneralCan())
		}
		up, down := a.store.Traffic()
		ui.Row(c).Gap(3).AlignItems(ui.Center).Tooltip(locales.UploadedAndDownloadedWithTheCurrent()).Children(func() {
			glyph(c, "arrowUp", 10, p.muted)
			ui.Text(c, formatBytes(up)+" · "+formatRate(a.upRate)).FontSize(11).TextColor(p.muted).FontFeatures("tnum")
			ui.Box(c).Width(6)
			glyph(c, "arrowDown", 10, p.muted)
			ui.Text(c, formatBytes(down)+" · "+formatRate(a.downRate)).FontSize(11).TextColor(p.muted).FontFeatures("tnum")
		})
		switch {
		case a.systemProxyOn():
			ui.Text(c, locales.MacOSProxy()).FontSize(10).FontWeight(600).TextColor(p.green).Background(p.greenSoft).Padding(2, 6).Radius(4).
				Tooltip(locales.MacOSSendsItsHTTPAndHTTPS())
		case a.sys.Enabled():
			ui.Text(c, fmt.Sprintf("macOS → %s:%d", a.sys.Host, a.sys.Port)).FontSize(10).FontWeight(600).TextColor(p.text2).Background(p.graySoft).Padding(2, 6).Radius(4).
				Tooltip(locales.MacOSSendsItsTrafficToAnother())
		}
	})
}

func (a *App) toolChips(c *ui.Context) {
	p := a.pal
	d := a.rules.Current()
	count := func(n int, on bool) int {
		if !on {
			return 0
		}
		return n
	}
	enabled := func(n int, f func(int) bool) int {
		k := 0
		for i := range n {
			if f(i) {
				k++
			}
		}
		return k
	}
	chips := []struct {
		kind, icon, name string
		n                int
	}{
		{"ssl", "lock", locales.SSLProxying(), count(enabled(len(d.SSL.Rules), func(i int) bool { return d.SSL.Rules[i].Enabled }), d.SSL.Enabled)},
		{"breakpoint", "bug", locales.ToolBreakpoint(), count(enabled(len(d.Breakpoints), func(i int) bool { return d.Breakpoints[i].Enabled }), d.ToolOn(rules.ToolBreakpoint))},
		{"maplocal", "folder", locales.ToolMapLocal(), count(enabled(len(d.MapLocal), func(i int) bool { return d.MapLocal[i].Enabled }), d.ToolOn(rules.ToolMapLocal))},
		{"mapremote", "map", locales.ToolMapRemote(), count(enabled(len(d.MapRemote), func(i int) bool { return d.MapRemote[i].Enabled }), d.ToolOn(rules.ToolMapRemote))},
		{"scripting", "script", locales.ToolScripting(), count(enabled(len(d.Scripts), func(i int) bool { return d.Scripts[i].Enabled }), d.ToolOn(rules.ToolScripting))},
		{"block", "block", locales.ToolBlockList(), count(enabled(len(d.Block), func(i int) bool { return d.Block[i].Enabled }), d.ToolOn(rules.ToolBlock))},
		{"allow", "check", locales.ToolAllowList(), count(enabled(len(d.Allow), func(i int) bool { return d.Allow[i].Enabled }), d.ToolOn(rules.ToolAllow))},
		{"network", "speed", locales.ToolNetworkConditions(), count(enabled(len(d.NetworkConditions), func(i int) bool { return d.NetworkConditions[i].Enabled }), d.ToolOn(rules.ToolNetwork))},
		{"dns", "dns", locales.ToolDNSSpoofing(), count(enabled(len(d.DNS), func(i int) bool { return d.DNS[i].Enabled }), d.ToolOn(rules.ToolDNS))},
		{"reverse", "reverse", locales.ToolReverseProxy(), count(enabled(len(d.ReverseProxies), func(i int) bool { return d.ReverseProxies[i].Enabled }), d.ToolOn(rules.ToolReverse))},
	}
	for _, ch := range chips {
		if ch.n == 0 {
			continue
		}
		b := ui.ButtonBase(c).Label(ch.name).Tooltip(locales.ToolRulesOn(ch.name, ch.n)).Padding(2, 6).Radius(5)
		if b.Hovered() {
			b.Background(p.hover)
		}
		b.Children(func() {
			ui.Row(c).Gap(3).AlignItems(ui.Center).Children(func() {
				glyph(c, ch.icon, 11, p.accent)
				ui.Text(c, fmt.Sprint(ch.n)).FontSize(10.5).FontWeight(600).TextColor(p.accent)
			})
		})
		if b.Clicked() {
			a.openWindow(ch.kind)
		}
	}
	if d.NoCaching {
		ui.Text(c, locales.NoCaching()).FontSize(10).FontWeight(600).TextColor(p.orange).Tooltip(locales.ToolsNoCachingIsOn())
	}
}

func (a *App) commentSheet(c *ui.Context) {
	if !a.comment.open {
		return
	}
	ui.Modal(c, &a.comment.open, func() {
		ui.Column(c).Width(420).Gap(10).Children(func() {
			ui.Text(c, locales.Comment()).FontSize(15).FontWeight(600)
			if len(a.comment.ids) > 1 {
				ui.Text(c, locales.ForFlows(len(a.comment.ids))).TextColor(a.pal.muted)
			}
			ui.TextArea(c, &a.comment.text).Placeholder(locales.WhatIsThisRequestAbout()).Height(90).AutoFocus().Label(locales.Comment())
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					a.comment.open = false
				}
				if ui.PrimaryButton(c, locales.Save()).Clicked() || c.Shortcut(ui.Cmd, ui.KeyEnter) {
					a.saveComment()
				}
			})
		})
	})
}

func (a *App) repeatSheet(c *ui.Context) {
	if !a.repeat.open {
		return
	}
	ui.Modal(c, &a.repeat.open, func() {
		ui.Column(c).Width(380).Gap(12).Children(func() {
			ui.Text(c, locales.AdvancedRepeat()).FontSize(15).FontWeight(600)
			ui.Text(c, locales.SendRequestsAgain(len(a.repeat.msgs))).TextColor(a.pal.muted)
			ui.Form(c, func() {
				ui.Field(c, locales.Iterations(), func() { ui.NumberInput(c, &a.repeat.count, 1, 1000, 1).Width(110) })
				ui.Field(c, locales.Concurrency(), func() { ui.NumberInput(c, &a.repeat.concurrency, 1, 50, 1).Width(110) })
				ui.Field(c, locales.DelayMs(), func() { ui.NumberInput(c, &a.repeat.delay, 0, 60000, 100).Width(110) })
			})
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					a.repeat.open = false
				}
				if ui.PrimaryButton(c, locales.Start()).Clicked() {
					a.runAdvancedRepeat()
				}
			})
		})
	})
}

func iconButton(c *ui.Context, icon, label string, color ui.Color) ui.Element {
	b := ui.Button(c, "").Label(label).Tooltip(label)
	b.Children(func() { glyph(c, icon, 14, color) })
	return b
}

func plainIconButton(c *ui.Context, icon, label string, size float32, color, hover ui.Color) ui.Element {
	b := ui.ButtonBase(c).Label(label).Tooltip(label).Padding(3, 5).Radius(5)
	if b.Hovered() {
		b.Background(hover)
	}
	b.Children(func() { glyph(c, icon, size, color) })
	return b
}

func (a *App) searchField(c *ui.Context, key string, value *string, placeholder, label string) (ui.Element, ui.Element) {
	p := a.pal
	var input ui.Element
	box := ui.Row(c.Key(key)).Height(26).Gap(5).AlignItems(ui.Center).Padding(0, 6, 0, 8).Radius(6).Background(p.surface).Border(1, p.border)
	box.Children(func() {
		glyph(c, "search", 12, p.muted)
		input = ui.TextInputBase(c, value).Placeholder(placeholder).Label(label).Grow(1)
		if input.Shortcut(0, ui.KeyEscape) {
			*value = ""
		}
		if *value != "" && plainIconButton(c, "xmark", locales.Clear(), 10, p.muted, p.hover).KeepFocus().Clicked() {
			*value = ""
		}
	})
	if input.Focused() {
		box.Border(1, p.accent)
	}
	return box, input
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
