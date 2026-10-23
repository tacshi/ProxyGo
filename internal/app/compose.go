package app

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	ui "github.com/egoist/mygo/proxygoui"
	"github.com/egoist/mygo/proxygoui/editor"

	"proxygo/internal/curl"
	"proxygo/internal/flow"
	"proxygo/internal/formdata"
	"proxygo/internal/proxy"
	"proxygo/locales"
)

type headerRow struct {
	on          bool
	name, value string
}

type messageEditor struct {
	response bool
	method   string
	url      string
	status   float64
	headers  []headerRow
	body     *editor.State
	tab      int

	compose  bool
	kind     int
	parts    []partRow
	nextPart int
}

func newMessageEditor(m proxy.Message, response bool) *messageEditor {
	e := &messageEditor{response: response, method: cmp.Or(m.Method, http.MethodGet), url: m.URL, status: float64(m.StatusCode)}
	for _, h := range m.Header.Entries {
		if strings.HasPrefix(h.Key.Name, ":") {
			continue
		}
		e.headers = append(e.headers, headerRow{on: h.Enabled, name: h.Key.Name, value: h.Value})
	}
	buf := editor.NewBuffer(string(m.Body))
	if l := languageFor(m.Header.Get("Content-Type")); l != nil {
		buf.SetLanguage(l)
	}
	e.body = &editor.State{Buffer: buf, SoftWrap: true, Label: locales.TabBody(), Placeholder: locales.NoBody()}
	if len(m.Body) > 0 {
		e.tab = 1
	}
	return e
}

func (e *messageEditor) message() proxy.Message {
	m := proxy.Message{Method: strings.ToUpper(strings.TrimSpace(e.method)), URL: strings.TrimSpace(e.url), StatusCode: int(e.status)}
	for _, h := range e.headers {
		if strings.TrimSpace(h.name) == "" {
			continue
		}
		m.Header.Entries = append(m.Header.Entries, flow.HeaderEntry{
			Enabled: h.on, Key: flow.HeaderKey{Name: strings.TrimSpace(h.name), Lower: strings.ToLower(strings.TrimSpace(h.name))}, Value: h.value,
		})
	}
	m.Body = []byte(e.body.Buffer.String())
	switch e.kind {
	case bodyForm:
		m.Body = formdata.URLEncoded(e.formParts(false))
		m.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case bodyMultipart:
		if body, ct, err := formdata.Multipart(e.formParts(true)); err == nil {
			m.Body = body
			m.Header.Set("Content-Type", ct)
		}
	}
	for i := range m.Header.Entries {
		if strings.EqualFold(m.Header.Entries[i].Key.Name, "Content-Length") {
			m.Header.Entries[i].Value = fmt.Sprint(len(m.Body))
		}
	}
	return m
}

func (e *messageEditor) setHeader(name, value string) {
	for i := range e.headers {
		if strings.EqualFold(e.headers[i].name, name) {
			e.headers[i].value, e.headers[i].on = value, true
			return
		}
	}
	e.headers = append(e.headers, headerRow{on: true, name: name, value: value})
}

func (a *App) headersView(c *ui.Context, e *messageEditor) {
	p := a.pal
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(8, inset).Gap(4).Children(func() {
			remove := -1
			for i := range e.headers {
				h := &e.headers[i]
				ui.Row(c.Key(i)).Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Checkbox(c, &h.on, "").Label(locales.SendThisHeader())
					ui.TextInput(c, &h.name).Placeholder(locales.ColumnName()).Label(locales.HeaderName()).Width(190)
					ui.TextInput(c, &h.value).Placeholder(locales.Value()).Label(locales.HeaderValue()).Grow(1)
					if plainIconButton(c, "minus", locales.RemoveHeader(), 12, p.muted, p.hover).Clicked() {
						remove = i
					}
				})
			}
			if remove >= 0 {
				e.headers = slices.Delete(e.headers, remove, remove+1)
			}
			ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
				if ui.Button(c, locales.AddHeader()).Clicked() {
					e.headers = append(e.headers, headerRow{on: true})
				}
				for _, preset := range [][2]string{{"Content-Type", "application/json"}, {"Authorization", "Bearer "}, {"Accept", "application/json"}} {
					if ui.Button(c, preset[0]).Tooltip(locales.SetHeaderTo(preset[0] + ": " + preset[1])).Clicked() {
						e.setHeader(preset[0], preset[1])
					}
				}
			})
		})
	})
}

func (a *App) bodyEditor(c *ui.Context, e *messageEditor, key string) {
	p := a.pal
	form := e.kind == bodyForm || e.kind == bodyMultipart
	ui.Column(c).Fill().Children(func() {
		ui.Row(c).Height(34).FillWidth().Padding(0, inset).Gap(8).AlignItems(ui.Center).Children(func() {
			if e.compose {
				kind := e.kind
				if ui.Segmented(c, &kind, bodyKindLabels()...).Label(locales.BodyType()).Changed() {
					e.setKind(kind)
				}
			}
			if form {
				ui.Text(c, locales.FieldsCount(len(e.parts))).FontSize(11).TextColor(p.muted)
				return
			}
			ui.Text(c, formatSize(e.body.Buffer.Len())).FontSize(11).TextColor(p.muted)
			ui.Spacer(c)
			if ui.Button(c, locales.BeautifyJSON()).Clicked() {
				v := jsontext.Value(e.body.Buffer.String())
				if err := v.Indent(jsontext.WithIndent("  ")); err == nil {
					e.body.Buffer.Set(string(v))
				} else {
					a.toast(locales.TheBodyIsNotValidJSON())
				}
			}
			if ui.Button(c, locales.Minify()).Clicked() {
				v := jsontext.Value(e.body.Buffer.String())
				if err := v.Compact(); err == nil {
					e.body.Buffer.Set(string(v))
				}
			}
		})
		ui.Divider(c)
		if form {
			a.formView(c, e)
			return
		}
		editor.View(c.Key(key), e.body).Grow(1).FillWidth()
	})
}

type composeState struct {
	edit    *messageEditor
	sending bool
	cancel  context.CancelFunc
	result  string
	err     string
	notes   []string
	resTab  int
	sentAt  time.Time
	history []proxy.Message

	timeout      float64
	follow       bool
	maxRedirects int
	socket       string
	curl         curlSheet
}

const defaultComposeTimeout = 60

func newCompose(rawURL string) composeState {
	var h flow.Header
	h.Set("Accept", "*/*")
	return composeState{edit: newComposeEditor(proxy.Message{Method: http.MethodGet, URL: rawURL, Header: h}), timeout: defaultComposeTimeout}
}

func (st *composeState) keepOptions(from composeState) {
	st.history, st.timeout, st.follow, st.maxRedirects, st.socket = from.history, from.timeout, from.follow, from.maxRedirects, from.socket
}

func (a *App) composeFrom(f *flow.Flow) {
	switch {
	case f != nil && f.IsTunnel():
		if !a.decrypts(f) {
			a.toast(locales.EnableSSLProxyingToEdit(f.Host()))
			return
		}
		old := a.compose
		a.compose = newCompose(f.URL())
		a.compose.keepOptions(old)
	case f != nil:
		old := a.compose
		a.compose = composeState{edit: newComposeEditor(proxy.MessageOf(f))}
		a.compose.keepOptions(old)
		a.compose.edit.headers = slices.DeleteFunc(a.compose.edit.headers, func(h headerRow) bool {
			return slices.Contains([]string{"proxy-connection", "proxy-authorization"}, strings.ToLower(h.name))
		})
		if f.IsWebSocket() {
			a.compose.edit.url = strings.Replace(strings.Replace(f.URL(), "https://", "wss://", 1), "http://", "ws://", 1)
			a.compose.edit.headers = slices.DeleteFunc(a.compose.edit.headers, func(h headerRow) bool {
				return slices.Contains([]string{"upgrade", "connection", "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions"}, strings.ToLower(h.name))
			})
		}
		a.compose.edit.tab = map[bool]int{true: 2, false: 0}[len(f.Request.BodyData) > 0]
	case a.compose.edit == nil:
		a.compose = newCompose("https://")
	}
	a.openWindow("compose")
}

func (a *App) sendCompose() {
	st := &a.compose
	msg := st.edit.message()
	ws := isWebSocketURL(msg.URL)
	if !ws {
		if _, err := parseURL(msg.URL); err != nil {
			st.err = err.Error()
			return
		}
	}
	a.closeComposeSocket()
	st.sending, st.err, st.result, st.sentAt, st.notes = true, "", "", time.Now(), nil
	st.history = append([]proxy.Message{msg}, slices.DeleteFunc(slices.Clone(st.history), func(m proxy.Message) bool {
		return m.Method == msg.Method && m.URL == msg.URL
	})...)
	if len(st.history) > 20 {
		st.history = st.history[:20]
	}
	if ws {
		a.connectCompose(msg)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	st.cancel = cancel
	opts := proxy.ReplayOptions{Timeout: time.Duration(st.timeout * float64(time.Second)), FollowRedirects: st.follow, MaxRedirects: st.maxRedirects}
	go func() {
		defer cancel()
		f, err := a.proxy.ReplayWith(ctx, msg, opts)
		a.do(func() {
			st.sending, st.cancel = false, nil
			switch {
			case errors.Is(err, context.Canceled):
				st.err = locales.Canceled()
				return
			case errors.Is(err, context.DeadlineExceeded):
				st.err = locales.NoResponseWithin(fmt.Sprintf("%g", st.timeout))
				return
			case errors.Is(err, proxy.ErrTooManyRedirects) && f != nil:
				st.err = err.Error()
			case err != nil:
				st.err = err.Error()
				return
			}
			st.result = f.UniqueID
			if st.result != "" {
				if _, ok := a.store.Lookup(st.result); !ok {
					a.store.Upsert(f.Clone())
				}
			}
		})
	}()
}

func (a *App) composeWindow(c *ui.Context) {
	p := a.pal
	st := &a.compose
	if st.edit == nil {
		*st = newCompose("https://")
	}
	e := st.edit
	send := false
	ws := isWebSocketURL(e.url)
	open := st.socket != "" && a.proxy.WebSocketOpen(st.socket)
	if st.socket != "" && !open {
		st.socket = ""
	}
	a.curlSheetView(c)
	ui.Row(c).FillWidth().Padding(10, inset, 6, inset).Gap(8).AlignItems(ui.Center).Children(func() {
		if ws {
			ui.Text(c, "WebSocket").FontSize(11).FontWeight(650).TextColor(p.purple).Background(p.purpleSoft).Padding(5, 8).Radius(6)
		} else {
			ui.Combobox(c, &e.method, []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}).Label(locales.ColumnMethod()).Width(110)
		}
		before := e.url
		in := ui.TextInput(c.Key("url"), &e.url).Placeholder(locales.HTTPSAPIExampleComV1Items()).Label("URL").Grow(1).AutoFocus()
		if in.Changed() && len(e.url) > len(before)+1 && curl.Looks(e.url) {
			if cmd, err := curl.Parse(e.url); err == nil {
				a.composeCurl(cmd)
				e = st.edit
			}
		}
		if in.Submitted() {
			send = true
		}
		if st.sending {
			ui.Spinner(c)
			if ui.Button(c, locales.Cancel()).Clicked() && st.cancel != nil {
				st.cancel()
			}
		}
		if open {
			if ui.Button(c, locales.Disconnect()).Tooltip(locales.CloseTheWebSocket()).Clicked() {
				a.closeComposeSocket()
			}
		} else {
			label := map[bool]string{true: locales.Connect(), false: locales.Send()}[ws]
			if ui.PrimaryButton(c, label).Disabled(st.sending).Tooltip(label+" (⌘↩)").Clicked() || c.Shortcut(ui.Cmd, ui.KeyEnter) {
				send = true
			}
		}
		if len(st.history) > 0 {
			ui.Button(c, "").Label(locales.History()).Tooltip(locales.RequestsSent()).Children(func() { glyph(c, "clock", 13, p.text2) }).Menu(func(m *ui.Menu) {
				for _, h := range st.history {
					if m.Item(h.Method + " " + shorten(h.URL, 80)).Chosen() {
						st.edit = newMessageEditor(h, false)
					}
				}
			})
		}
	})
	ui.Row(c).FillWidth().Padding(0, inset, 8, inset).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.MenuButton(c, locales.New(), func(m *ui.Menu) {
			for _, name := range composeTemplates {
				if m.Item(composeTemplateLabel(name)).Chosen() {
					a.composeTemplate(name)
				}
			}
		})
		if ui.Button(c, locales.ImportFromCURLEllipsis()).Clicked() {
			a.openCurlSheet()
		}
		ui.Spacer(c)
		if !ws {
			ui.Checkbox(c, &st.follow, locales.FollowRedirects()).Tooltip(locales.Follow3xxAnswersToWhereThey())
			ui.Box(c).Width(8)
		}
		ui.Text(c, locales.Timeout()).TextColor(p.text2)
		ui.NumberInput(c, &st.timeout, 0, 3600, 1).Width(110).Label(locales.TimeoutInSeconds()).Tooltip(locales.SecondsToWaitForTheResponse())
		ui.Text(c, locales.Seconds()).TextColor(p.muted)
	})
	if send && !st.sending {
		a.sendCompose()
	}
	if st.err != "" {
		ui.Text(c, st.err).TextColor(p.red).Padding(0, inset, 6, inset).Wrap()
	}
	for _, n := range st.notes {
		ui.Text(c, n).FontSize(11).TextColor(p.yellow).Padding(0, inset, 4, inset).Wrap()
	}
	ui.Divider(c)
	ui.SplitVerticalPercent(c, &a.composeSplit, func() {
		ui.Column(c).Fill().Children(func() {
			tabs := []string{"Headers", "Query", "Body"}
			if ws {
				tabs = tabs[:2]
				if e.tab > 1 {
					e.tab = 0
				}
			}
			paneHeader(c, p, locales.PhaseRequest(), &e.tab, tabs, func() {
				ui.Text(c, locales.HeadersCount(len(e.headers))).FontSize(11).TextColor(p.muted)
			})
			switch tabs[e.tab] {
			case "Headers":
				a.headersView(c, e)
			case "Query":
				a.queryEditor(c, e)
			case "Body":
				a.bodyEditor(c, e, "composeBody")
			}
		})
	}, func() {
		ui.Column(c).Fill().Children(func() {
			f, _ := a.store.Lookup(st.result)
			if f == nil {
				paneHeader(c, p, locales.PhaseResponse(), &st.resTab, nil, nil)
				if st.sending {
					centered(c, 8, func() {
						ui.Spinner(c)
						ui.Text(c, locales.SendingEllipsis()).TextColor(p.muted)
					})
				} else {
					emptyState(c, p, map[bool]string{true: locales.ConnectToSendAndSeeMessages(), false: locales.SendTheRequestToSeeItsResponse()}[ws])
				}
				return
			}
			if f.IsWebSocket() && f.StatusCode() == http.StatusSwitchingProtocols {
				paneHeader(c, p, locales.TabMessages(), &st.resTab, nil, func() {
					ui.Text(c, f.StatusLine()).FontSize(10.5).FontWeight(650).TextColor(p.purple).Background(p.purpleSoft).Padding(2, 7).Radius(5)
				})
				a.messages(c, f)
				return
			}
			paneHeader(c, p, locales.PhaseResponse(), &st.resTab, []string{"Body", "Header", "Raw"}, func() {
				bg, tc := p.flowColors(f)
				ui.Text(c, f.StatusLine()).FontSize(10.5).FontWeight(650).TextColor(tc).Background(bg).Padding(2, 7).Radius(5)
				ui.Text(c, flowDuration(f)+" · "+formatSize(f.ResponseBodySize())).FontSize(11).TextColor(p.muted)
			})
			switch {
			case f.IsError():
				a.errorPane(c, f)
			case f.IsActive():
				emptyState(c, p, locales.WaitingForTheResponse())
			case st.resTab == 0:
				a.bodyView(c, f, true, "compose")
			case st.resTab == 1:
				a.headerTable(c, f.Response.Header, "response")
			default:
				a.textViewer(c, f.UniqueID+":composeRaw", rawResponse(f), "", locales.RawResponse())
			}
		})
	}).Grow(1)
}

func (a *App) queryEditor(c *ui.Context, e *messageEditor) {
	p := a.pal
	u, err := url.Parse(e.url)
	if err != nil {
		emptyState(c, p, locales.TheURLIsNotValid())
		return
	}
	type pair struct{ k, v string }
	var rows []pair
	for part := range strings.SplitSeq(u.RawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		rows = append(rows, pair{k, v})
	}
	changed := false
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(8, inset).Gap(4).Children(func() {
			remove := -1
			for i := range rows {
				r := &rows[i]
				ui.Row(c.Key(i)).Gap(6).AlignItems(ui.Center).Children(func() {
					if ui.TextInput(c, &r.k).Placeholder(locales.ColumnName()).Label(locales.Parameter()).Width(190).Changed() {
						changed = true
					}
					if ui.TextInput(c, &r.v).Placeholder(locales.Value()).Label(locales.Value()).Grow(1).Changed() {
						changed = true
					}
					if plainIconButton(c, "minus", locales.RemoveParameter(), 12, p.muted, p.hover).Clicked() {
						remove = i
					}
				})
			}
			if remove >= 0 {
				rows = slices.Delete(rows, remove, remove+1)
				changed = true
			}
			if ui.Button(c, locales.AddParameter()).AlignSelf(ui.Start).Clicked() {
				rows = append(rows, pair{"name", ""})
				changed = true
			}
		})
	})
	if changed {
		var parts []string
		for _, r := range rows {
			parts = append(parts, url.QueryEscape(r.k)+"="+url.QueryEscape(r.v))
		}
		u.RawQuery = strings.Join(parts, "&")
		e.url = u.String()
	}
}

func (a *App) breakpointEditor(c *ui.Context) {
	p := a.pal
	a.windowHeader(c, locales.ToolBreakpoint(), locales.EditAPausedRequestBeforeIt(), func() {
		if len(a.pauses) > 1 {
			if ui.Button(c, locales.AbortAll()).Clicked() {
				for _, pd := range slices.Clone(a.pauses) {
					a.resolvePause(pd.ID, false, false)
				}
			}
			if ui.Button(c, locales.ContinueAll()).Clicked() {
				for _, pd := range slices.Clone(a.pauses) {
					a.resolvePause(pd.ID, true, true)
				}
			}
		}
		if ui.Button(c, locales.RulesEllipsis()).Clicked() {
			a.openWindow("breakpoint")
		}
	})
	if len(a.pauses) == 0 {
		ui.Column(c).Grow(1).Center().Gap(10).Children(func() {
			glyph(c, "bug", 30, p.faint)
			ui.Text(c, locales.NothingIsPaused()).FontSize(15).FontWeight(600).TextColor(p.text2)
			d := a.rules.Current()
			n := 0
			for _, r := range d.Breakpoints {
				if r.Enabled {
					n++
				}
			}
			switch {
			case n == 0:
				ui.Text(c, locales.AddABreakpointRuleOrChoose()).TextColor(p.muted)
			case !d.ToolOn("breakpoint"):
				ui.Text(c, locales.BreakpointsAreSwitchedOff()).TextColor(p.yellow)
			default:
				ui.Text(c, locales.RequestsMatchingRulesPauseHere(n)).TextColor(p.muted)
			}
			if ui.Button(c, locales.BreakpointRulesEllipsis()).Clicked() {
				a.openWindow("breakpoint")
			}
		})
		return
	}
	var chosen *pending
	for _, pd := range a.pauses {
		if pd.ID == a.bpChosen {
			chosen = pd
		}
	}
	if chosen == nil {
		chosen = a.pauses[0]
		a.bpChosen = chosen.ID
	}
	ui.Divider(c)
	if a.bpListWidth == 0 {
		a.bpListWidth = 300
	}
	ui.Split(c, &a.bpListWidth, func() {
		ui.Scroll(c).Fill().Background(p.sidebar).Children(func() {
			ui.Column(c).FillWidth().Padding(6).Gap(2).Children(func() {
				for _, pd := range a.pauses {
					row := ui.Column(c.Key(pd.ID)).FillWidth().Padding(6, 8).Gap(2).Radius(6)
					if pd.ID == a.bpChosen {
						row.Background(p.accent.Alpha(0.15))
					} else if row.Hovered() {
						row.Background(p.hover)
					}
					if row.Clicked() {
						a.bpChosen = pd.ID
					}
					row.Children(func() {
						ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
							phase := map[bool]string{true: locales.PhaseResponse(), false: locales.PhaseRequest()}[pd.Response]
							ui.Text(c, phase).FontSize(9.5).FontWeight(700).TextColor(p.purple).Background(p.purpleSoft).Padding(1, 5).Radius(4)
							ui.Text(c, pd.Flow.MethodName()).FontSize(10).FontWeight(650).TextColor(p.pillText)
							ui.Spacer(c)
							ui.Text(c, time.Since(pd.at).Round(time.Second).String()).FontSize(10).TextColor(p.faint)
						})
						ui.Text(c, pd.Flow.URL()).FontSize(11).TextColor(p.text2).SingleLine()
					})
				}
			})
		})
	}, func() {
		a.pausedEditor(c, chosen)
	}).Grow(1)
	c.After(time.Second)
}

func (a *App) pausedEditor(c *ui.Context, pd *pending) {
	p := a.pal
	a.templateSheetView(c)
	e := pd.edit
	ui.Column(c.Key(pd.ID)).Fill().Children(func() {
		ui.Row(c).FillWidth().Padding(10, 14).Gap(8).AlignItems(ui.Center).Children(func() {
			if pd.Response {
				ui.Text(c, locales.Status()).TextColor(p.muted)
				ui.NumberInput(c, &e.status, 100, 599, 1).Width(100).Label(locales.StatusCodeLabel())
				ui.Text(c, http.StatusText(int(e.status))).TextColor(p.text2)
				ui.Spacer(c)
				ui.Text(c, shorten(pd.Message.URL, 70)).FontSize(11).TextColor(p.muted).SingleLine()
			} else {
				ui.Combobox(c, &e.method, []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}).Label(locales.ColumnMethod()).Width(110)
				ui.TextInput(c, &e.url).Label("URL").Grow(1)
			}
		})
		ui.Row(c).FillWidth().Padding(0, 14, 6, 14).Children(func() {
			ui.Text(c, locales.RuleName(pd.Rule)).FontSize(11).TextColor(p.muted)
		})
		ui.Divider(c)
		tabs := []string{"Headers", "Body"}
		paneHeader(c, p, map[bool]string{true: locales.PhaseResponse(), false: locales.PhaseRequest()}[pd.Response], &e.tab, tabs, nil)
		ui.Column(c).Grow(1).Children(func() {
			if e.tab == 0 {
				a.headersView(c, e)
			} else {
				a.bodyEditor(c, e, "bpBody"+pd.ID)
			}
		})
		ui.Divider(c)
		ui.Row(c).FillWidth().Padding(10, 14).Gap(8).AlignItems(ui.Center).Children(func() {
			a.pauseActions(c, pd)
			ui.Spacer(c)
			if ui.Button(c, locales.ContinueWithoutChanges()).Clicked() {
				a.resolvePause(pd.ID, true, false)
			}
			if ui.PrimaryButton(c, locales.Execute()).Tooltip(map[bool]string{true: locales.SendTheEditedResponse(), false: locales.SendTheEditedRequest()}[pd.Response]).Clicked() || c.Shortcut(ui.Cmd, ui.KeyEnter) {
				if !pd.Response {
					if _, err := parseURL(e.url); err != nil {
						a.toast(err.Error())
						return
					}
				}
				a.resolvePause(pd.ID, true, true)
			}
		})
	})
}
