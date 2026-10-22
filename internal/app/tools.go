package app

import (
	"cmp"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"
	"github.com/egoist/mygo/proxygoui/editor"

	"proxygo/internal/certs"
	"proxygo/internal/rules"
	"proxygo/locales"
)

type toolState struct {
	list    ui.ListState
	row     int
	query   string
	editing bool
	isNew   bool
	draft   any
	test    string
	err     string
	body    *editor.State
	headers string
	tab     int
	newHost string
	secret  string
	profile string
	pick    string
}

func (a *App) toolState(kind string) *toolState {
	t := a.tools[kind]
	if t == nil {
		t = &toolState{row: -1}
		a.tools[kind] = t
	}
	return t
}

type ruleKind struct {
	tool        string
	title       func() string
	about       func() string
	add         func() string
	noun        func() string
	columns     func() []ui.TableColumn
	ids         func(d *rules.Data) []string
	enabled     func(d *rules.Data, id string) *bool
	matcher     func(d *rules.Data, id string) *rules.Matcher
	cells       func(d *rules.Data, id string) []string
	folder      func(d *rules.Data, id string) *string
	extra       func(a *App, c *ui.Context)
	empty, hint func() string
	fresh       func() any
	copyOf      func(d *rules.Data, id string) any
	form        func(a *App, c *ui.Context, t *toolState) string
	save        func(d *rules.Data, draft any)
	remove      func(d *rules.Data, id string)
}

var methods = []string{"ANY", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

func byID[T any](list []*T, id string, get func(*T) string) *T {
	for _, r := range list {
		if r != nil && get(r) == id {
			return r
		}
	}
	return nil
}

func putByID[T any](list []*T, v *T, get func(*T) string) []*T {
	for i, r := range list {
		if r != nil && get(r) == get(v) {
			list[i] = v
			return list
		}
	}
	return append(list, v)
}

func dropByID[T any](list []*T, id string, get func(*T) string) []*T {
	return slices.DeleteFunc(list, func(r *T) bool { return r == nil || get(r) == id })
}

func ids[T any](list []*T, get func(*T) string) []string {
	out := make([]string, 0, len(list))
	for _, r := range list {
		if r != nil {
			out = append(out, get(r))
		}
	}
	return out
}

func clone[T any](v *T) *T {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func methodLabel(m string) string { return cmp.Or(strings.ToUpper(m), "ANY") }

func matchSummary(m rules.Matcher) string {
	s := m.URL
	if m.Match == "regex" {
		s = locales.RegexSummary(s)
	}
	if m.GraphQL != "" {
		s += "  " + locales.GraphQLSummary(m.GraphQL)
	}
	return s
}

func mlID(r *rules.MapLocalRule) string     { return r.ID }
func mrID(r *rules.MapRemoteRule) string    { return r.ID }
func bpID(r *rules.BreakpointRule) string   { return r.ID }
func urlID(r *rules.URLRule) string         { return r.ID }
func ncID(r *rules.NetworkCondition) string { return r.ID }
func dnsID(r *rules.DNSRule) string         { return r.ID }
func rvID(r *rules.ReverseProxy) string     { return r.ID }
func ccID(r *rules.ClientCertificate) string {
	return r.ID
}

var ruleKinds = map[string]*ruleKind{
	"maplocal": {
		tool: rules.ToolMapLocal, title: locales.ToolMapLocal, add: locales.NewRule, noun: locales.MapLocalRule,
		about: locales.AnswerMatchingRequestsWithALocal,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnName(), Width: 160}, {Title: locales.ColumnMatchingRule()}, {Title: locales.ColumnMethod(), Width: 70}, {Title: locales.ColumnResponse(), Width: 200}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.MapLocal, mlID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.MapLocal, id, mlID).Enabled },
		matcher: func(d *rules.Data, id string) *rules.Matcher { return &byID(d.MapLocal, id, mlID).Matcher },
		folder:  func(d *rules.Data, id string) *string { return &byID(d.MapLocal, id, mlID).Folder },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.MapLocal, id, mlID)
			resp := r.Path
			if resp == "" {
				resp = fmt.Sprintf("%d · %s", cmp.Or(r.StatusCode, 200), formatSize(len(r.Body)))
			}
			return []string{r.Name, matchSummary(r.Matcher), methodLabel(r.Method), resp}
		},
		fresh: func() any {
			return &rules.MapLocalRule{ID: rules.NewID(), Enabled: true, Matcher: rules.Matcher{URL: "https://"}, StatusCode: 200, Body: "{\n  \n}"}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.MapLocal, id, mlID)) },
		form:   mapLocalForm,
		save:   func(d *rules.Data, v any) { d.MapLocal = putByID(d.MapLocal, v.(*rules.MapLocalRule), mlID) },
		remove: func(d *rules.Data, id string) { d.MapLocal = dropByID(d.MapLocal, id, mlID) },
	},
	"mapremote": {
		tool: rules.ToolMapRemote, title: locales.ToolMapRemote, add: locales.NewRule, noun: locales.MapRemoteRule,
		about: locales.SendMatchingRequestsToAnotherURL,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnName(), Width: 150}, {Title: locales.ColumnFrom()}, {Title: locales.ColumnMethod(), Width: 70}, {Title: locales.ColumnTo()}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.MapRemote, mrID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.MapRemote, id, mrID).Enabled },
		matcher: func(d *rules.Data, id string) *rules.Matcher { return &byID(d.MapRemote, id, mrID).Matcher },
		folder:  func(d *rules.Data, id string) *string { return &byID(d.MapRemote, id, mrID).Folder },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.MapRemote, id, mrID)
			return []string{r.Name, matchSummary(r.Matcher), methodLabel(r.Method), remoteTarget(r)}
		},
		fresh: func() any {
			return &rules.MapRemoteRule{ID: rules.NewID(), Enabled: true, Matcher: rules.Matcher{URL: "https://", IncludeSubpaths: true}}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.MapRemote, id, mrID)) },
		form:   mapRemoteForm,
		save:   func(d *rules.Data, v any) { d.MapRemote = putByID(d.MapRemote, v.(*rules.MapRemoteRule), mrID) },
		remove: func(d *rules.Data, id string) { d.MapRemote = dropByID(d.MapRemote, id, mrID) },
	},
	"breakpoint": {
		tool: rules.ToolBreakpoint, title: locales.BreakpointRules, add: locales.NewBreakpoint, noun: locales.BreakpointRule,
		about: locales.PauseMatchingRequestsBeforeTheyGo,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnName(), Width: 160}, {Title: locales.ColumnMatchingRule()}, {Title: locales.ColumnMethod(), Width: 70}, {Title: locales.ColumnPauses(), Width: 150}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.Breakpoints, bpID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.Breakpoints, id, bpID).Enabled },
		matcher: func(d *rules.Data, id string) *rules.Matcher { return &byID(d.Breakpoints, id, bpID).Matcher },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.Breakpoints, id, bpID)
			return []string{r.Name, matchSummary(r.Matcher), methodLabel(r.Method), map[string]string{rules.PhaseRequest: locales.PhaseRequest(), rules.PhaseResponse: locales.PhaseResponse()}[r.Phase] + map[bool]string{true: locales.RequestAndResponse()}[r.Phase == rules.PhaseBoth || r.Phase == ""]}
		},
		fresh: func() any {
			return &rules.BreakpointRule{ID: rules.NewID(), Enabled: true, Matcher: rules.Matcher{URL: "https://"}, Phase: rules.PhaseBoth}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.Breakpoints, id, bpID)) },
		form:   breakpointForm,
		save:   func(d *rules.Data, v any) { d.Breakpoints = putByID(d.Breakpoints, v.(*rules.BreakpointRule), bpID) },
		remove: func(d *rules.Data, id string) { d.Breakpoints = dropByID(d.Breakpoints, id, bpID) },
	},
	"block": {
		tool: rules.ToolBlock, title: locales.ToolBlockList, add: locales.BlockAURL, noun: locales.BlockedURL,
		about: locales.StopMatchingRequestsBeforeTheyReach,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnName(), Width: 160}, {Title: locales.ColumnMatchingRule()}, {Title: locales.ColumnMethod(), Width: 70}, {Title: locales.ColumnAction(), Width: 140}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.Block, urlID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.Block, id, urlID).Enabled },
		matcher: func(d *rules.Data, id string) *rules.Matcher { return &byID(d.Block, id, urlID).Matcher },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.Block, id, urlID)
			return []string{r.Name, matchSummary(r.Matcher), methodLabel(r.Method), map[string]string{rules.BlockDisplay: locales.BlockAndDisplay(), rules.BlockHide: locales.BlockAndHide()}[r.Action]}
		},
		fresh: func() any {
			return &rules.URLRule{ID: rules.NewID(), Enabled: true, Matcher: rules.Matcher{URL: "https://"}}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.Block, id, urlID)) },
		form:   func(a *App, c *ui.Context, t *toolState) string { return urlRuleForm(a, c, t, true) },
		save:   func(d *rules.Data, v any) { d.Block = putByID(d.Block, v.(*rules.URLRule), urlID) },
		remove: func(d *rules.Data, id string) { d.Block = dropByID(d.Block, id, urlID) },
	},
	"allow": {
		tool: rules.ToolAllow, title: locales.ToolAllowList, add: locales.AllowAURL, noun: locales.AllowedURL,
		about: locales.WhileThisListHasRulesProxyGo,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnName(), Width: 160}, {Title: locales.ColumnMatchingRule()}, {Title: locales.ColumnMethod(), Width: 70}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.Allow, urlID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.Allow, id, urlID).Enabled },
		matcher: func(d *rules.Data, id string) *rules.Matcher { return &byID(d.Allow, id, urlID).Matcher },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.Allow, id, urlID)
			return []string{r.Name, matchSummary(r.Matcher), methodLabel(r.Method)}
		},
		fresh: func() any {
			return &rules.URLRule{ID: rules.NewID(), Enabled: true, Matcher: rules.Matcher{URL: "https://"}}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.Allow, id, urlID)) },
		form:   func(a *App, c *ui.Context, t *toolState) string { return urlRuleForm(a, c, t, false) },
		save:   func(d *rules.Data, v any) { d.Allow = putByID(d.Allow, v.(*rules.URLRule), urlID) },
		remove: func(d *rules.Data, id string) { d.Allow = dropByID(d.Allow, id, urlID) },
	},
	"network": {
		tool: rules.ToolNetwork, title: locales.ToolNetworkConditions, add: locales.NewCondition,
		about: locales.SlowMatchingTrafficDownAddLatency,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnProfile(), Width: 140}, {Title: locales.ColumnMatchingRule()}, {Title: locales.ColumnLatency(), Width: 80}, {Title: locales.ColumnDownload(), Width: 90}, {Title: locales.ColumnUpload(), Width: 90}, {Title: locales.ColumnLoss(), Width: 60}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.NetworkConditions, ncID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.NetworkConditions, id, ncID).Enabled },
		matcher: func(d *rules.Data, id string) *rules.Matcher { return &byID(d.NetworkConditions, id, ncID).Matcher },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.NetworkConditions, id, ncID)
			kbps := func(v float64) string {
				if v <= 0 {
					return "∞"
				}
				return fmt.Sprintf("%.0f KB/s", v)
			}
			return []string{r.Name, matchSummary(r.Matcher), fmt.Sprintf("%d ms", r.LatencyMS), kbps(r.DownloadKBps), kbps(r.UploadKBps), fmt.Sprintf("%.0f%%", r.PacketLoss)}
		},
		fresh: func() any {
			p := rules.Presets[2]
			return &rules.NetworkCondition{ID: rules.NewID(), Enabled: true, Name: p.Name, LatencyMS: p.LatencyMS, DownloadKBps: p.DownloadKBps, UploadKBps: p.UploadKBps}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.NetworkConditions, id, ncID)) },
		form:   networkForm,
		save: func(d *rules.Data, v any) {
			d.NetworkConditions = putByID(d.NetworkConditions, v.(*rules.NetworkCondition), ncID)
		},
		remove: func(d *rules.Data, id string) { d.NetworkConditions = dropByID(d.NetworkConditions, id, ncID) },
	},
	"dns": {
		tool: rules.ToolDNS, title: locales.ToolDNSSpoofing, add: locales.NewEntry, noun: locales.DNSEntry,
		about: locales.ResolveAHostToTheAddress,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnHost()}, {Title: locales.ColumnAddress(), Width: 200}, {Title: locales.ColumnPort(), Width: 80}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.DNS, dnsID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.DNS, id, dnsID).Enabled },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.DNS, id, dnsID)
			port := locales.SamePort()
			if r.Port > 0 {
				port = strconv.Itoa(r.Port)
			}
			return []string{r.Host, r.IP, port}
		},
		fresh:  func() any { return &rules.DNSRule{ID: rules.NewID(), Enabled: true, IP: "127.0.0.1"} },
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.DNS, id, dnsID)) },
		form:   dnsForm,
		save:   func(d *rules.Data, v any) { d.DNS = putByID(d.DNS, v.(*rules.DNSRule), dnsID) },
		remove: func(d *rules.Data, id string) { d.DNS = dropByID(d.DNS, id, dnsID) },
	},
	"reverse": {
		tool: rules.ToolReverse, title: locales.ToolReverseProxy, add: locales.NewReverseProxy,
		about: locales.ListenOnALocalPortAnd,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnLocalPort(), Width: 110}, {Title: locales.ColumnForwardsTo()}, {Title: locales.ColumnHostHeader(), Width: 120}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.ReverseProxies, rvID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.ReverseProxies, id, rvID).Enabled },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.ReverseProxies, id, rvID)
			return []string{fmt.Sprintf("localhost:%d", r.ListenPort), r.Target, map[bool]string{true: locales.HostPreserved(), false: locales.HostTargets()}[r.PreserveHost]}
		},
		fresh: func() any {
			return &rules.ReverseProxy{ID: rules.NewID(), Enabled: true, ListenPort: 8080, Target: "https://"}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.ReverseProxies, id, rvID)) },
		form:   reverseForm,
		save: func(d *rules.Data, v any) {
			d.ReverseProxies = putByID(d.ReverseProxies, v.(*rules.ReverseProxy), rvID)
		},
		remove: func(d *rules.Data, id string) { d.ReverseProxies = dropByID(d.ReverseProxies, id, rvID) },
	},
	"clientcerts": {
		title: locales.ClientCertificates, add: locales.AddCertificate,
		about: locales.PresentACertificateToServersThat,
		empty: locales.NoCertificatesYet, hint: locales.AddACertificateForTheHosts,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnHost(), Width: 200}, {Title: locales.ColumnCertificate()}, {Title: locales.ColumnKey()}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.ClientCerts, ccID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.ClientCerts, id, ccID).Enabled },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.ClientCerts, id, ccID)
			if r.P12Path != "" {
				return []string{r.Host, r.P12Path, locales.InTheBundle()}
			}
			return []string{r.Host, r.CertPath, cmp.Or(r.KeyPath, locales.InTheCertificateFile())}
		},
		fresh:  func() any { return &rules.ClientCertificate{ID: rules.NewID(), Enabled: true} },
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.ClientCerts, id, ccID)) },
		form:   clientCertForm,
		save:   func(d *rules.Data, v any) { d.ClientCerts = putByID(d.ClientCerts, v.(*rules.ClientCertificate), ccID) },
		remove: func(d *rules.Data, id string) {
			if r := byID(d.ClientCerts, id, ccID); r != nil && r.PasswordRef != "" {
				_ = certs.Keychain.Delete(r.PasswordRef)
			}
			d.ClientCerts = dropByID(d.ClientCerts, id, ccID)
		},
	},
}

func remoteTarget(r *rules.MapRemoteRule) string {
	if r.NewURL != "" {
		return r.NewURL
	}
	var parts []string
	for _, kv := range [][2]string{{"scheme", r.Scheme}, {"host", r.Host}, {"port", map[bool]string{true: strconv.Itoa(r.Port)}[r.Port > 0]}, {"path", r.Path}, {"query", r.Query}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+" "+kv[1])
		}
	}
	return strings.Join(parts, ", ")
}

func (a *App) openDraft(kind string, draft any) {
	a.beginEdit(kind, a.toolState(kind), draft, true)
	a.openWindow(kind)
}

func (a *App) beginEdit(kind string, t *toolState, draft any, isNew bool) {
	t.editing, t.isNew, t.draft, t.err = true, isNew, draft, ""
	t.test, t.body, t.headers, t.tab = "", nil, "", 0
	if r, ok := draft.(*rules.MapLocalRule); ok {
		buf := editor.NewBuffer(r.Body)
		if l := languageFor(cmp.Or(r.ContentType, "application/json")); l != nil {
			buf.SetLanguage(l)
		}
		t.body = &editor.State{Buffer: buf, Label: locales.ResponseBody(), SoftWrap: true}
		var lines []string
		for _, h := range r.Headers {
			lines = append(lines, h.Name+": "+h.Value)
		}
		t.headers = strings.Join(lines, "\n")
		if r.Path != "" {
			t.tab = 1
		}
	}
	if r, ok := draft.(*rules.BreakpointTemplate); ok {
		t.body = &editor.State{Buffer: editor.NewBuffer(r.Raw), Label: locales.Template(), SoftWrap: true}
	}
	switch r := draft.(type) {
	case *rules.ServerCertificate:
		t.tab = map[bool]int{true: 1}[r.P12Path != ""]
	case *rules.ClientCertificate:
		t.tab = map[bool]int{true: 1}[r.P12Path != ""]
	}
	t.secret, t.profile = "", ""
	_ = kind
}

func (a *App) ruleWindow(c *ui.Context, kind string) {
	p := a.pal
	k := ruleKinds[kind]
	t := a.toolState(kind)
	d := a.rules.Current()
	all := k.ids(d)
	columns := k.columns()
	base := len(columns)
	if k.folder != nil {
		slices.SortStableFunc(all, func(x, y string) int { return strings.Compare(*k.folder(d, x), *k.folder(d, y)) })
		if slices.ContainsFunc(all, func(id string) bool { return *k.folder(d, id) != "" }) {
			columns = append([]ui.TableColumn{{Title: locales.ColumnFolder(), Width: 120}}, columns...)
		}
	}
	cells := func(id string) []string {
		out := k.cells(d, id)
		if len(columns) > base {
			out = append([]string{*k.folder(d, id)}, out...)
		}
		return out
	}
	q := strings.ToLower(t.query)
	var shown []string
	for _, id := range all {
		if q == "" || strings.Contains(strings.ToLower(strings.Join(cells(id), " ")), q) {
			shown = append(shown, id)
		}
	}
	if t.pick != "" {
		if i := slices.Index(shown, t.pick); i >= 0 {
			t.row = i
		}
		t.pick = ""
	}
	a.windowHeader(c, k.title(), k.about(), func() {
		if k.tool != "" {
			on := d.ToolOn(k.tool)
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, map[bool]string{true: locales.On(), false: locales.Off()}[on]).FontWeight(600).TextColor(map[bool]ui.Color{true: p.green, false: p.muted}[on])
				if ui.Switch(c, &on).Label(locales.EnableTool(k.title())).Changed() {
					a.setTool(k.tool, on)
				}
			})
		}
	})
	ui.Row(c).FillWidth().Padding(0, windowInset, 8, windowInset).Gap(8).AlignItems(ui.Center).Children(func() {
		if ui.PrimaryButton(c, k.add()).Clicked() {
			a.beginEdit(kind, t, k.fresh(), true)
		}
		chosen := t.row >= 0 && t.row < len(shown)
		if ui.Button(c, locales.Edit()).Disabled(!chosen).Clicked() {
			a.beginEdit(kind, t, k.copyOf(d, shown[t.row]), false)
		}
		if ui.Button(c, locales.Duplicate()).Disabled(!chosen).Clicked() {
			a.duplicateRule(kind, shown[t.row])
		}
		if ui.Button(c, locales.Delete()).Disabled(!chosen).Clicked() {
			id := shown[t.row]
			a.rules.Update(func(d *rules.Data) { k.remove(d, id) })
			t.row = -1
		}
		if k.extra != nil {
			k.extra(a, c)
		}
		ui.Spacer(c)
		box, _ := a.searchField(c, "q", &t.query, locales.SearchRules(), locales.SearchRulesLabel())
		box.Width(200)
	})
	ui.Column(c).Grow(1).Margin(0, windowInset, windowInset, windowInset).Radius(8).Border(1, p.border).Clip().Children(func() {
		if len(all) == 0 {
			ui.Column(c).Fill().Center().Gap(10).Children(func() {
				glyph(c, map[string]string{"maplocal": "folder", "mapremote": "map", "breakpoint": "bug", "block": "block", "allow": "check", "network": "speed", "dns": "dns", "reverse": "reverse", "clientcerts": "certificate",
					"bptemplates": "bug", "blockedapps": "block", "protobuf": "code", "servercerts": "certificate"}[kind], 28, p.faint)
				ui.Text(c, orText(k.empty, locales.NoRulesYet)).FontSize(14).FontWeight(600).TextColor(p.text2)
				ui.Text(c, orText(k.hint, locales.AddOneHereOrFromAFlowsMenu)).TextColor(p.muted)
				if ui.Button(c, k.add()).Clicked() {
					a.beginEdit(kind, t, k.fresh(), true)
				}
			})
			return
		}
		cols, first := columns, 0
		if k.enabled != nil {
			cols, first = append([]ui.TableColumn{{Title: "", ID: "on", Width: 26, Fixed: true}}, columns...), 1
		}
		enabled := func(id string) bool { return k.enabled == nil || *k.enabled(d, id) }
		t.list.Selected = &t.row
		t.list.Key = func(i int) any { return shown[i] }
		tbl := ui.Table(c.Key("rules"), &t.list, cols, len(shown), func(row, col int) {
			id := shown[row]
			sel := row == t.row
			if col < first {
				on := *k.enabled(d, id)
				if ui.Checkbox(c, &on, "").Label(locales.Enabled()).Changed() {
					a.rules.Update(func(d *rules.Data) { *k.enabled(d, id) = on })
				}
				return
			}
			cells := cells(id)
			color := p.text
			if col > first {
				color = p.text2
			}
			if sel {
				color = p.onAccent
			}
			hit := ui.Box(c).Absolute().Top(-6).Bottom(-6).Left(-8).Right(-8)
			txt := ui.Text(c, cells[col-first]).TextColor(color).SingleLine()
			if !enabled(id) && !sel {
				txt.TextColor(p.faint)
			}
			hit.ContextMenu(func(m *ui.Menu) {
				if m.Item(locales.EditEllipsis()).Chosen() {
					a.beginEdit(kind, t, k.copyOf(d, id), false)
				}
				if m.Item(locales.Duplicate()).Chosen() {
					a.duplicateRule(kind, id)
				}
				if k.enabled != nil {
					on := *k.enabled(d, id)
					if m.Item(map[bool]string{true: locales.Disable(), false: locales.Enable()}[on]).Chosen() {
						a.rules.Update(func(d *rules.Data) { *k.enabled(d, id) = !on })
					}
				}
				if k.folder != nil && k.enabled != nil {
					if folder := *k.folder(d, id); folder != "" {
						in := func(x string) bool { f := *k.folder(d, x); return f == folder || strings.HasPrefix(f, folder+"/") }
						state := map[bool]bool{}
						for _, x := range k.ids(d) {
							if in(x) {
								state[*k.enabled(d, x)] = true
							}
						}
						for _, on := range []bool{true, false} {
							if !state[!on] {
								continue
							}
							if m.Item(map[bool]string{true: locales.EnableFolder(folder), false: locales.DisableFolder(folder)}[on]).Chosen() {
								a.rules.Update(func(d *rules.Data) {
									for _, x := range k.ids(d) {
										if f := *k.folder(d, x); f == folder || strings.HasPrefix(f, folder+"/") {
											*k.enabled(d, x) = on
										}
									}
								})
							}
						}
					}
				}
				m.Separator()
				if m.Item(locales.Delete()).Chosen() {
					a.rules.Update(func(d *rules.Data) { k.remove(d, id) })
				}
			})
		}).Grow(1).Label(k.title())
		if tbl.Submitted() && t.row >= 0 && t.row < len(shown) {
			a.beginEdit(kind, t, k.copyOf(d, shown[t.row]), false)
		}
		if (tbl.Shortcut(0, ui.KeyBackspace) || tbl.Shortcut(0, ui.KeyDelete)) && t.row >= 0 && t.row < len(shown) {
			id := shown[t.row]
			a.rules.Update(func(d *rules.Data) { k.remove(d, id) })
		}
	})
	a.ruleEditor(c, kind, k, t)
}

func (a *App) duplicateRule(kind, id string) {
	k := ruleKinds[kind]
	d := a.rules.Snapshot()
	draft := k.copyOf(&d, id)
	switch r := draft.(type) {
	case *rules.MapLocalRule:
		r.ID, r.Name = rules.NewID(), locales.CopyName(r.Name)
	case *rules.MapRemoteRule:
		r.ID, r.Name = rules.NewID(), locales.CopyName(r.Name)
	case *rules.BreakpointRule:
		r.ID, r.Name = rules.NewID(), locales.CopyName(r.Name)
	case *rules.URLRule:
		r.ID, r.Name = rules.NewID(), locales.CopyName(r.Name)
	case *rules.NetworkCondition:
		r.ID, r.Name = rules.NewID(), locales.CopyName(r.Name)
	case *rules.DNSRule:
		r.ID = rules.NewID()
	case *rules.ReverseProxy:
		r.ID, r.ListenPort = rules.NewID(), r.ListenPort+1
	case *rules.ClientCertificate:
		r.ID = rules.NewID()
		r.PasswordRef = copySecret(r.PasswordRef, "client-"+r.ID)
	case *rules.BreakpointTemplate:
		r.ID, r.Name = rules.NewID(), locales.CopyName(r.Name)
	case *rules.AppRule:
		r.ID = rules.NewID()
	case *rules.ProtobufRule:
		r.ID, r.Name = rules.NewID(), locales.CopyName(r.Name)
	case *rules.ServerCertificate:
		r.ID = rules.NewID()
		r.PasswordRef = copySecret(r.PasswordRef, "server-"+r.ID)
	}
	before := k.ids(&d)
	a.rules.Update(func(d *rules.Data) { k.save(d, draft) })
	a.toolState(kind).pick = addedRule(before, k.ids(a.rules.Current()))
}

func copySecret(ref, newRef string) string {
	if ref == "" {
		return ""
	}
	secret, err := certs.Keychain.Get(ref)
	if err != nil || certs.Keychain.Set(newRef, secret) != nil {
		return ""
	}
	return newRef
}

func (a *App) ruleEditor(c *ui.Context, kind string, k *ruleKind, t *toolState) {
	if !t.editing {
		return
	}
	_, winH := c.Size()
	ui.Modal(c, &t.editing, func() {
		ui.Column(c).Width(sheetWidth(c, map[bool]float32{true: 900, false: 640}[kind == "maplocal"])).Gap(12).Children(func() {
			ui.Text(c, map[bool]string{true: locales.NewRuleNoun(orText(k.noun, k.title)), false: locales.EditRuleNoun(orText(k.noun, k.title))}[t.isNew]).FontSize(15).FontWeight(650)
			var invalid string
			ui.Scroll(c).MaxHeight(max(winH-150, 100)).AlignSelf(ui.Stretch).Margin(0, -4).Children(func() {
				ui.Column(c).FillWidth().Gap(10).Padding(0, 4).Children(func() {
					invalid = k.form(a, c, t)
				})
			})
			if t.err != "" {
				ui.Text(c, t.err).TextColor(a.pal.red)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					t.editing = false
				}
				save := ui.PrimaryButton(c, map[bool]string{true: locales.Add(), false: locales.Save()}[t.isNew]).Disabled(invalid != "")
				if invalid != "" {
					save.Tooltip(invalid)
				}
				if save.Clicked() || (invalid == "" && c.Shortcut(ui.Cmd, ui.KeyEnter)) {
					a.saveDraft(k, t)
				}
			})
		})
	})
}

func sheetWidth(c *ui.Context, want float32) float32 {
	winW, _ := c.Size()
	return min(want, winW-60)
}

func ruleName(name string, m rules.Matcher) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	u := m.URL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	return shorten(strings.TrimSuffix(u, "/*"), 60)
}

func (a *App) saveDraft(k *ruleKind, t *toolState) {
	switch r := t.draft.(type) {
	case *rules.MapLocalRule:
		r.Name = ruleName(r.Name, r.Matcher)
	case *rules.MapRemoteRule:
		r.Name = ruleName(r.Name, r.Matcher)
	case *rules.BreakpointRule:
		r.Name = ruleName(r.Name, r.Matcher)
	case *rules.URLRule:
		r.Name = ruleName(r.Name, r.Matcher)
	}
	if r, ok := t.draft.(*rules.BreakpointTemplate); ok {
		r.Raw = t.body.Buffer.String()
		r.Name = cmp.Or(strings.TrimSpace(r.Name), templateTitle(r))
	}
	if err := a.saveSecret(t); err != nil {
		t.err = err.Error()
		return
	}
	if r, ok := t.draft.(*rules.MapLocalRule); ok {
		if t.tab == 0 {
			r.Path = ""
			r.Body = t.body.Buffer.String()
		} else {
			r.Body = ""
		}
		r.Headers = nil
		for _, e := range parseHeaderLines(t.headers).Entries {
			r.Headers = append(r.Headers, rules.Pair{Name: e.Key.Name, Value: e.Value})
		}
	}
	draft := t.draft
	before := k.ids(a.rules.Current())
	a.rules.Update(func(d *rules.Data) {
		k.save(d, draft)
		if k.tool != "" && t.isNew {
			delete(d.DisabledTools, k.tool)
		}
	})
	t.pick = addedRule(before, k.ids(a.rules.Current()))
	t.editing = false
}

func addedRule(before, after []string) string {
	for _, id := range after {
		if !slices.Contains(before, id) {
			return id
		}
	}
	return ""
}

func (a *App) matcherForm(c *ui.Context, t *toolState, name *string, m *rules.Matcher, extra ...func()) string {
	p := a.pal
	mode := 0
	if m.Match == "regex" {
		mode = 1
	}
	method := methodLabel(m.Method)
	invalid := m.Valid()
	ui.Form(c, func() {
		if name != nil {
			ui.Field(c, locales.ColumnName(), func() { ui.TextInput(c, name).Placeholder(locales.Optional()).Label(locales.ColumnName()) })
		}
		urlErr := ""
		if strings.TrimSpace(m.URL) != "" {
			urlErr = invalid
		}
		ui.Field(c, locales.URL(), func() {
			ui.TextInput(c, &m.URL).Placeholder("https://api.example.com/v1/*").Label(locales.MatchingURL()).AutoFocus()
		}).Description(map[int]string{0: locales.MatchesAnythingOneCharacterLeaveOut(), 1: locales.AGoRegularExpressionMatchedAgainst()}[mode]).Error(urlErr)
		ui.Field(c, locales.Matching(), func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				if ui.Segmented(c, &mode, locales.Wildcard(), locales.Regex()).Label(locales.MatchType()).Changed() {
					m.Match = map[int]string{0: "wildcard", 1: "regex"}[mode]
				}
				if ui.Select(c, &method, methods).Label(locales.ColumnMethod()).Width(110).Changed() {
					m.Method = method
					if method == "ANY" {
						m.Method = ""
					}
				}
				ui.Checkbox(c, &m.IncludeSubpaths, locales.IncludeSubpaths())
			})
		})
		ui.Field(c, locales.GraphQL(), func() {
			ui.TextInput(c, &m.GraphQL).Placeholder(locales.OperationNameForGraphQLEndpointsOptional()).Label(locales.GraphQLOperation())
		})
		ui.Field(c, locales.Test(), func() {
			ui.Column(c).Gap(4).Children(func() {
				ui.TextInput(c, &t.test).Placeholder(locales.PasteAURLToCheckThe()).Label(locales.TestURL())
				if t.test != "" {
					ok := m.Matches(cmp.Or(m.Method, "GET"), t.test)
					icon, color, text := "checkCircle", p.green, locales.ThisURLMatches()
					if !ok {
						icon, color, text = "xmark", p.red, locales.ThisURLDoesNotMatch()
					}
					ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
						glyph(c, icon, 12, color)
						ui.Text(c, text).FontSize(11).TextColor(color)
					})
				}
			})
		})
		for _, fn := range extra {
			fn()
		}
	})
	return invalid
}

func mapLocalForm(a *App, c *ui.Context, t *toolState) string {
	p := a.pal
	r := t.draft.(*rules.MapLocalRule)
	var invalid string
	status := float64(cmp.Or(r.StatusCode, 200))
	delay := float64(r.DelayMS)
	wide := sheetWidth(c, 900) >= 780
	var layout ui.Element
	if wide {
		layout = ui.Row(c).FillWidth().Gap(18).AlignItems(ui.Stretch)
	} else {
		layout = ui.Column(c).FillWidth().Gap(14)
	}
	layout.Children(func() {
		rule := ui.Column(c).Gap(10)
		if wide {
			rule.Width(460)
		} else {
			rule.FillWidth()
		}
		rule.Children(func() {
			var folder string
			invalid = a.matcherForm(c, t, &r.Name, &r.Matcher, func() {
				folder = a.folderField(c, ruleFolders(a.rules.Current().MapLocal, func(r *rules.MapLocalRule) string { return r.Folder }), &r.Folder)
			})
			invalid = cmp.Or(invalid, folder)
			ui.Divider(c)
			ui.Form(c, func() {
				ui.Field(c, locales.Status(), func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						if ui.NumberInput(c, &status, 100, 599, 1).Width(110).Changed() {
							r.StatusCode = int(status)
						}
						ui.Text(c, http.StatusText(int(status))).TextColor(p.muted)
					})
				})
				ui.Field(c, locales.ContentType(), func() {
					ui.TextInput(c, &r.ContentType).Placeholder(locales.DetectedFromTheBodyOrThe()).Label(locales.ContentTypeLabel())
				})
				ui.Field(c, locales.Headers(), func() {
					ui.TextArea(c, &t.headers).Placeholder(locales.NameValueALineEach()).Height(56).Label(locales.Headers())
				})
				ui.Field(c, locales.Delay(), func() {
					ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
						if ui.NumberInput(c, &delay, 0, 120000, 100).Width(110).Changed() {
							r.DelayMS = int(delay)
						}
						ui.Text(c, locales.Ms()).TextColor(p.muted)
					})
				})
			})
		})
		source := ui.Column(c).Gap(8)
		if wide {
			source.Grow(1)
		} else {
			source.FillWidth()
		}
		source.Children(func() {
			ui.Segmented(c, &t.tab, locales.ResponseBodyLabel(), locales.LocalFileOrFolder()).Label(locales.Source())
			if t.tab == 1 {
				ui.Row(c).Gap(6).Children(func() {
					ui.TextInput(c, &r.Path).Placeholder(locales.PathToFileJSONOrA()).Label(locales.LocalPath()).Grow(1)
					if ui.Button(c, locales.FileEllipsis()).Clicked() {
						a.choosePath("maplocal", false, func(p string) { r.Path = p })
					}
					if ui.Button(c, locales.FolderEllipsis()).Clicked() {
						a.choosePath("maplocal", true, func(p string) { r.Path = p })
					}
				})
				ui.Text(c, locales.AFolderAnswersWithTheFile()).FontSize(11).TextColor(p.muted).Wrap()
				if r.Path != "" {
					if _, err := os.Stat(expandHome(r.Path)); err != nil {
						ui.Text(c, locales.ThisPathDoesNotExist()).FontSize(11).TextColor(p.yellow)
					}
				}
				return
			}
			ui.Column(c).Grow(1).MinHeight(260).FillWidth().Radius(6).Border(1, p.border).Clip().Children(func() {
				editor.View(c.Key("body"), t.body).Fill()
			})
		})
	})
	if t.tab == 1 && r.Path == "" {
		invalid = cmp.Or(invalid, locales.ChooseAFileOrFolder())
	}
	return invalid
}

func mapRemoteForm(a *App, c *ui.Context, t *toolState) string {
	p := a.pal
	r := t.draft.(*rules.MapRemoteRule)
	var folder string
	invalid := a.matcherForm(c, t, &r.Name, &r.Matcher, func() {
		folder = a.folderField(c, ruleFolders(a.rules.Current().MapRemote, func(r *rules.MapRemoteRule) string { return r.Folder }), &r.Folder)
	})
	invalid = cmp.Or(invalid, folder)
	ui.Divider(c)
	port := ""
	if r.Port > 0 {
		port = strconv.Itoa(r.Port)
	}
	scheme := cmp.Or(r.Scheme, locales.Unchanged())
	ui.Form(c, func() {
		ui.Field(c, locales.MapTo(), func() {
			ui.TextInput(c, &r.NewURL).Placeholder(locales.HTTPLocalhost3000OrSetThe()).Label(locales.NewURL())
		}).Description(locales.AURLOfOnlyAHost())
		ui.Fieldset(c, locales.OrChangeOnly(), func() {
			ui.Field(c, locales.Scheme(), func() {
				if ui.Select(c, &scheme, []string{locales.Unchanged(), "http", "https"}).Label(locales.Scheme()).Width(130).Changed() {
					r.Scheme = scheme
					if scheme == locales.Unchanged() {
						r.Scheme = ""
					}
				}
			})
			ui.Field(c, locales.ColumnHost(), func() { ui.TextInput(c, &r.Host).Placeholder(locales.Unchanged()).Label(locales.ColumnHost()) })
			ui.Field(c, locales.Port(), func() {
				if ui.TextInput(c, &port).Placeholder(locales.Unchanged()).Label(locales.Port()).Width(130).Changed() {
					r.Port = portOf(port, r.Port)
				}
			})
			ui.Field(c, locales.Path(), func() { ui.TextInput(c, &r.Path).Placeholder(locales.Unchanged()).Label(locales.Path()) })
			ui.Field(c, locales.Query(), func() { ui.TextInput(c, &r.Query).Placeholder(locales.Unchanged()).Label(locales.Query()) })
		})
		ui.Field(c, locales.ColumnHostHeader(), func() {
			ui.Checkbox(c, &r.PreserveHost, locales.KeepTheOriginalHostHeader())
		})
	})
	if r.NewURL == "" && r.Scheme == "" && r.Host == "" && r.Port == 0 && r.Path == "" && r.Query == "" {
		invalid = cmp.Or(invalid, locales.EnterWhereRequestsGo())
	}
	if r.NewURL != "" {
		if u, err := url.Parse(r.NewURL); err != nil || u.Host == "" {
			invalid = cmp.Or(invalid, locales.TheNewURLNeedsAScheme())
		}
	}
	if t.test != "" && invalid == "" {
		if u, err := url.Parse(t.test); err == nil && r.Matches(cmp.Or(r.Method, "GET"), t.test) {
			if nu, err := r.Rewrite(u); err == nil {
				ui.Row(c).Gap(6).Children(func() {
					ui.Text(c, locales.GoesTo()).TextColor(p.muted)
					ui.Text(c, nu.String()).TextColor(p.link).Selectable()
				})
			}
		}
	}
	return invalid
}

func breakpointForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.BreakpointRule)
	invalid := a.matcherForm(c, t, &r.Name, &r.Matcher)
	req := r.Phase == rules.PhaseRequest || r.Phase == rules.PhaseBoth || r.Phase == ""
	resp := r.Phase == rules.PhaseResponse || r.Phase == rules.PhaseBoth || r.Phase == ""
	ui.Form(c, func() {
		ui.Field(c, locales.Pause(), func() {
			ui.Row(c).Gap(14).Children(func() {
				a1 := ui.Checkbox(c, &req, locales.PhaseRequest()).Changed()
				a2 := ui.Checkbox(c, &resp, locales.PhaseResponse()).Changed()
				if a1 || a2 {
					switch {
					case req && resp:
						r.Phase = rules.PhaseBoth
					case req:
						r.Phase = rules.PhaseRequest
					case resp:
						r.Phase = rules.PhaseResponse
					}
				}
			})
		})
	})
	if !req && !resp {
		invalid = cmp.Or(invalid, locales.PauseTheRequestTheResponseOr())
	}
	return invalid
}

func urlRuleForm(a *App, c *ui.Context, t *toolState, block bool) string {
	r := t.draft.(*rules.URLRule)
	invalid := a.matcherForm(c, t, &r.Name, &r.Matcher)
	if block {
		display, hide := locales.BlockAndDisplayAnswer403(), locales.BlockAndHideDropTheConnection()
		action := map[string]string{rules.BlockDisplay: display, rules.BlockHide: hide}[r.Action]
		ui.Form(c, func() {
			ui.Field(c, locales.ColumnAction(), func() {
				if ui.Select(c, &action, []string{display, hide}).Label(locales.ColumnAction()).Changed() {
					r.Action = map[bool]string{true: rules.BlockHide, false: rules.BlockDisplay}[action == hide]
				}
			})
		})
	}
	return invalid
}

func networkForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.NetworkCondition)
	invalid := a.matcherForm(c, t, nil, &r.Matcher)
	profiles := slices.Clone(rules.Presets)
	for _, p := range a.rules.Current().NetworkProfiles {
		if p != nil {
			profiles = append(profiles, rules.Preset{Name: p.Name, LatencyMS: p.LatencyMS, DownloadKBps: p.DownloadKBps, UploadKBps: p.UploadKBps, PacketLoss: p.PacketLoss})
		}
	}
	names := []string{}
	for _, p := range profiles {
		names = append(names, p.Name)
	}
	names = append(names, locales.CustomProfile())
	preset := r.Name
	if !slices.Contains(names, preset) {
		preset = locales.CustomProfile()
	}
	saved := slices.ContainsFunc(a.rules.Current().NetworkProfiles, func(p *rules.NetworkProfile) bool { return p != nil && p.Name == preset })
	ui.Form(c, func() {
		ui.Field(c, locales.ColumnProfile(), func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				if ui.Select(c, &preset, names).Label(locales.ColumnProfile()).Width(200).Changed() {
					r.Name = preset
					for _, p := range profiles {
						if p.Name == preset {
							r.LatencyMS, r.DownloadKBps, r.UploadKBps, r.PacketLoss = p.LatencyMS, p.DownloadKBps, p.UploadKBps, p.PacketLoss
						}
					}
				}
				if saved && ui.Button(c, locales.DeleteProfile()).Tooltip(locales.ForgetTheProfile(preset)).Clicked() {
					name := preset
					a.rules.Update(func(d *rules.Data) {
						d.NetworkProfiles = slices.DeleteFunc(d.NetworkProfiles, func(p *rules.NetworkProfile) bool { return p == nil || p.Name == name })
					})
				}
			})
		})
		latency, down, up, loss := float64(r.LatencyMS), r.DownloadKBps, r.UploadKBps, r.PacketLoss
		custom := func(label, unit string, v *float64, lo, hi, step float64, set func(float64)) {
			ui.Field(c, label, func() {
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					if ui.NumberInput(c, v, lo, hi, step).Width(120).Changed() {
						set(*v)
						r.Name = locales.CustomProfile()
					}
					ui.Text(c, unit).TextColor(a.pal.muted)
				})
			})
		}
		custom(locales.ColumnLatency(), "ms", &latency, 0, 60000, 50, func(v float64) { r.LatencyMS = int(v) })
		custom(locales.ColumnDownload(), locales.KbS0IsUnlimited(), &down, 0, 1e6, 50, func(v float64) { r.DownloadKBps = v })
		custom(locales.ColumnUpload(), locales.KbS0IsUnlimited(), &up, 0, 1e6, 50, func(v float64) { r.UploadKBps = v })
		custom(locales.PacketLoss(), locales.OfRequestsFail(), &loss, 0, 100, 5, func(v float64) { r.PacketLoss = v })
		if preset == "Custom" {
			ui.Field(c, locales.SaveAsProfile(), func() {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.TextInput(c, &t.profile).Placeholder(locales.ProfileName()).Label(locales.ProfileName()).Width(200)
					name := strings.TrimSpace(t.profile)
					taken := slices.Contains(names, name)
					save := ui.Button(c, locales.Save()).Disabled(name == "" || taken)
					if taken {
						save.Tooltip(locales.AProfileHasThatName())
					}
					if save.Clicked() {
						np := &rules.NetworkProfile{Name: name, LatencyMS: r.LatencyMS, DownloadKBps: r.DownloadKBps, UploadKBps: r.UploadKBps, PacketLoss: r.PacketLoss}
						a.rules.Update(func(d *rules.Data) { d.NetworkProfiles = append(d.NetworkProfiles, np) })
						r.Name, t.profile = name, ""
					}
				})
			}).Description(locales.KeepTheseValuesToChooseAgain())
		}
	})
	return invalid
}

func portOf(text string, old int) int {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0
	}
	if n, err := strconv.Atoi(text); err == nil && n > 0 && n < 65536 {
		return n
	}
	return old
}

func dnsForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.DNSRule)
	port := ""
	if r.Port > 0 {
		port = strconv.Itoa(r.Port)
	}
	ui.Form(c, func() {
		ui.Field(c, locales.ColumnHost(), func() {
			ui.TextInput(c, &r.Host).Placeholder(locales.APIExampleComOrExampleCom()).Label(locales.ColumnHost()).AutoFocus()
		}).
			Description(locales.ADomainCoversItsSubdomainsToo())
		ui.Field(c, locales.ColumnAddress(), func() { ui.TextInput(c, &r.IP).Placeholder("127.0.0.1").Label(locales.ColumnAddress()) })
		ui.Field(c, locales.Port(), func() {
			if ui.TextInput(c, &port).Placeholder(locales.Unchanged()).Label(locales.Port()).Width(130).Changed() {
				r.Port = portOf(port, r.Port)
			}
		}).Description(locales.EmptyKeepsTheRequestsPort())
	})
	switch {
	case strings.TrimSpace(r.Host) == "":
		return locales.EnterAHost()
	case net.ParseIP(strings.TrimSpace(r.IP)) == nil:
		return locales.EnterAnIPAddress()
	}
	return ""
}

func reverseForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.ReverseProxy)
	port := float64(r.ListenPort)
	ui.Form(c, func() {
		ui.Field(c, locales.ColumnLocalPort(), func() {
			if ui.NumberInput(c, &port, 1, 65535, 1).Width(110).Changed() {
				r.ListenPort = int(port)
			}
		})
		ui.Field(c, locales.Target(), func() {
			ui.TextInput(c, &r.Target).Placeholder("https://api.example.com").Label(locales.Target()).AutoFocus()
		})
		ui.Field(c, locales.ColumnName(), func() { ui.TextInput(c, &r.Name).Placeholder(locales.Optional()).Label(locales.ColumnName()) })
		ui.Field(c, locales.ColumnHostHeader(), func() { ui.Checkbox(c, &r.PreserveHost, locales.KeepTheClientsHostHeader()) })
	})
	u, err := url.Parse(r.Target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return locales.EnterTheTargetsURLWithHTTP()
	}
	if r.ListenPort == a.proxy.Port() {
		return locales.ThatPortIsProxyGosOwn()
	}
	return ""
}

func clientCertForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.ClientCertificate)
	invalid := a.certFields(c, t, "clientcerts", func() {
		ui.Field(c, locales.ColumnHost(), func() {
			ui.TextInput(c, &r.Host).Placeholder(locales.APIExampleComOrExampleCom()).Label(locales.ColumnHost()).AutoFocus()
		})
	}, &r.CertPath, &r.KeyPath, &r.P12Path, &r.PasswordRef, nil)
	if strings.TrimSpace(r.Host) == "" {
		return locales.EnterAHost()
	}
	return invalid
}

func (a *App) choosePath(kind string, folder bool, set func(string)) {
	win := a.windows[kind]
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: win, Title: map[bool]string{true: locales.ChooseAFolder(), false: locales.ChooseAFile()}[folder], Directory: folder})
		if err != nil || len(paths) == 0 {
			return
		}
		a.do(func() { set(paths[0]) })
	}()
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}

func (a *App) sslWindow(c *ui.Context) {
	p := a.pal
	t := a.toolState("ssl")
	d := a.rules.Current()
	list := []string{"include", "exclude"}[min(t.tab, 1)]
	a.windowHeader(c, locales.SSLProxyingList(), locales.ProxyGoDecryptsHTTPSOnlyForThe(), func() {
		on := d.SSL.Enabled
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, map[bool]string{true: locales.On(), false: locales.Off()}[on]).FontWeight(600).TextColor(map[bool]ui.Color{true: p.green, false: p.muted}[on])
			if ui.Switch(c, &on).Label(locales.EnableSSLProxying()).Changed() {
				a.rules.Update(func(d *rules.Data) { d.SSL.Enabled = on })
			}
		})
	})
	if !a.certTrusted {
		ui.Row(c).FillWidth().Padding(0, windowInset, 8, windowInset).Children(func() {
			ui.Row(c).Grow(1).Padding(8, 10).Gap(8).Radius(6).Background(p.yellowSoft).AlignItems(ui.Center).Children(func() {
				glyph(c, "warning", 13, p.yellow)
				ui.Text(c, locales.ThisMacDoesNotTrustThe()).Grow(1).Shrink(1).Wrap()
				if ui.Button(c, locales.InstallEllipsis()).Clicked() {
					a.installCertificate()
				}
			})
		})
	}
	ui.Row(c).FillWidth().Padding(0, windowInset, 8, windowInset).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Tabs(c, &t.tab, locales.Include(), locales.Exclude()).Label(locales.List())
		ui.Spacer(c)
		add := ui.TextInput(c.Key("host"), &t.newHost).Placeholder(locales.ExampleComExampleComOr()).Label(locales.ColumnHost()).Width(260)
		submit := add.Submitted()
		if ui.PrimaryButton(c, locales.Add()).Disabled(strings.TrimSpace(t.newHost) == "").Clicked() || submit {
			host := strings.TrimSpace(t.newHost)
			if u, err := url.Parse(host); err == nil && u.Host != "" {
				host = u.Host
			}
			host, _, _ = strings.Cut(host, "/")
			if host != "" {
				a.rules.Update(func(d *rules.Data) {
					d.SSL.Enabled = true
					d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: rules.NewID(), Enabled: true, List: list, Target: host, TargetType: "domain"})
				})
				t.newHost = ""
			}
		}
	})
	var shown []*rules.SSLRule
	for _, r := range d.SSL.Rules {
		if r.List == list || (list == "include" && r.List == "") {
			shown = append(shown, r)
		}
	}
	ui.Column(c).Grow(1).Margin(0, windowInset, windowInset, windowInset).Radius(8).Border(1, p.border).Clip().Children(func() {
		if len(shown) == 0 {
			emptyState(c, p, map[string]string{"include": locales.NoHostsYetAddOneAbove(), "exclude": locales.NoExcludedHosts()}[list])
			return
		}
		t.list.Selected = &t.row
		ui.Table(c.Key(list), &t.list, []ui.TableColumn{{Title: "", ID: "on", Width: 26, Fixed: true}, {Title: locales.ColumnHost()}, {Title: "", ID: "delete", Width: 34, Fixed: true}}, len(shown), func(row, col int) {
			r := shown[row]
			id := r.ID
			switch col {
			case 0:
				on := r.Enabled
				if ui.Checkbox(c, &on, "").Label(locales.Enabled()).Changed() {
					a.rules.Update(func(d *rules.Data) {
						if x := byID(d.SSL.Rules, id, func(r *rules.SSLRule) string { return r.ID }); x != nil {
							x.Enabled = on
						}
					})
				}
			case 1:
				ui.Text(c, r.Target).SingleLine().TextColor(map[bool]ui.Color{true: p.text, false: p.faint}[r.Enabled]).ContextMenu(func(m *ui.Menu) {
					other := map[string]string{"include": "exclude", "exclude": "include"}[list]
					if m.Item(map[string]string{"include": locales.MoveToInclude(), "exclude": locales.MoveToExclude()}[other]).Chosen() {
						a.rules.Update(func(d *rules.Data) {
							if x := byID(d.SSL.Rules, id, func(r *rules.SSLRule) string { return r.ID }); x != nil {
								x.List = other
							}
						})
					}
					if m.Item(locales.Delete()).Chosen() {
						a.rules.Update(func(d *rules.Data) {
							d.SSL.Rules = dropByID(d.SSL.Rules, id, func(r *rules.SSLRule) string { return r.ID })
						})
					}
				})
			case 2:
				if plainIconButton(c, "trash", locales.Delete(), 12, p.muted, p.hover).Clicked() {
					a.rules.Update(func(d *rules.Data) {
						d.SSL.Rules = dropByID(d.SSL.Rules, id, func(r *rules.SSLRule) string { return r.ID })
					})
				}
			}
		}).Grow(1).Label(locales.Hosts())
	})
}
