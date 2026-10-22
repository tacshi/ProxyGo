package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"proxygo/internal/codegen"
	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/session"
	"proxygo/internal/settings"
	"proxygo/locales"
)

func (a *App) setPaused(p bool) {
	a.paused = p
	a.proxyPaused.Store(p)
	a.proxy.SetPaused(p)
	if a.menu.pause != nil {
		a.menu.pause.SetChecked(p)
	}
	if p {
		a.toast(locales.RecordingPausedTrafficStillFlowsUnrecorded())
	} else {
		a.toast(locales.GroupRecording())
	}
}

func (a *App) clearFlows() {
	a.store.Clear()
	a.flows, a.visible = nil, nil
	a.version = 0
	a.selected, a.row = "", -1
	a.chosen.Clear()
	a.sessionPath = ""
	a.filterKey = ""
}

func (a *App) deleteFlows(fs []*flow.Flow) {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.UniqueID
	}
	next := ""
	if i := slices.IndexFunc(a.visible, func(f *flow.Flow) bool { return f.UniqueID == a.selected }); i >= 0 && slices.Contains(ids, a.selected) {
		kept := func(j int) bool { return !slices.Contains(ids, a.visible[j].UniqueID) }
		for j := i + 1; j < len(a.visible) && next == ""; j++ {
			if kept(j) {
				next = a.visible[j].UniqueID
			}
		}
		for j := i - 1; j >= 0 && next == ""; j-- {
			if kept(j) {
				next = a.visible[j].UniqueID
			}
		}
		a.selected = ""
	}
	a.store.Remove(ids...)
	a.chosen.Clear()
	if next != "" {
		a.selectFlow(next)
	}
}

func (a *App) deleteMatching(match func(*flow.Flow) bool) {
	var fs []*flow.Flow
	for _, f := range a.flows {
		if match(f) {
			fs = append(fs, f)
		}
	}
	a.deleteFlows(fs)
	a.toast(locales.DeletedFlows(len(fs)))
	if s, ok := parseSource(a.section); ok && !slices.ContainsFunc(a.store.Snapshot(), s.match) {
		a.section = "all"
	}
}

func (a *App) setSaved(fs []*flow.Flow, on bool) {
	for _, f := range fs {
		a.store.Update(f.UniqueID, func(s *flow.Flow) { s.Saved = on })
	}
}

func (a *App) setHighlight(fs []*flow.Flow, color string) {
	for _, f := range fs {
		a.store.Update(f.UniqueID, func(s *flow.Flow) { s.Highlight = color })
	}
}

func (a *App) setStrike(fs []*flow.Flow, on bool) {
	for _, f := range fs {
		a.store.Update(f.UniqueID, func(s *flow.Flow) { s.Strikethrough = on })
	}
}

func (a *App) resetStyle(fs []*flow.Flow) {
	for _, f := range fs {
		a.store.Update(f.UniqueID, func(s *flow.Flow) { s.Highlight, s.Strikethrough = "", false })
	}
}

type commentState struct {
	open     bool
	text     string
	ids      []string
	draft    string
	draftFor string
}

func (a *App) editComment(fs []*flow.Flow) {
	if len(fs) == 0 {
		return
	}
	a.comment = commentState{open: true, text: fs[0].Comment, draftFor: a.comment.draftFor, draft: a.comment.draft}
	for _, f := range fs {
		a.comment.ids = append(a.comment.ids, f.UniqueID)
	}
}

func (a *App) saveComment() {
	text := strings.TrimSpace(a.comment.text)
	for _, id := range a.comment.ids {
		a.store.Update(id, func(s *flow.Flow) { s.Comment = text })
	}
	a.comment.open, a.comment.ids, a.comment.draftFor = false, nil, ""
}

func (a *App) togglePin(key string) {
	pinned := false
	a.updateSettings(func(s *settings.Settings) { pinned = s.TogglePin(key) })
	name := strings.SplitN(key, ":", 2)[1]
	if pinned {
		a.toast(locales.PinnedName(name))
	} else {
		a.toast(locales.UnpinnedName(name))
		if a.section == "pin:"+key {
			a.section = "all"
		}
	}
}

func (a *App) pinned(key string) bool { return slices.Contains(a.set.Pinned, key) }

func (a *App) copyURLs(fs []*flow.Flow) {
	urls := make([]string, len(fs))
	for i, f := range fs {
		urls[i] = f.URL()
	}
	a.copy(strings.Join(urls, "\n"), locales.CopiedURL())
}

func (a *App) copyCode(fs []*flow.Flow, language string) {
	if len(fs) == 0 {
		return
	}
	gen := codegen.Named(language)
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = gen(codegen.Of(f))
	}
	a.copy(strings.Join(parts, "\n\n"), locales.CopiedAs(cmp.Or(language, "cURL")))
	if language != "" && language != a.set.CodeLanguage {
		a.updateSettings(func(s *settings.Settings) { s.CodeLanguage = language })
	}
}

func (a *App) copyRaw(f *flow.Flow, response bool) {
	if f == nil {
		return
	}
	if response {
		a.copy(rawResponse(f), "response")
	} else {
		a.copy(rawRequest(f), "request")
	}
}

func (a *App) repeatFlows(fs []*flow.Flow) {
	for _, f := range fs {
		if f.IsTunnel() {
			a.toast(locales.AnEncryptedTunnelCannotBeRepeated(f.Host()))
			continue
		}
		if f.IsWebSocket() {
			a.toast(locales.AWebSocketRequestCannotBeRepeated())
			continue
		}
		msg := proxy.MessageOf(f)
		go func() {
			nf, err := a.proxy.Replay(context.Background(), msg)
			a.do(func() {
				if err != nil {
					a.toast(locales.RepeatError(err.Error()))
					return
				}
				if a.set.AutoSelect && nf != nil {
					a.refreshFlows()
					a.applyFilter()
					a.selectFlow(nf.UniqueID)
				}
			})
		}()
	}
}

type repeatState struct {
	open        bool
	count       float64
	concurrency float64
	delay       float64
	msgs        []proxy.Message
	running     bool
}

func (a *App) advancedRepeat(fs []*flow.Flow) {
	if len(fs) == 0 {
		return
	}
	a.repeat = repeatState{open: true, count: 10, concurrency: 1}
	for _, f := range fs {
		if !f.IsTunnel() {
			a.repeat.msgs = append(a.repeat.msgs, proxy.MessageOf(f))
		}
	}
}

func (a *App) runAdvancedRepeat() {
	r := a.repeat
	a.repeat.open, a.repeat.running = false, true
	go func() {
		failed := 0
		delay := time.Duration(r.delay) * time.Millisecond
		for _, m := range r.msgs {
			for _, res := range a.proxy.Repeat(context.Background(), m, int(r.count), int(r.concurrency), delay) {
				if res.Err != nil || res.Flow == nil || res.Flow.IsError() {
					failed++
				}
			}
		}
		total := len(r.msgs) * int(r.count)
		a.do(func() {
			a.repeat.running = false
			if failed > 0 {
				a.toast(locales.RepeatedRequestsFailed(total, failed))
			} else {
				a.toast(locales.RepeatedRequests(total))
			}
		})
	}()
}

func ruleURL(f *flow.Flow) string {
	u, _, _ := strings.Cut(f.URL(), "?")
	return u
}

func (a *App) enableSSL(host string, all bool) {
	target := host
	if all {
		target = "*"
	}
	a.rules.Update(func(d *rules.Data) { includeSSL(d, target) })
	if all {
		a.toast(locales.SSLProxyingIsOnForEvery())
	} else {
		a.toast(locales.SSLProxyingIsOnForHost(host))
	}
}

func includeSSL(d *rules.Data, target string) {
	d.SSL.Enabled = true
	for _, r := range d.SSL.Rules {
		if strings.EqualFold(r.Target, target) {
			r.Enabled, r.List = true, "include"
			return
		}
	}
	d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: rules.NewID(), Enabled: true, List: "include", Target: target, TargetType: "domain"})
}

func (a *App) enableSSLForClient(f *flow.Flow) {
	name := clientName(f)
	var hosts []string
	for _, g := range a.flows {
		if clientName(g) == name && (g.IsTunnel() || g.IsHTTPS()) && g.Host() != "" && !slices.Contains(hosts, g.Host()) {
			hosts = append(hosts, g.Host())
		}
	}
	slices.Sort(hosts)
	a.rules.Update(func(d *rules.Data) {
		for _, host := range hosts {
			includeSSL(d, host)
		}
	})
	a.toast(locales.SSLProxyingIsOnForDomainsOf(len(hosts), a.clientLabel(f)))
}

func (a *App) excludeSSL(host string) {
	a.rules.Update(func(d *rules.Data) {
		for _, r := range d.SSL.Rules {
			if strings.EqualFold(r.Target, host) && r.List == "exclude" {
				r.Enabled = true
				return
			}
		}
		d.SSL.Rules = append(d.SSL.Rules, &rules.SSLRule{ID: rules.NewID(), Enabled: true, List: "exclude", Target: host, TargetType: "domain"})
	})
	a.toast(locales.ProxyGoNoLongerDecrypts(host))
}

func (a *App) mapLocalFromFlow(f *flow.Flow) {
	r := &rules.MapLocalRule{ID: rules.NewID(), Enabled: true, Name: f.Host() + f.URLPath(), Matcher: rules.Matcher{URL: ruleURL(f), Method: f.MethodName()}, StatusCode: 200}
	if f.Response != nil && !f.IsError() {
		r.StatusCode = f.StatusCode()
		r.Body = string(f.DecodedResponseBody())
		if ct := f.Response.Header.Get("Content-Type"); isJSON(strings.ToLower(ct), []byte(r.Body)) {
			r.Body = prettyText([]byte(r.Body), ct)
		}
		for _, e := range f.Response.Header.Entries {
			switch strings.ToLower(e.Key.Name) {
			case "content-length", "content-encoding", "transfer-encoding", "connection", "date", ":status":
				continue
			}
			if e.Enabled {
				r.Headers = append(r.Headers, rules.Pair{Name: e.Key.Name, Value: e.Value})
			}
		}
	}
	a.openDraft("maplocal", r)
}

func (a *App) mapRemoteFromFlow(f *flow.Flow) {
	r := &rules.MapRemoteRule{ID: rules.NewID(), Enabled: true, Name: f.Host(), Matcher: rules.Matcher{URL: ruleURL(f)}, NewURL: f.Scheme() + "://localhost:3000" + strings.SplitN(f.URLPath(), "?", 2)[0]}
	a.openDraft("mapremote", r)
}

func (a *App) breakpointFromFlow(f *flow.Flow) {
	r := &rules.BreakpointRule{ID: rules.NewID(), Enabled: true, Name: f.Host() + f.URLPath(), Matcher: rules.Matcher{URL: ruleURL(f)}, Phase: rules.PhaseBoth}
	a.rules.Update(func(d *rules.Data) {
		d.Breakpoints = append(d.Breakpoints, r)
		delete(d.DisabledTools, rules.ToolBreakpoint)
	})
	a.toast(locales.BreakpointAddedFor(shorten(ruleURL(f), 60)))
	a.toolState("breakpoint").pick = r.ID
	a.openWindow("breakpoint")
}

func (a *App) scriptFromFlow(f *flow.Flow) {
	r := &rules.ScriptRule{ID: rules.NewID(), Enabled: true, Name: f.Host(), Matcher: rules.Matcher{URL: ruleURL(f)}, OnRequest: true, OnResponse: true, Script: scriptTemplate()}
	a.rules.Update(func(d *rules.Data) { d.Scripts = append(d.Scripts, r) })
	a.scriptUI.selected = r.ID
	a.openWindow("scripting")
}

func (a *App) blockFromFlow(f *flow.Flow, allow bool) {
	r := &rules.URLRule{ID: rules.NewID(), Enabled: true, Name: f.Host(), Matcher: rules.Matcher{URL: ruleURL(f)}}
	a.rules.Update(func(d *rules.Data) {
		if allow {
			d.Allow = append(d.Allow, r)
		} else {
			d.Block = append(d.Block, r)
		}
	})
	if allow {
		a.toast(locales.AddedToTheAllowList())
	} else {
		a.toast(locales.AddedToTheBlockList())
	}
}

func (a *App) throttleFromFlow(f *flow.Flow) {
	r := &rules.NetworkCondition{ID: rules.NewID(), Enabled: true, Name: "3G", Matcher: rules.Matcher{URL: f.Scheme() + "://" + f.Host() + "/*"}, LatencyMS: 200, DownloadKBps: 780, UploadKBps: 330}
	a.openDraft("network", r)
}

func (a *App) toolOn(tool string) bool { return a.rules.Current().ToolOn(tool) }

func (a *App) setTool(tool string, on bool) {
	a.rules.Update(func(d *rules.Data) {
		if d.DisabledTools == nil {
			d.DisabledTools = map[string]bool{}
		}
		if on {
			delete(d.DisabledTools, tool)
		} else {
			d.DisabledTools[tool] = true
		}
	})
}

func (a *App) setNoCaching(on bool) {
	a.rules.Update(func(d *rules.Data) { d.NoCaching = on })
	if a.menu.noCaching != nil {
		a.menu.noCaching.SetChecked(on)
	}
}

func (a *App) openSessionDialog(add bool) {
	title := locales.OpenSession()
	if add {
		title = locales.Import()
	}
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent: a.win, Title: title,
			Filters: []mygo.FileFilter{
				{Name: locales.SessionsAndArchives(), Extensions: session.Extensions},
				{Name: locales.AllFiles(), Extensions: []string{"*"}},
			},
		})
		if err != nil || len(paths) == 0 {
			return
		}
		a.openPath(paths[0], add)
	}()
}

func (a *App) openPath(path string, add bool) {
	b, err := session.Open(path)
	a.do(func() {
		if errors.Is(err, fs.ErrNotExist) {
			a.toast(locales.IsNoLongerThere(filepath.Base(path)))
			a.updateSettings(func(s *settings.Settings) { s.RemoveRecent(path) })
			a.refreshRecentMenu()
			return
		}
		if err != nil {
			a.toast(locales.CannotOpen(filepath.Base(path), err.Error()))
			return
		}
		a.loadBundle(b, path, add)
		a.updateSettings(func(s *settings.Settings) { s.AddRecent(path) })
		a.refreshRecentMenu()
		if add {
			a.toast(locales.ImportedFlows(len(b.Flows)))
		} else if a.win != nil {
			a.win.SetTitle("ProxyGo — " + filepath.Base(path))
		}
	})
}

func (a *App) saveSessionDialog(selection bool) {
	flows := a.store.Snapshot()
	if selection {
		flows = a.chosenFlows()
	}
	name := "Session_" + time.Now().Format("2006-01-02_15-04-05") + session.Ext
	dir := a.lastDir()
	icons := a.iconStrings()
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent: a.win, Title: locales.SaveSession(), DefaultPath: filepath.Join(dir, name),
			Filters: []mygo.FileFilter{{Name: locales.ProxyGoSession(), Extensions: []string{strings.TrimPrefix(session.Ext, ".")}}},
		})
		if err != nil || path == "" {
			return
		}
		err = session.Write(path, flows, icons)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotSave(err.Error()))
				return
			}
			if !selection {
				a.sessionPath = path
			}
			a.updateSettings(func(s *settings.Settings) { s.AddRecent(path) })
			a.refreshRecentMenu()
			a.toast(locales.SavedName(filepath.Base(path)))
		})
	}()
}

func (a *App) saveSession() {
	if a.sessionPath == "" || !strings.HasSuffix(a.sessionPath, session.Ext) || a.sessionPath == a.autosavePath() {
		a.saveSessionDialog(false)
		return
	}
	path := a.sessionPath
	if err := session.Write(path, a.store.Snapshot(), a.iconStrings()); err != nil {
		a.toast(locales.CannotSave(err.Error()))
		return
	}
	a.toast(locales.SavedName(filepath.Base(path)))
}

func (a *App) lastDir() string {
	if len(a.set.RecentSessions) > 0 {
		return filepath.Dir(a.set.RecentSessions[0])
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Desktop")
}

var exportFormats = map[string]struct{ ext, title string }{
	"har":          {"har", "HAR"},
	"csv":          {"csv", "CSV"},
	"postman":      {"postman_collection.json", "Postman Collection"},
	"openapi":      {"yaml", "OpenAPI (YAML)"},
	"openapi-html": {"html", "OpenAPI (HTML)"},
	"raw":          {"txt", "Raw HTTP"},
}

func (a *App) exportDialog(format string, selection bool) {
	flows := a.store.Snapshot()
	if selection {
		flows = a.chosenFlows()
	}
	a.exportFlows(format, flows, "ProxyGo_"+time.Now().Format("2006-01-02_15-04-05"))
}

func (a *App) exportFlows(format string, flows []*flow.Flow, name string) {
	ef, ok := exportFormats[format]
	if !ok {
		return
	}
	dir := a.lastDir()
	icons := a.iconStrings()
	ext := ef.ext
	if i := strings.LastIndexByte(ext, '.'); i >= 0 {
		ext = ext[i+1:]
	}
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent: a.win, Title: locales.ExportAsTitle(exportTitle(format)), DefaultPath: filepath.Join(dir, name+"."+ef.ext),
			Filters: []mygo.FileFilter{{Name: exportTitle(format), Extensions: []string{ext}}},
		})
		if err != nil || path == "" {
			return
		}
		err = session.Export(path, format, flows, icons)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotExport(err.Error()))
				return
			}
			a.toast(locales.ExportedFlowsTo(len(flows), filepath.Base(path)))
		})
	}()
}

func (a *App) exportCode(f *flow.Flow, language string) {
	if f == nil {
		return
	}
	code := codegen.Named(language)(codegen.Of(f))
	ext := codegen.Extension(language)
	dir := a.lastDir()
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: a.win, Title: locales.ExportLanguage(language), DefaultPath: filepath.Join(dir, "request."+ext)})
		if err != nil || path == "" {
			return
		}
		err = os.WriteFile(path, []byte(code+"\n"), 0o644)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotSave(err.Error()))
			} else {
				a.toast(locales.SavedName(filepath.Base(path)))
			}
		})
	}()
}

func (a *App) blockApp(f *flow.Flow, hide bool) {
	r := &rules.AppRule{ID: rules.NewID(), Enabled: true, AppName: clientName(f)}
	if f.Client.BundleIdentifier != nil && *f.Client.BundleIdentifier != "" {
		r.BundleID = *f.Client.BundleIdentifier
	}
	if hide {
		r.Action = rules.BlockHide
	}
	a.rules.Update(func(d *rules.Data) {
		d.BlockedApps = append(d.BlockedApps, r)
		delete(d.DisabledTools, rules.ToolBlock)
	})
	a.toast(locales.BlockedAppsTraffic(cmp.Or(a.clientLabel(f), r.BundleID)))
}

func (a *App) exportBody(f *flow.Flow, response bool) {
	if f == nil {
		return
	}
	body := f.DecodedRequestBody()
	if response {
		body = f.DecodedResponseBody()
	}
	name := cmp.Or(filepath.Base(strings.SplitN(f.URLPath(), "?", 2)[0]), "body")
	if name == "/" || name == "." {
		name = "body"
	}
	dir := a.lastDir()
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: a.win, Title: locales.SaveBody(), DefaultPath: filepath.Join(dir, name)})
		if err != nil || path == "" {
			return
		}
		err = os.WriteFile(path, body, 0o644)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotSave(err.Error()))
			} else {
				a.toast(locales.SavedName(filepath.Base(path)))
			}
		})
	}()
}

func (a *App) exportRules() {
	dir := a.lastDir()
	parent := a.dialogParent("settings")
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Title: locales.ExportSettings(),
			DefaultPath: filepath.Join(dir, "ProxyGo Settings "+time.Now().Format("2006-01-02")+".json"),
			Filters:     []mygo.FileFilter{{Name: "JSON", Extensions: []string{"json"}}}})
		if err != nil || path == "" {
			return
		}
		err = a.rules.Export(path)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotExport(err.Error()))
			} else {
				a.toast(locales.ExportedTheToolsRulesAndSettings())
			}
		})
	}()
}

func (a *App) importRules() {
	parent := a.dialogParent("settings")
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Title: locales.ImportSettings(),
			Filters: []mygo.FileFilter{{Name: "JSON", Extensions: []string{"json"}}}})
		if err != nil || len(paths) == 0 {
			return
		}
		r, err := confirm(parent, locales.ReplaceEveryRuleAndSettingWith(), locales.TheCurrentRulesAreReplacedExport(), locales.Replace(), locales.Cancel())
		if err != nil || r != 0 {
			return
		}
		err = a.rules.Import(paths[0])
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotImportError(err.Error()))
			} else {
				a.toast(locales.ImportedSettings())
			}
		})
	}()
}

func (a *App) dialogParent(kind string) *mygo.Window {
	if w := a.windows[kind]; w != nil {
		return w
	}
	return a.win
}

func confirm(parent *mygo.Window, message, detail string, buttons ...string) (int, error) {
	r, err := mygo.Dialog.Message(mygo.MessageOptions{
		Parent: parent, Type: mygo.MessageWarning, Message: message, Detail: detail,
		Buttons: buttons, DefaultButton: 0, CancelButton: len(buttons) - 1,
	})
	return r.Button, err
}

func confirmDelete(parent *mygo.Window, message, detail string) (bool, error) {
	r, err := mygo.Dialog.Message(mygo.MessageOptions{
		Parent: parent, Type: mygo.MessageWarning, Message: message, Detail: detail,
		Buttons: []string{locales.Delete(), locales.Cancel()}, DefaultButton: 1, CancelButton: 1,
	})
	return r.Button == 0, err
}

func revealInFinder(path string) { _ = exec.Command("open", "-R", path).Start() }
func openPath(path string)       { _ = exec.Command("open", path).Start() }

func (a *App) installCertificate() {
	if a.certs == nil {
		return
	}
	go func() {
		err := a.certs.Install()
		trusted := err == nil && a.awaitTrust(true)
		a.do(func() {
			a.certTrusted = trusted
			switch {
			case err != nil:
				a.toast(locales.CannotInstallTheCertificate(err.Error()))
			case trusted:
				a.toast(locales.TheProxyGoCertificateIsInstalledAnd())
			default:
				a.toast(locales.TheCertificateIsInstalledButMacOS())
			}
		})
	}()
}

func (a *App) checkTrust() {
	if a.certs == nil {
		return
	}
	go func() {
		trusted := a.certs.Trusted()
		a.do(func() {
			a.certTrusted = trusted
			if trusted {
				a.toast(locales.MacOSTrustsTheProxyGoCertificate())
			} else {
				a.toast(locales.MacOSDoesNotTrustTheProxyGo())
			}
		})
	}()
}

func (a *App) awaitTrust(want bool) bool {
	trusted := a.certs.Trusted()
	for range 20 {
		if trusted == want {
			break
		}
		time.Sleep(250 * time.Millisecond)
		trusted = a.certs.Trusted()
	}
	return trusted
}

func (a *App) uninstallCertificate() {
	if a.certs == nil {
		return
	}
	go func() {
		err := a.certs.Uninstall()
		trusted := a.awaitTrust(false)
		a.do(func() {
			a.certTrusted = trusted
			if err != nil {
				a.toast(locales.CannotRemoveTheCertificate(err.Error()))
			} else {
				a.toast(locales.RemovedTheProxyGoCertificateFromThe())
			}
		})
	}()
}

func (a *App) regenerateCertificate() {
	if a.certs == nil {
		return
	}
	parent := a.dialogParent("certificate")
	go func() {
		r, err := confirm(parent, locales.ResetTheProxyGoCertificate(), locales.ANewRootCertificateReplacesThe(), locales.Reset(), locales.Cancel())
		if err != nil || r != 0 {
			return
		}
		_ = a.certs.Uninstall()
		err = a.certs.Regenerate()
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotReset(err.Error()))
				return
			}
			a.certTrusted = false
			a.toast(locales.MadeANewRootCertificateInstall())
		})
	}()
}

func (a *App) exportCertificate(format string) {
	if a.certs == nil {
		return
	}
	ext := map[string]string{"pem": "pem", "der": "cer", "key": "key", "p12": "p12"}[format]
	parent := a.dialogParent("certificate")
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Title: locales.ExportCertificate(),
			DefaultPath: filepath.Join(a.lastDir(), "ProxyGo CA."+ext)})
		if err != nil || path == "" {
			return
		}
		password := ""
		if format == "p12" {
			password = "proxygo"
		}
		err = a.certs.Export(format, path, password)
		a.do(func() {
			switch {
			case err != nil:
				a.toast(locales.CannotExport(err.Error()))
			case format == "p12":
				a.toast(locales.ExportedWithPassword(filepath.Base(path)))
			default:
				a.toast(locales.ExportedName(filepath.Base(path)))
			}
		})
	}()
}

func parseURL(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New(locales.TheURLMustStartWithHTTP())
	}
	if u.Host == "" {
		return nil, errors.New(locales.TheURLHasNoHost())
	}
	return u, nil
}

func (a *App) proxyAddress() string {
	return fmt.Sprintf("%s:%d", a.proxyHost(), a.proxy.Port())
}

func (a *App) proxyHost() string {
	if a.set.ListenLocalhost {
		return "127.0.0.1"
	}
	return primaryIP()
}
