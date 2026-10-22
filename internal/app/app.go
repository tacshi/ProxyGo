package app

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	_ "image/png"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/certs"
	"proxygo/internal/clientinfo"
	"proxygo/internal/control"
	"proxygo/internal/flow"
	"proxygo/internal/mcp"
	"proxygo/internal/privileged"
	"proxygo/internal/protobuf"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/saved"
	"proxygo/internal/script"
	"proxygo/internal/session"
	"proxygo/internal/settings"
	"proxygo/internal/store"
	"proxygo/internal/systemproxy"
	"proxygo/locales"
)

type App struct {
	dir     string
	store   *store.Store
	rules   *rules.Store
	certs   *certs.Manager
	proxy   *proxy.Server
	clients *clientinfo.Lookup
	scripts *script.Engine
	prefs   *settings.Store
	set     settings.Settings
	pal     palette

	win       *mygo.Window
	windows   map[string]*mygo.Window
	menu      menuItems
	clipboard func(string)
	toasts    map[string][]string

	flows     []*flow.Flow
	version   uint64
	visible   []*flow.Flow
	filterKey string
	list      ui.ListState
	row       int
	chosen    ui.Selection[string]
	selected  string
	sort      ui.SortOrder
	sorted    ui.SortOrder
	colValues map[string]string
	newest    string
	ov        *overviewStats

	section        string
	kinds          map[string]bool
	query          string
	deep           bool
	conditions     []store.Condition
	matchAny       bool
	advanced       bool
	sidebarQuery   string
	sidebarHandle  ui.Handle
	expanded       map[string]bool
	sources        *sourceTree
	sourcesVersion uint64
	srcParent      map[string]string
	srcExpandable  map[string]bool
	filterHandle   ui.Handle
	filterFocus    bool
	appsOpen       bool
	domainsOpen    bool
	foldersOpen    bool
	devicesOpen    bool

	splitChrome, lastWin ui.Rect
	reqTabName           string
	respTabName          string
	bodyMode             map[string]int
	viewers              map[string]*viewer
	trees                map[string]*jsonTree
	images               map[string]*ui.Bitmap
	dots                 menuDots
	dotsOn, dotsDark     bool
	partRow              map[string]*int
	wsRow                int
	ws                   wsView
	sseRow               int
	listSplit            float32
	composeSplit         float32
	scriptSplit          float32
	jsonFilter           map[string]*jsonQuery

	paused                    bool
	proxyErr                  string
	sys                       systemproxy.State
	sysKnown, routeHintClosed bool
	overrode                  bool
	sysBefore                 systemproxy.State
	upRate                    int64
	memory                    int64
	downRate                  int64
	lastUp                    int64
	lastDown                  int64
	certTrusted               bool

	palette    paletteState
	comment    commentState
	repeat     repeatState
	colEdit    columnEditor
	folderSave folderSheet

	pauses      []*pending
	bpChosen    string
	compose     composeState
	lists       map[string]*ui.ListState
	tplSave     templateSheet
	bpListWidth float32
	devices     devices
	rootImport  rootImport
	presetSave  presetSheet
	deviceEdit  deviceSheet
	tray        *mygo.Tray
	trayItems   trayItems
	quitting    bool
	askMu       sync.Mutex
	diff        diffState
	tools       map[string]*toolState
	scriptUI    scriptState
	settingsTab int
	drafts      settingsDrafts
	certTab     int

	icons       map[string]*ui.Bitmap
	iconData    map[string][]byte
	bundleIcon  appIconState
	updates     updatePrefs
	sessionPath string

	schemas  *protobuf.Schemas
	folders  *saved.Store
	sessions map[string]*sessionView

	control        *control.Server
	mcp            *mcp.Server
	automationErr  string
	mcpOn          atomic.Bool
	mcpShowSecrets atomic.Bool
	localOnly      atomic.Bool
	proxyPaused    atomic.Bool

	queueMu sync.Mutex
	queue   []func()
}

func New(dir string) (*App, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	a := &App{
		dir:          dir,
		prefs:        settings.Open(filepath.Join(dir, "settings.json")),
		rules:        rules.Open(filepath.Join(dir, "rules.json")),
		scripts:      script.New(),
		windows:      map[string]*mygo.Window{},
		clipboard:    func(s string) { mygo.Clipboard.WriteText(s) },
		section:      "all",
		row:          -1,
		kinds:        map[string]bool{},
		expanded:     map[string]bool{},
		appsOpen:     true,
		domainsOpen:  true,
		foldersOpen:  true,
		devicesOpen:  true,
		bodyMode:     map[string]int{},
		viewers:      map[string]*viewer{},
		trees:        map[string]*jsonTree{},
		images:       map[string]*ui.Bitmap{},
		partRow:      map[string]*int{},
		tools:        map[string]*toolState{},
		icons:        map[string]*ui.Bitmap{},
		iconData:     map[string][]byte{},
		listSplit:    65,
		composeSplit: 50,
		scriptSplit:  50,
	}
	a.set = a.prefs.Get()
	a.paused = a.set.StartPaused
	a.proxyPaused.Store(a.paused)
	a.syncAtomics()
	a.store = store.New(a.set.MaxFlows)
	a.store.SetMemoryLimit(int64(a.set.MemoryLimitMB) << 20)
	a.scripts.SetRoot(filepath.Join(dir, "scripts"))
	a.schemas = protobuf.OpenSchemas(filepath.Join(dir, "protobuf"))
	a.folders = saved.Open(filepath.Join(dir, "saved"))
	cm, err := certs.New(filepath.Join(dir, "certificates"))
	if err != nil {
		a.proxyErr = locales.CertificateAuthorityError(err.Error())
	} else {
		a.certs = cm
	}
	a.proxy = a.newProxy(nil)
	a.compose = newCompose("https://")
	return a, nil
}

func (a *App) newProxy(clients *clientinfo.Lookup) *proxy.Server {
	addr, network := a.set.ListenAddr(a.set.Port)
	p := proxy.New(proxy.Options{
		Addr:       addr,
		Network:    network,
		Certs:      a.certs,
		Rules:      a.rules,
		Scripts:    a.scripts,
		Clients:    clients,
		Sink:       a.store,
		Breakpoint: a.breakpoint,
		AskDevice:  a.askDevice,
	})
	p.SetPaused(a.paused)
	return p
}

func Main() {
	mygo.App.SetName("ProxyGo")
	dir := os.Getenv("PROXYGO_DATA_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "ProxyGo")
	}
	mygo.App.SetWindowStateStore(windowStates(dir))
	a, err := New(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ProxyGo:", err)
		os.Exit(1)
	}
	if a.set.Language != "" {
		mygo.App.SetLocale(a.set.Language)
	}
	mygo.Theme.SetSource(themeSource(a.set.Appearance))
	mygo.Use(updaterPlugin(a.set.AppIcon))
	mygo.App.WhenReady(a.start)
	if err := mygo.App.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "ProxyGo:", err)
		os.Exit(1)
	}
}

func (a *App) start() {
	a.clients = clientinfo.New(1200 * time.Millisecond)
	a.proxy = a.newProxy(a.clients)
	if a.certs != nil {
		if err := a.proxy.Start(); err != nil {
			a.proxyErr = locales.TheProxyCouldNotListen(strconv.Itoa(a.set.Port), err.Error())
		}
	}

	a.win = mygo.NewWindow(mygo.WindowOptions{
		Title:                "ProxyGo",
		Width:                1440,
		Height:               900,
		UseContentSize:       true,
		MinWidth:             900,
		MinHeight:            560,
		TitleBarStyle:        mygo.TitleBarHidden,
		TrafficLightPosition: &mygo.Point{X: 14, Y: 18},
		StateKey:             "main",
		AlwaysOnTop:          a.set.StayOnTop,
		Content:              ui.View(a.view),
	})
	a.win.OnClose(func(e *mygo.CloseEvent) {
		if !a.quitting {
			e.PreventDefault()
			a.win.Hide()
		}
	})
	mygo.App.OnBeforeQuit(func(*mygo.QuitEvent) { a.quitting = true })
	mygo.App.OnActivate(func(visible bool) {
		if !visible {
			a.showMain()
		}
	})
	a.win.OnClosed(a.shutdown)
	a.win.OnFocus(func() { go a.refreshTrust() })
	a.watchUpdates()
	a.installMenu()
	a.watchLocale()
	a.watchMenuDots()
	a.applyAppIcon()
	a.setMenuBarIcon(!a.set.HideMenuBarIcon)
	a.startServers()
	if a.set.OpenLastSession {
		a.openLastSession()
	}
	go a.recoverSystemProxy()
	if a.set.OverrideSystemProxy && a.proxyErr == "" {
		a.setSystemProxy(true)
	}
	go a.watch()
	go a.refreshTrust()
	go func() {
		st := systemproxy.Status()
		a.do(func() { a.sys, a.sysKnown = st, true })
	}()
}

func (a *App) shutdown() {
	if a.overrode && systemproxy.Status().PointsAt("127.0.0.1", a.proxy.Port()) {
		if privileged.RestoreProxy(a.sysBefore) == nil {
			systemproxy.Forget(a.proxyStatePath())
		}
	}
	a.stopServers()
	a.saveAutosave()
	a.updateSettings(func(*settings.Settings) {})
	if a.clients != nil {
		a.clients.Close()
	}
	a.proxy.Stop()
	for _, w := range a.windows {
		w.Close()
	}
}

func (a *App) watch() {
	tick := time.NewTicker(120 * time.Millisecond)
	defer tick.Stop()
	var seen uint64
	n := 0
	for range tick.C {
		if a.win == nil || a.win.IsDestroyed() {
			return
		}
		if v := a.store.Version(); v != seen {
			seen = v
			a.win.Update(func() {
				for _, w := range a.windows {
					w.Invalidate()
				}
			})
		}
		n++
		if n%8 == 0 {
			up, down := a.store.Traffic()
			a.do(func() {
				a.upRate = max(0, (up-a.lastUp)*1000/960)
				a.downRate = max(0, (down-a.lastDown)*1000/960)
				a.lastUp, a.lastDown = up, down
			})
		}
		if n%25 == 0 {
			st := systemproxy.Status()
			mem := residentMemory()
			a.do(func() { a.sys, a.sysKnown, a.memory = st, true, mem })
		}
	}
}

func (a *App) do(fn func()) {
	if a.win != nil {
		a.win.Update(func() {
			fn()
			for _, w := range a.windows {
				w.Invalidate()
			}
		})
		return
	}
	a.queueMu.Lock()
	a.queue = append(a.queue, fn)
	a.queueMu.Unlock()
}

func (a *App) runQueued() {
	a.queueMu.Lock()
	fns := a.queue
	a.queue = nil
	a.queueMu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

func (a *App) invalidate() {
	if a.win != nil {
		a.win.Invalidate()
	}
	for _, w := range a.windows {
		w.Invalidate()
	}
}

func (a *App) toast(msg string) {
	key := a.frontWindow()
	if a.toasts == nil {
		a.toasts = map[string][]string{}
	}
	a.toasts[key] = append(a.toasts[key], msg)
	a.invalidate()
}

func (a *App) frontWindow() string {
	for key, w := range a.windows {
		if w.IsFocused() {
			return key
		}
	}
	return ""
}

func (a *App) showToasts(c *ui.Context, key string) {
	for _, m := range a.toasts[key] {
		c.Toast(m)
	}
	delete(a.toasts, key)
}

func (a *App) copy(text, what string) {
	a.clipboard(text)
	if what != "" {
		a.toast(what)
	}
}

func (a *App) updateSettings(fn func(*settings.Settings)) {
	layout := a.set
	err := a.prefs.Update(func(s *settings.Settings) {
		s.SidebarWidth, s.TableHeight, s.TableWidth, s.DetailPercent = layout.SidebarWidth, layout.TableHeight, layout.TableWidth, layout.DetailPercent
		fn(s)
	})
	if err != nil {
		a.toast(locales.CannotSaveSettings(err.Error()))
	}
	a.set = a.prefs.Get()
	a.syncAtomics()
}

func (a *App) refreshFlows() {
	v := a.store.Version()
	if v == a.version && a.flows != nil {
		return
	}
	a.version = v
	a.flows = a.store.Snapshot()
	a.filterKey = ""
}

func (a *App) filter() store.Filter {
	f := store.Filter{Query: a.query, Deep: a.deep, Kinds: a.kinds, Conditions: a.conditions, Any: a.matchAny}
	switch {
	case strings.HasPrefix(a.section, "app:"), strings.HasPrefix(a.section, "domain:"), strings.HasPrefix(a.section, "src:"):
		if s, ok := parseSource(a.section); ok {
			f.Client, f.Host, f.Path = s.app, s.host, s.path
		}
	case strings.HasPrefix(a.section, "pin:"):
		key := strings.TrimPrefix(a.section, "pin:")
		if host, ok := strings.CutPrefix(key, "host:"); ok {
			f.Host = host
		} else if app, ok := strings.CutPrefix(key, "app:"); ok {
			f.Client = app
		}
	case a.section == "pinned":
		for _, k := range a.set.Pinned {
			if host, ok := strings.CutPrefix(k, "host:"); ok {
				f.Hosts = append(f.Hosts, host)
			}
		}
		if len(f.Hosts) == 0 {
			f.Hosts = []string{"\x00"}
		}
	case a.section == "saved":
		f.Saved = true
	}
	return f
}

func (a *App) applyFilter() {
	key := fmt.Sprint(a.version, a.section, a.query, a.deep, a.kinds, a.conditions, a.matchAny, a.sort, a.set.Pinned)
	if key == a.filterKey {
		return
	}
	a.filterKey = key
	a.visible = store.Apply(a.flows, a.filter())
	if a.sort.Column != "" && a.sort.Column != store.SortRow {
		store.Sort(a.visible, a.sort.Column, a.sort.Descending)
	} else if a.sort.Descending {
		store.Sort(a.visible, store.SortRow, true)
	}
	a.row = -1
	for i, f := range a.visible {
		if f.UniqueID == a.selected {
			a.row = i
			break
		}
	}
	if a.sort != a.sorted {
		a.sorted = a.sort
		switch {
		case a.row >= 0:
			a.list.ScrollTo(a.row, ui.Center)
		case a.sort.Descending || (a.sort.Column != "" && a.sort.Column != store.SortRow):
			a.list.ScrollTo(0, ui.Start)
		default:
			a.list.ScrollToEnd()
		}
	}
	if !a.set.AutoSelect || len(a.flows) == 0 {
		return
	}
	if id := a.flows[len(a.flows)-1].UniqueID; id != a.newest {
		a.newest = id
		if slices.ContainsFunc(a.visible, func(f *flow.Flow) bool { return f.UniqueID == id }) {
			a.selectFlow(id)
			return
		}
	}
	if a.row < 0 && len(a.visible) > 0 {
		last := len(a.visible) - 1
		if a.sort.Descending {
			last = 0
		}
		a.selectFlow(a.visible[last].UniqueID)
	}
}

func (a *App) selectedFlow() *flow.Flow {
	if a.selected == "" {
		return nil
	}
	f, _ := a.store.Lookup(a.selected)
	return f
}

func (a *App) chosenFlows() []*flow.Flow {
	var out []*flow.Flow
	for _, f := range a.visible {
		if a.chosen.Has(f.UniqueID) {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		if f := a.selectedFlow(); f != nil {
			out = append(out, f)
		}
	}
	return out
}

func (a *App) selectFlow(id string) {
	a.selected = id
	a.chosen.Clear()
	if id != "" {
		a.chosen.Add(id)
	}
	a.row = -1
	for i, f := range a.visible {
		if f.UniqueID == id {
			a.row = i
			a.list.ScrollIntoView(i)
			break
		}
	}
}

func (a *App) autosavePath() string { return filepath.Join(a.dir, "Last Session"+session.Ext) }

func (a *App) saveAutosave() {
	flows := a.store.Snapshot()
	if len(flows) == 0 {
		_ = os.Remove(a.autosavePath())
		return
	}
	_ = session.Write(a.autosavePath(), flows, a.iconStrings())
}

func (a *App) openLastSession() {
	path := a.autosavePath()
	if _, err := os.Stat(path); err != nil {
		matches, _ := filepath.Glob(filepath.Join(a.dir, "*"+session.Ext))
		if len(matches) == 0 {
			return
		}
		path = matches[0]
		for _, m := range matches[1:] {
			fi, err1 := os.Stat(m)
			li, err2 := os.Stat(path)
			if err1 == nil && err2 == nil && fi.ModTime().After(li.ModTime()) {
				path = m
			}
		}
	}
	if b, err := session.Open(path); err == nil {
		a.loadBundle(b, path, false)
	}
}

func (a *App) loadBundle(b *session.Bundle, path string, add bool) {
	if add {
		a.store.Append(b.Flows)
	} else {
		a.store.Replace(b.Flows)
		a.sessionPath = path
	}
	a.loadIcons(b.Icons)
	a.refreshFlows()
	a.applyFilter()
	if !add && len(a.visible) > 0 {
		a.selectFlow(a.visible[len(a.visible)-1].UniqueID)
	}
}

func (a *App) iconStrings() map[string]string {
	out := make(map[string]string, len(a.iconData))
	for p, data := range a.iconData {
		out[p] = base64.StdEncoding.EncodeToString(data)
	}
	return out
}

func (a *App) loadIcons(icons map[string]string) {
	for path, b64 := range icons {
		if _, ok := a.iconData[path]; ok {
			continue
		}
		if i := strings.Index(b64, "base64,"); i >= 0 {
			b64 = b64[i+7:]
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(data) == 0 || blankImage(data) {
			continue
		}
		a.iconData[path] = data
		if bmp, err := ui.DecodeBitmap(data); err == nil {
			a.icons[path] = bmp
		}
	}
}

func blankImage(data []byte) bool {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return false
	}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a > 0x1000 {
				return false
			}
		}
	}
	return true
}

func (a *App) appIcon(path string) *ui.Bitmap {
	if path == "" {
		return nil
	}
	if bmp, ok := a.icons[path]; ok {
		return bmp
	}
	if a.win == nil {
		return nil
	}
	a.icons[path] = nil
	bundle := cmp.Or(clientinfo.BundlePath(path), path)
	if data, err := mygo.Shell.FileIcon(bundle, 32); err == nil && len(data) > 0 && !blankImage(data) {
		if bmp, err := ui.DecodeBitmap(data); err == nil {
			a.icons[path] = bmp
			a.iconData[path] = data
			return bmp
		}
	}
	return nil
}

type pending struct {
	*proxy.Pause
	done chan decision
	edit *messageEditor
	at   time.Time
}

type decision struct {
	msg proxy.Message
	ok  bool
}

func (a *App) breakpoint(ctx context.Context, p *proxy.Pause) (proxy.Message, bool) {
	pd := &pending{Pause: p, done: make(chan decision, 1), at: time.Now()}
	a.do(func() {
		pd.edit = newMessageEditor(p.Message, p.Response)
		a.pauses = append(a.pauses, pd)
		if a.bpChosen == "" {
			a.bpChosen = p.ID
		}
		a.openWindow("bpedit")
	})
	select {
	case d := <-pd.done:
		return d.msg, d.ok
	case <-ctx.Done():
		a.do(func() { a.dropPause(pd.ID) })
		return p.Message, false
	}
}

func (a *App) resolvePause(id string, ok, edited bool) {
	for _, pd := range a.pauses {
		if pd.ID != id {
			continue
		}
		msg := pd.Message
		if edited && pd.edit != nil {
			msg = pd.edit.message()
		}
		pd.done <- decision{msg: msg, ok: ok}
		a.dropPause(id)
		return
	}
}

func (a *App) dropPause(id string) {
	for i, pd := range a.pauses {
		if pd.ID == id {
			a.pauses = append(a.pauses[:i], a.pauses[i+1:]...)
			break
		}
	}
	if a.bpChosen == id {
		a.bpChosen = ""
		if len(a.pauses) > 0 {
			a.bpChosen = a.pauses[0].ID
		}
	}
	a.invalidate()
}

func (a *App) setSystemProxy(on bool) { a.changeSystemProxy(on, false) }

func (a *App) resetSystemProxy() { a.changeSystemProxy(false, true) }

func (a *App) changeSystemProxy(on, reset bool) {
	go func() { _ = a.applySystemProxy(on, reset) }()
}

func (a *App) removeHelper() {
	go func() {
		err := privileged.Uninstall()
		a.do(func() {
			switch {
			case errors.Is(err, privileged.ErrCanceled):
			case err != nil:
				a.toast(locales.HelperError(err.Error()))
			default:
				a.toast(locales.RemovedProxyGosHelper())
			}
		})
	}()
}

func (a *App) systemProxyOn() bool { return a.isProxyGo(a.sys) }

func (a *App) isProxyGo(st systemproxy.State) bool {
	port := a.proxy.Port()
	return st.PointsAt("127.0.0.1", port) || st.PointsAt(primaryIP(), port)
}

func (a *App) refreshTrust() {
	if a.certs == nil {
		return
	}
	trusted := a.certs.Trusted()
	a.do(func() {
		if a.certTrusted != trusted {
			a.certTrusted = trusted
			a.invalidate()
		}
	})
}

func (a *App) listState(key string, follow bool) *ui.ListState {
	l := a.lists[key]
	if l == nil {
		if a.lists == nil || len(a.lists) >= 64 {
			a.lists = map[string]*ui.ListState{}
		}
		l = &ui.ListState{FollowEnd: follow}
		a.lists[key] = l
	}
	return l
}
