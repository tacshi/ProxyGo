package app

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/saved"
	"proxygo/internal/store"
)

const maxSidebarItems = 300

func (a *App) sidebar(c *ui.Context) {
	p := a.pal
	bar := c.TitleBar()
	tree := a.sourceTree()
	apps, domains := tree.apps, tree.domains
	q := strings.ToLower(strings.TrimSpace(a.sidebarQuery))
	a.srcParent, a.srcExpandable = map[string]string{}, map[string]bool{}
	match := func(s string) bool { return q == "" || strings.Contains(strings.ToLower(s), q) }

	ui.Column(c).FillHeight().Background(p.sidebar).Children(func() {
		ui.Row(c).Height(max(bar.Height, 52)).FillWidth().Padding(0, 8, 0, bar.Left+14).AlignItems(ui.Center).DragWindow().Children(func() {
			ui.Spacer(c)
			if plainIconButton(c, "sidebar", "Hide Sidebar (⌥⌘S)", 15, p.text2, p.hover).Clicked() {
				a.setSidebar(false)
			}
		})
		sb := ui.Sidebar(c, &a.section, func() {
			ui.SidebarSection(c, "Capture", nil, func() {
				ui.SidebarItem(c, "overview", icon("chart"), "Overview")
				ui.SidebarItem(c, "all", icon("list"), "All").Children(func() {
					if len(a.flows) > 0 {
						ui.Badge(c, fmt.Sprint(len(a.flows)))
					}
				})
			})
			ui.SidebarSection(c, "Favorites", nil, func() {
				ui.SidebarItem(c, "saved", icon("bookmark"), "Saved").Children(func() {
					if n := countSaved(a.flows); n > 0 {
						ui.Badge(c, fmt.Sprint(n))
					}
				})
				ui.SidebarItem(c, "pinned", icon("pin"), "Pinned Domains")
				for _, key := range a.set.Pinned {
					kind, name, _ := strings.Cut(key, ":")
					ic, n, label := "globe", domains[name], name
					switch {
					case kind == "app" && tree.devices[name] > 0:
						ic, n, label = "device", tree.devices[name], a.deviceName(name)
					case kind == "app":
						ic, n = "appWindow", apps[name]
					}
					it := ui.SidebarItem(c, "pin:"+key, icon(ic), label)
					it.Children(func() {
						if n > 0 {
							ui.Badge(c, fmt.Sprint(n))
						}
					})
					it.ContextMenu(func(m *ui.Menu) {
						if m.Item("Unpin").Chosen() {
							a.togglePin(key)
						}
					})
				}
			})
			if len(tree.devices) > 0 {
				ui.SidebarSection(c, fmt.Sprintf("Remote Devices (%d)", len(tree.devices)), &a.devicesOpen, func() {
					for _, ip := range store.ByCount(tree.devices) {
						var only func(source) bool
						if q != "" && !match(ip) && !match(a.deviceName(ip)) {
							hosts := tree.appHosts[ip]
							if !slices.ContainsFunc(slices.Collect(maps.Keys(hosts)), match) {
								continue
							}
							only = func(s source) bool { return match(s.host) }
						}
						a.sourceItem(c, tree, source{app: ip}, 0, tree.devices[ip], only)
					}
				})
			}
			if folders := a.folders.Folders(); len(folders) > 0 {
				ui.SidebarSection(c, "Saved Folders", &a.foldersOpen, func() {
					for _, f := range folders {
						if match(f.Path) {
							a.folderItem(c, f)
						}
					}
				})
			}
			ui.SidebarSection(c, fmt.Sprintf("Apps (%d)", len(tree.apps)), &a.appsOpen, func() {
				for i, name := range store.ByCount(tree.apps) {
					if i >= maxSidebarItems {
						break
					}
					app := source{app: name}
					var only func(source) bool
					if q != "" && !match(name) {
						hosts := tree.appHosts[name]
						if !slices.ContainsFunc(slices.Collect(maps.Keys(hosts)), match) {
							continue
						}
						only = func(s source) bool { return match(s.host) }
					}
					a.sourceItem(c, tree, app, 0, tree.apps[name], only)
				}
			})
			ui.SidebarSection(c, fmt.Sprintf("Domains (%d)", len(tree.domains)), &a.domainsOpen, func() {
				for i, host := range store.ByCount(tree.domains) {
					if i >= maxSidebarItems {
						break
					}
					if !match(host) {
						continue
					}
					a.sourceItem(c, tree, source{host: host}, 0, tree.domains[host], nil)
				}
			})
		}).Grow(1).Label("Sources").Bind(&a.sidebarHandle)
		if sb.Shortcut(0, ui.KeyRight) {
			if a.srcExpandable[a.section] {
				a.expanded[a.section] = true
			}
		}
		if sb.Shortcut(0, ui.KeyLeft) {
			if a.expanded[a.section] {
				a.expanded[a.section] = false
			} else if up, ok := a.srcParent[a.section]; ok {
				a.section = up
			}
		}
		ui.Divider(c)
		ui.Row(c).Height(footerHeight).FillWidth().Padding(0, 8).AlignItems(ui.Center).Children(func() {
			box, _ := a.searchField(c, "sidebarFilter", &a.sidebarQuery, "Filter Domain or App", "Filter domains and apps")
			box.Grow(1).Background(p.bg)
		})
	})
}

func (a *App) sourceTree() *sourceTree {
	if a.sources == nil || a.sourcesVersion != a.version {
		a.sources = buildSources(a.flows)
		a.sourcesVersion = a.version
	}
	return a.sources
}

const maxChildren = 200

func (a *App) sourceItem(c *ui.Context, tree *sourceTree, s source, depth, count int, only func(source) bool) {
	p := a.pal
	id := s.id()
	expandable := tree.expandable(s)
	open := a.expanded[id] || (only != nil && depth == 0)
	device := s.host == "" && tree.devices[s.app] > 0
	label := s.label()
	ic := "folder"
	switch {
	case device:
		ic, label = "device", a.deviceName(s.app)
	case s.host == "":
		ic = "appWindow"
	case s.path == "" && a.rules.Current().ShouldMITM(s.host):
		ic = "lockOpen"
	case s.path == "":
		ic = "globe"
	}
	indent := 18 + float32(depth)*14
	var bmp *ui.Bitmap
	if s.host == "" && !device {
		bmp = a.appIcon(tree.appPaths[s.app])
	}
	if bmp != nil {
		ic = "blank"
	}
	it := ui.SidebarItem(c, id, icon(ic), label).PaddingStart(indent)
	it.Children(func() {
		if bmp != nil {
			ui.Column(c).Absolute().Left(indent).Top(0).Bottom(0).Width(16).Center().Children(func() {
				ui.Image(c, bmp).Size(16, 16)
			})
		}
		if expandable {
			color := p.muted
			if a.section == id && a.sidebarHandle.Focused(c) {
				color = p.onAccent
			}
			name := map[bool]string{true: "Collapse ", false: "Expand "}[open] + label
			arrow := ui.ButtonBase(c).Absolute().Left(indent - 17).Top(0).Bottom(0).Width(16).Label(name).KeepFocus()
			arrow.Children(func() {
				ui.Column(c).Fill().Center().Children(func() {
					glyph(c, map[bool]string{true: "chevronDown", false: "chevronRight"}[open], 9, color)
				})
			})
			if arrow.Clicked() {
				a.expanded[id] = !open
			}
		}
		ui.Badge(c, fmt.Sprint(count))
	})
	if device {
		it.Tooltip(s.app)
		it.ContextMenu(func(m *ui.Menu) { a.deviceMenu(m, s.app) })
	} else {
		it.ContextMenu(func(m *ui.Menu) { a.sourceMenu(m, s) })
	}
	if expandable {
		a.srcExpandable[id] = true
	}
	if up, ok := s.parent(); ok {
		a.srcParent[id] = up.id()
	}
	if !expandable || !open {
		return
	}
	for i, ch := range tree.children(s) {
		if i >= maxChildren {
			break
		}
		if only != nil && !only(ch.source) {
			continue
		}
		a.sourceItem(c, tree, ch.source, depth+1, ch.count, nil)
	}
}

func (a *App) sourceMenu(m *ui.Menu, s source) {
	switch {
	case s.host == "":
		a.appMenu(m, s.app)
		return
	case s.app == "" && s.path == "":
		a.domainMenu(m, s.host)
		return
	}
	if s.path == "" {
		key := "host:" + s.host
		if m.Item(map[bool]string{true: "Unpin ", false: "Pin "}[a.pinned(key)] + s.host).Chosen() {
			a.togglePin(key)
		}
		if !a.rules.Current().ShouldMITM(s.host) && m.Item("Enable SSL Proxying for "+s.host).Chosen() {
			a.enableSSL(s.host, false)
		}
	}
	if m.Item("Copy URL Pattern").Chosen() {
		a.copy(s.pattern(), "the URL pattern")
	}
	m.Submenu("Tools", func(m *ui.Menu) {
		probe := &flow.Flow{Request: &flow.Request{Scheme: "https", Host: s.host, FullPath: "https://" + s.pattern(), Method: flow.Method{Name: "GET"}}}
		if m.Item("Breakpoint…").Chosen() {
			a.breakpointFromFlow(probe)
		}
		if m.Item("Map Remote…").Chosen() {
			a.mapRemoteFromFlow(probe)
		}
		if m.Item("Network Conditions…").Chosen() {
			a.throttleFromFlow(probe)
		}
		if m.Item("Block List").Chosen() {
			a.blockFromFlow(probe, false)
		}
	})
	m.Separator()
	where := s.host + s.path
	if s.app != "" {
		where += " in " + s.app
	}
	if m.Item("Delete All from " + where).Chosen() {
		a.deleteMatching(s.match)
	}
}

func (a *App) appMenu(m *ui.Menu, name string) {
	key := "app:" + name
	if m.Item(map[bool]string{true: "Unpin", false: "Pin"}[a.pinned(key)]).Chosen() {
		a.togglePin(key)
	}
	if m.Item("Copy Name").Chosen() {
		a.copy(name, "the app's name")
	}
	var some, secure *flow.Flow
	for _, f := range a.flows {
		if clientName(f) != name {
			continue
		}
		some = cmp.Or(some, f)
		if secure == nil && (f.IsTunnel() || f.IsHTTPS()) {
			secure = f
		}
	}
	if secure != nil || some != nil && name != "System" {
		m.Separator()
	}
	if secure != nil && m.Item("Enable SSL Proxying for Its Domains").Chosen() {
		a.enableSSLForClient(secure)
	}
	if some != nil && name != "System" && m.Item("Block this App").Chosen() {
		a.blockApp(some, false)
	}
	m.Separator()
	if m.Item("Delete All from " + name).Chosen() {
		a.deleteMatching(func(f *flow.Flow) bool { return clientName(f) == name })
	}
}

func (a *App) domainMenu(m *ui.Menu, host string) {
	key := "host:" + host
	if m.Item(map[bool]string{true: "Unpin", false: "Pin"}[a.pinned(key)]).Chosen() {
		a.togglePin(key)
	}
	if m.Item("Copy Domain").Chosen() {
		a.copy(host, "the domain")
	}
	m.Separator()
	if a.rules.Current().ShouldMITM(host) {
		m.Item("SSL Proxying Is On").Disabled(true)
	} else if m.Item("Enable SSL Proxying").Chosen() {
		a.enableSSL(host, false)
	}
	m.Submenu("Tools", func(m *ui.Menu) {
		probe := &flow.Flow{Request: &flow.Request{Scheme: "https", Host: host, FullPath: "https://" + host + "/*", Method: flow.Method{Name: "GET"}}}
		if m.Item("Map Remote…").Chosen() {
			a.mapRemoteFromFlow(probe)
		}
		if m.Item("Breakpoint…").Chosen() {
			a.breakpointFromFlow(probe)
		}
		if m.Item("Network Conditions…").Chosen() {
			a.throttleFromFlow(probe)
		}
		if m.Item("Block List").Chosen() {
			a.blockFromFlow(probe, false)
		}
	})
	m.Separator()
	if m.Item("Delete All from " + host).Chosen() {
		a.deleteMatching(func(f *flow.Flow) bool { return strings.EqualFold(f.Host(), host) })
	}
}

func countSaved(flows []*flow.Flow) int {
	n := 0
	for _, f := range flows {
		if f.Saved {
			n++
		}
	}
	return n
}

func (a *App) folderItem(c *ui.Context, f saved.Folder) {
	p := a.pal
	depth := float32(strings.Count(f.Path, "/"))
	b := ui.ButtonBase(c.Key("folder:"+f.Path)).Label("Open "+f.Path).Padding(5, 8, 5, 8+depth*14).Radius(6).FillWidth()
	if b.Hovered() {
		b.Background(p.hover)
	}
	b.Children(func() {
		ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, icon("folder")).FontSize(16).TextColor(p.accent)
			ui.Text(c, f.Name()).Grow(1).SingleLine()
			if f.Count > 0 {
				ui.Badge(c, fmt.Sprint(f.Count))
			}
		})
	})
	if b.Clicked() {
		a.openFolder(f.Path)
	}
	b.ContextMenu(func(m *ui.Menu) {
		if m.Item("Open in New Window").Chosen() {
			a.openFolder(f.Path)
		}
		if m.Item("Import into Session").Chosen() {
			a.importFolder(f.Path)
		}
		if m.Item("Export as HAR…").Chosen() {
			a.exportFolder(f.Path)
		}
		m.Separator()
		if m.Item("Rename…").Chosen() {
			a.folderSave = folderSheet{open: true, path: f.Path, rename: f.Path}
		}
		if m.Item("Delete " + f.Name() + "…").Chosen() {
			a.deleteFolder(f)
		}
	})
}
