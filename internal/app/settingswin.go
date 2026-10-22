package app

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/privileged"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
)

var settingsTabs = []string{"General", "Proxy", "HTTPS", "Tools", "Automation", "Advanced"}

type settingsDrafts struct {
	port       float64
	bypass     string
	access     string
	upBypass   string
	maxFlows   float64
	initDone   bool
	socksPort  float64
	pac        string
	accessFrom string
}

func (a *App) settingsWindow(c *ui.Context) {
	p := a.pal
	d := a.rules.Current()
	drafts := &a.drafts
	if !drafts.initDone {
		*drafts = settingsDrafts{
			initDone: true, port: float64(a.set.Port), maxFlows: float64(a.set.MaxFlows),
			bypass: strings.Join(d.Bypass, "\n"), access: strings.Join(d.Access.IPs, "\n"),
			upBypass: strings.Join(d.Upstream.Bypass, "\n"), socksPort: float64(d.Socks.Port), pac: d.Upstream.PACURL,
		}
	}
	ui.Row(c).FillWidth().Padding(14, 16, 6, 16).Justify(ui.Center).Children(func() {
		ui.Tabs(c, &a.settingsTab, settingsTabs...).Label("Settings")
	})
	ui.Divider(c)
	ui.Scroll(c.Key(settingsTabs[a.settingsTab])).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(18, 28).Gap(14).Children(func() {
			switch settingsTabs[a.settingsTab] {
			case "General":
				a.generalSettings(c, p)
			case "Proxy":
				a.proxySettings(c, p, d)
			case "HTTPS":
				a.httpsSettings(c, p, d)
			case "Tools":
				a.toolSettings(c, p, d)
			case "Automation":
				a.automationSettings(c, p)
			case "Advanced":
				a.advancedSettings(c, p)
			}
		})
	})
}

func group(c *ui.Context, p palette, title string, build func()) {
	ui.Column(c).FillWidth().Gap(8).Children(func() {
		ui.Text(c, title).FontWeight(650).TextColor(p.text)
		ui.Column(c).FillWidth().Padding(12, 14).Gap(10).Radius(8).Background(p.surface).Children(build)
	})
}

func (a *App) generalSettings(c *ui.Context, p palette) {
	drafts := &a.drafts
	group(c, p, "Proxy Port", func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.NumberInput(c, &drafts.port, 1024, 65535, 1).Width(120).Label("Port")
			if ui.Button(c, "Apply").Disabled(int(drafts.port) == a.proxy.Port()).Clicked() {
				port := int(drafts.port)
				addr, network := a.set.ListenAddr(port)
				if err := a.proxy.SetListen(addr, network); err != nil {
					a.toast("Port " + strconv.Itoa(port) + ": " + err.Error())
					_ = a.proxy.SetListen(a.set.ListenAddr(a.set.Port))
				} else {
					a.updateSettings(func(s *settings.Settings) { s.Port = port })
					a.proxyErr = ""
					a.toast("ProxyGo listens on port " + strconv.Itoa(port))
					if a.systemProxyOn() || a.overrode {
						a.setSystemProxy(true)
					}
				}
			}
			ui.Text(c, "Listening on "+a.proxyAddress()).TextColor(p.muted)
		})
	})
	group(c, p, "On Launch", func() {
		a.settingSwitch(c, "Override the macOS proxy", "And give it back on quit.", a.set.OverrideSystemProxy, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.OverrideSystemProxy = on })
		})
		a.settingSwitch(c, "Open the last session", "Keep the flows of the last run.", a.set.OpenLastSession, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.OpenLastSession = on })
		})
		a.settingSwitch(c, "Start with recording paused", "", a.set.StartPaused, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.StartPaused = on })
		})
	})
	group(c, p, "Window", func() {
		a.settingRow(c, "Appearance", "", func() {
			mode := map[string]int{settings.AppearanceSystem: 0, settings.AppearanceLight: 1, settings.AppearanceDark: 2}[a.set.Appearance]
			if ui.Segmented(c, &mode, "System", "Light", "Dark").Label("Appearance").Changed() {
				a.setAppearance([]string{settings.AppearanceSystem, settings.AppearanceLight, settings.AppearanceDark}[mode])
			}
		})
		a.settingSwitch(c, "Keep the window on top", "", a.set.StayOnTop, a.setStayOnTop)
		a.menuBarSettings(c)
	})
	group(c, p, "App Icon", func() {
		ui.Text(c, "Shown in the Dock and in Finder.").FontSize(11).TextColor(p.muted)
		a.appIconPicker(c, p)
	})
	group(c, p, "Flows", func() {
		a.settingSwitch(c, "Select new requests as they arrive", "Auto Select", a.set.AutoSelect, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.AutoSelect = on })
		})
		a.settingRow(c, "Keep at most", "The oldest flows go first.", func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				if ui.NumberInput(c, &drafts.maxFlows, 1000, 1_000_000, 1000).Width(110).Label("Most flows").Changed() {
					n := int(drafts.maxFlows)
					a.updateSettings(func(s *settings.Settings) { s.MaxFlows = n })
					a.store.SetLimit(n)
				}
				ui.Text(c, "flows").TextColor(p.text2)
			})
		})
		a.memorySettings(c, p)
	})
	a.updatesGroup(c, p)
}

func (a *App) appIconPicker(c *ui.Context, p palette) {
	choice := cmp.Or(a.set.AppIcon, appIcons[0].id)
	ui.RadioGroup(c, func() {
		for _, icon := range appIcons {
			r := ui.RadioBase(c.Key("app-icon-"+icon.id), &choice, icon.id).Label(icon.name).
				OnChange(func() { a.setAppIcon(choice) })
			r.Column().AlignItems(ui.Center).Gap(4).Padding(6, 8).Radius(12).Border(2, ui.Transparent)
			chosen := choice == icon.id
			switch {
			case chosen:
				r.BorderColor(p.accent).Background(p.bg)
			case r.Hovered():
				r.Background(p.hover)
			}
			r.Children(func() {
				ui.Image(c, a.appIconThumbnail(icon.id)).Size(56, 56)
				ui.Text(c, icon.name).FontSize(11).TextColor(map[bool]ui.Color{true: p.text, false: p.muted}[chosen])
			})
		}
	}).Label("App Icon").Row().Wrap().Gap(4)
}

func (a *App) settingSwitch(c *ui.Context, label, description string, on bool, set func(bool)) {
	a.settingRow(c, label, description, func() {
		v := on
		if ui.Switch(c, &v).Label(label).Changed() {
			set(v)
		}
	})
}

func (a *App) settingRow(c *ui.Context, label, description string, control func()) {
	p := a.pal
	ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Gap(1).Children(func() {
			ui.Text(c, label).TextColor(p.text)
			if description != "" {
				ui.Text(c, description).FontSize(11).TextColor(p.muted)
			}
		})
		control()
	})
}

func lines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(strings.ReplaceAll(s, ",", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (a *App) proxySettings(c *ui.Context, p palette, d *rules.Data) {
	drafts := &a.drafts
	a.listenSettings(c, p)
	group(c, p, "macOS Proxy", func() {
		on := a.systemProxyOn()
		a.settingSwitch(c, "Override the macOS proxy", "Send this Mac's HTTP and HTTPS traffic through ProxyGo.", on, a.setSystemProxy)
		installed := privileged.Installed()
		status := "Not installed: the first change to the macOS proxy installs it, after your password."
		if installed {
			status = "Installed: ProxyGo changes the macOS proxy without asking for your password."
		}
		a.settingRow(c, "Helper", status, func() {
			if installed && ui.Button(c, "Remove").Tooltip("Uninstall ProxyGo's helper; the next change asks for your password again").Clicked() {
				a.removeHelper()
			}
		})
		ui.Text(c, "Bypass the proxy for").TextColor(p.text2)
		ui.TextArea(c, &drafts.bypass).Height(70).Label("Bypassed hosts").Placeholder("localhost, *.local, 10.0.0.0/8")
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, "Apply Bypass List").Clicked() {
				list := lines(drafts.bypass)
				a.rules.Update(func(d *rules.Data) { d.Bypass = list })
				if on {
					a.setSystemProxy(true)
				}
			}
			if ui.Button(c, "Reset to Default").Clicked() {
				drafts.bypass = strings.Join(rules.DefaultBypass, "\n")
			}
		})
	})
	group(c, p, "SOCKS5 Proxy", func() {
		a.settingSwitch(c, "Listen for SOCKS5", "For apps that only speak SOCKS. Its traffic is recorded and decrypted like the HTTP proxy's.", d.Socks.Enabled, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.Socks.Enabled = on })
		})
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "Port").TextColor(p.text2)
			ui.NumberInput(c, &drafts.socksPort, 1024, 65535, 1).Width(120).Label("SOCKS port")
			if ui.Button(c, "Apply").Disabled(int(drafts.socksPort) == d.Socks.Port).Clicked() {
				port := int(drafts.socksPort)
				a.rules.Update(func(d *rules.Data) { d.Socks.Port = port })
			}
			if port := a.proxy.SocksPort(); port > 0 {
				ui.Text(c, fmt.Sprintf("Listening on %s:%d", a.proxyHost(), port)).TextColor(p.green)
			}
		})
	})
	group(c, p, "External Proxy", func() {
		up := d.Upstream
		a.settingSwitch(c, "Send ProxyGo's traffic through another proxy", "As a corporate proxy, or another debugging proxy.", up.Enabled, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.Upstream.Enabled = on })
		})
		field := func(label string, v string, set func(string)) {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, label).TextColor(p.text2).Width(110)
				val := v
				in := ui.TextInput(c.Key(label), &val).Placeholder("host:port, or http://user:pass@host:port").Label(label).Grow(1)
				if in.Changed() {
					set(val)
				}
			})
		}
		field("HTTP Proxy", up.HTTP, func(v string) { a.rules.Update(func(d *rules.Data) { d.Upstream.HTTP = strings.TrimSpace(v) }) })
		field("HTTPS Proxy", up.HTTPS, func(v string) { a.rules.Update(func(d *rules.Data) { d.Upstream.HTTPS = strings.TrimSpace(v) }) })
		a.pacField(c, p, d)
		ui.Text(c, "Connect directly to").TextColor(p.text2)
		ui.TextArea(c, &drafts.upBypass).Height(52).Label("External proxy bypass").Placeholder("*.internal, localhost")
		if ui.Button(c, "Apply").AlignSelf(ui.Start).Clicked() {
			list := lines(drafts.upBypass)
			a.rules.Update(func(d *rules.Data) { d.Upstream.Bypass = list })
		}
	})
	group(c, p, "Access Control", func() {
		modes := []string{rules.AccessAll, rules.AccessAsk, rules.AccessLocal, rules.AccessList}
		names := []string{"Any device", "Ask about each new device", "This Mac only", "This Mac and the devices listed"}
		choice := names[max(slices.Index(modes, d.Access.Mode), 0)]
		a.settingRow(c, "Who may connect", map[string]string{
			rules.AccessAsk: "ProxyGo asks before a device not listed uses it; those you allow join the list.",
		}[d.Access.Mode], func() {
			if ui.Select(c, &choice, names).Label("Who may connect").Width(250).Changed() {
				m := modes[slices.Index(names, choice)]
				a.rules.Update(func(d *rules.Data) { d.Access.Mode = m })
			}
		})
		if joined := strings.Join(d.Access.IPs, "\n"); joined != drafts.accessFrom {
			drafts.access, drafts.accessFrom = joined, joined
		}
		if d.Access.Mode == rules.AccessList || d.Access.Mode == rules.AccessAsk {
			ui.TextArea(c, &drafts.access).Height(64).Label("Allowed addresses").Placeholder("192.168.1.20\n10.0.0.0/24")
			if ui.Button(c, "Apply").AlignSelf(ui.Start).Clicked() {
				list := lines(drafts.access)
				a.rules.Update(func(d *rules.Data) { d.Access.IPs = list })
			}
		}
		if a.set.ListenLocalhost {
			ui.Text(c, "Only this Mac can connect while Listening › Only this Mac is on.").FontSize(11).TextColor(p.muted)
		} else {
			ui.Text(c, "Devices on your network connect to "+a.proxyAddress()+".").FontSize(11).TextColor(p.muted)
		}
	})
}

func (a *App) httpsSettings(c *ui.Context, p palette, d *rules.Data) {
	group(c, p, "Decryption", func() {
		a.settingSwitch(c, "SSL Proxying", "Decrypt the hosts on the SSL Proxying List.", d.SSL.Enabled, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.SSL.Enabled = on })
		})
		if ui.Button(c, "SSL Proxying List…").AlignSelf(ui.Start).Clicked() {
			a.openWindow("ssl")
		}
		a.settingSwitch(c, "HTTP/2", "Speak HTTP/2 with clients and servers that offer it.", !d.DisableHTTP2, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.DisableHTTP2 = !on })
		})
		a.settingSwitch(c, "Accept any server certificate", "Connect to servers with self-signed or expired certificates. Not safe on networks you do not trust.", d.InsecureTLS, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.InsecureTLS = on })
		})
	})
	group(c, p, "TLS Key Logging", func() {
		path := filepath.Join(a.dir, "sslkeylog.txt")
		a.settingSwitch(c, "Write TLS secrets to a key log", "Wireshark reads it to decrypt captured packets (SSLKEYLOGFILE format).", d.KeyLogPath != "", func(on bool) {
			a.rules.Update(func(d *rules.Data) {
				d.KeyLogPath = ""
				if on {
					d.KeyLogPath = path
				}
			})
		})
		if d.KeyLogPath != "" {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, d.KeyLogPath).FontSize(11).TextColor(p.text2).Selectable().Grow(1)
				if ui.Button(c, "Reveal").Clicked() {
					revealInFinder(d.KeyLogPath)
				}
			})
		}
	})
	group(c, p, "Certificates", func() {
		a.certificateButtons(c, d)
		a.leafSettings(c, p, d)
	})
	group(c, p, "Caching", func() {
		a.settingSwitch(c, "No Caching", "Strip conditional request headers and mark responses uncacheable, so every request reaches the server.", d.NoCaching, a.setNoCaching)
	})
}

func (a *App) toolSettings(c *ui.Context, p palette, d *rules.Data) {
	group(c, p, "Diagnostics", func() {
		a.settingSwitch(c, "Diagnostic headers", "Add X-ProxyGo-* headers to the responses a tool changed, naming the tool and its rule, for the client to see.", d.DiagnosticHeaders, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.DiagnosticHeaders = on })
		})
	})
	group(c, p, "Tools", func() {
		ui.Text(c, "Switch a tool off to stop all its rules at once, keeping them.").FontSize(11).TextColor(p.muted)
		for _, t := range rules.AllTools {
			ui.Row(c.Key(t.ID)).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Text(c, t.Name).Grow(1)
				if ui.Button(c, "Rules…").Clicked() {
					a.openWindow(t.ID)
				}
				on := d.ToolOn(t.ID)
				if ui.Switch(c, &on).Label(t.Name).Changed() {
					a.setTool(t.ID, on)
				}
			})
		}
	})
}

func (a *App) advancedSettings(c *ui.Context, p palette) {
	group(c, p, "Rules and Settings", func() {
		ui.Text(c, "Back up every tool's rules and the proxy settings to a file, or restore them.").TextColor(p.text2)
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, "Export…").Clicked() {
				a.exportRules()
			}
			if ui.Button(c, "Import…").Clicked() {
				a.importRules()
			}
		})
	})
	group(c, p, "Data", func() {
		ui.Text(c, a.dir).FontSize(11).TextColor(p.text2).Selectable()
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, "Open Data Folder").Clicked() {
				openPath(a.dir)
			}
			if ui.Button(c, "Clear Recent Sessions").Clicked() {
				a.updateSettings(func(s *settings.Settings) { s.RecentSessions = nil })
				a.refreshRecentMenu()
			}
			if ui.Button(c, "Reset Network Proxy").Tooltip("Turn the macOS proxy off").Clicked() {
				a.resetSystemProxy()
			}
		})
	})
}

var certTabs = []string{"This Mac", "iOS Device", "iOS Simulator", "Android", "Android Emulator", "Other"}

func (a *App) certificateWindow(c *ui.Context) {
	p := a.pal
	a.windowHeader(c, "Certificate", "Devices and apps must trust ProxyGo's root certificate before they accept decrypted HTTPS.", nil)
	if a.certs == nil {
		emptyState(c, p, a.proxyErr)
		return
	}
	a.rootImportView(c)
	ui.Row(c).FillWidth().Padding(0, windowInset, 12, windowInset).Children(func() {
		ui.Column(c).Grow(1).Padding(14).Gap(8).Radius(8).Background(p.surface).Children(func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				glyph(c, "certificate", 22, p.accent)
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, a.certs.CommonName()).FontWeight(650)
					ui.Text(c, "Expires "+a.certs.NotAfter().Format("2 January 2006")).FontSize(11).TextColor(p.muted)
				})
				if a.certTrusted {
					ui.Text(c, "Trusted on this Mac").FontSize(11).FontWeight(650).TextColor(p.green).Background(p.greenSoft).Padding(2, 8).Radius(5)
				} else {
					ui.Text(c, "Not trusted on this Mac").FontSize(11).FontWeight(650).TextColor(p.yellow).Background(p.yellowSoft).Padding(2, 8).Radius(5)
				}
			})
			ui.Text(c, "SHA-256 "+a.certs.Fingerprint()).FontSize(10.5).TextColor(p.muted).Selectable().Wrap()
			ui.Row(c).Gap(8).Children(func() {
				if !a.certTrusted {
					if ui.PrimaryButton(c, "Install on this Mac…").Clicked() {
						a.installCertificate()
					}
				} else if ui.Button(c, "Remove from this Mac").Clicked() {
					a.uninstallCertificate()
				}
				ui.MenuButton(c, "Export", func(m *ui.Menu) {
					for _, f := range [][2]string{{"pem", "Root Certificate as PEM…"}, {"der", "Root Certificate as DER…"}, {"p12", "Root Certificate as P12…"}, {"key", "Private Key…"}} {
						if m.Item(f[1]).Chosen() {
							a.exportCertificate(f[0])
						}
					}
				})
				if ui.Button(c, "Reveal in Finder").Clicked() {
					revealInFinder(a.certs.CertPath())
				}
				ui.MenuButton(c, "More", func(m *ui.Menu) {
					if m.Item("Use Your Own Root Certificate…").Chosen() {
						a.rootImport = rootImport{open: true}
					}
					if m.Item("Custom Server Certificates…").Chosen() {
						a.openWindow("servercerts")
					}
					if m.Item("Automatic Setup…").Chosen() {
						a.openWindow("setup")
					}
					m.Separator()
					if m.Item("Reset Certificate…").Chosen() {
						a.regenerateCertificate()
					}
				})
				if ui.Button(c, "Check Again").Clicked() {
					a.checkTrust()
				}
			})
		})
	})
	ui.Row(c).FillWidth().Padding(0, windowInset, 8, windowInset).Children(func() {
		ui.Tabs(c, &a.certTab, certTabs...).Label("Platform")
	})
	ui.Scroll(c.Key(certTabs[a.certTab])).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(4, 22, 18, 22).Gap(8).Children(func() {
			step := func(n int, text string) {
				ui.Row(c).Gap(10).Children(func() {
					ui.Text(c, strconv.Itoa(n)).FontWeight(700).TextColor(p.accent).Width(16)
					ui.Text(c, text).TextColor(p.text2).Wrap().Grow(1).Selectable()
				})
			}
			addr := a.proxyAddress()
			if tab := certTabs[a.certTab]; a.set.ListenLocalhost && (tab == "iOS Device" || tab == "Android") {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					glyph(c, "warning", 12, p.yellow)
					ui.Text(c, "ProxyGo takes only this Mac's connections: turn off Only this Mac in Settings › Proxy for a device to connect.").TextColor(p.yellow).Wrap().Grow(1)
				})
			}
			switch certTabs[a.certTab] {
			case "This Mac":
				step(1, "Choose Install on this Mac above. macOS asks for your password, then trusts the certificate for TLS.")
				step(2, "Turn on Tools › Override macOS Proxy, or point an app at "+addr+".")
				step(3, "Add the hosts to decrypt in Tools › SSL Proxying List. Firefox keeps its own store: import the PEM in its Settings › Certificates.")
			case "iOS Device":
				step(1, "On the iPhone, open Settings › Wi-Fi › your network › Configure Proxy › Manual: Server "+primaryIP()+", Port "+strconv.Itoa(a.proxy.Port())+".")
				step(2, "In Safari, open http://proxy.go and download the certificate; allow the profile.")
				step(3, "Settings › General › VPN & Device Management: install the ProxyGo profile.")
				step(4, "Settings › General › About › Certificate Trust Settings: turn on full trust for ProxyGo.")
			case "iOS Simulator":
				step(1, "Boot the simulator, then run:")
				code(c, p, "xcrun simctl keychain booted add-root-cert '"+a.certs.CertPath()+"'")
				if ui.Button(c, "Copy Command").AlignSelf(ui.Start).Clicked() {
					a.copy("xcrun simctl keychain booted add-root-cert '"+a.certs.CertPath()+"'", "the command")
				}
				step(2, "The simulator uses the Mac's proxy: turn on Override macOS Proxy.")
				a.simulatorInstall(c)
			case "Android":
				step(1, "Settings › Wi-Fi › your network › Proxy › Manual: host "+primaryIP()+", port "+strconv.Itoa(a.proxy.Port())+".")
				step(2, "In Chrome, open http://proxy.go and tap Download for Android (CRT).")
				step(3, "Settings › Security › Encryption & credentials › Install a certificate › CA certificate.")
				step(4, "Apps targeting Android 7+ trust user certificates only with a network security config:")
				code(c, p, "<network-security-config>\n  <debug-overrides>\n    <trust-anchors>\n      <certificates src=\"user\" />\n    </trust-anchors>\n  </debug-overrides>\n</network-security-config>")
				a.androidInstall(c, false)
			case "Android Emulator":
				step(1, "Start the emulator with ProxyGo as its proxy:")
				code(c, p, "emulator -avd <name> -http-proxy http://127.0.0.1:"+strconv.Itoa(a.proxy.Port()))
				step(2, "Push the certificate and install it from Settings › Security:")
				code(c, p, "adb push '"+a.certs.CertPath()+"' /sdcard/Download/proxygo-ca.pem")
				a.androidInstall(c, true)
			case "Other":
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "Automatic Setup opens a terminal, a browser or an Electron app already set up.").TextColor(p.text2).Grow(1).Wrap()
					if ui.Button(c, "Automatic Setup…").Clicked() {
						a.openWindow("setup")
					}
				})
				a.firefoxTrust(c)
				a.javaInstall(c)
				ui.Text(c, "Tools that ignore the macOS keychain read the PEM file:").TextColor(p.text2).Margin(8, 0, 0, 0)
				pem := a.certs.CertPath()
				for _, r := range [][2]string{
					{"Node.js", "export NODE_EXTRA_CA_CERTS='" + pem + "'\nexport HTTPS_PROXY=http://127.0.0.1:" + strconv.Itoa(a.proxy.Port())},
					{"Python (requests)", "export REQUESTS_CA_BUNDLE='" + pem + "'\nexport HTTPS_PROXY=http://127.0.0.1:" + strconv.Itoa(a.proxy.Port())},
					{"Ruby", "export SSL_CERT_FILE='" + pem + "'\nexport HTTPS_PROXY=http://127.0.0.1:" + strconv.Itoa(a.proxy.Port())},
					{"cURL", "curl --proxy http://127.0.0.1:" + strconv.Itoa(a.proxy.Port()) + " --cacert '" + pem + "' https://example.com"},
					{"Go", "SSL_CERT_FILE='" + pem + "' HTTPS_PROXY=http://127.0.0.1:" + strconv.Itoa(a.proxy.Port()) + " go run ."},
					{"Java", "keytool -importcert -alias proxygo -keystore \"$JAVA_HOME/lib/security/cacerts\" -file '" + pem + "'"},
					{"Docker", "docker run -e HTTPS_PROXY=http://host.docker.internal:" + strconv.Itoa(a.proxy.Port()) + " -v '" + pem + "':/proxygo.pem -e SSL_CERT_FILE=/proxygo.pem …"},
				} {
					ui.Text(c, r[0]).FontWeight(650).Margin(6, 0, 0, 0)
					code(c, p, r[1])
				}
			}
		})
	})
}

func code(c *ui.Context, p palette, text string) {
	ui.Text(c, text).Font("Menlo").FontSize(11).TextColor(p.text).Background(p.surface).Padding(8, 10).Radius(6).Selectable().Wrap().FillWidth()
}
