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
	"proxygo/locales"
)

var settingsTabs = []string{"General", "Proxy", "HTTPS", "Tools", "Automation", "Advanced"}

type settingsDrafts struct {
	port       float64
	bypass     string
	access     string
	upBypass   string
	upEditing  string
	maxFlows   float64
	initDone   bool
	socksPort  float64
	pac        string
	accessFrom string
}

func settingsTabLabels() []string {
	return []string{locales.General(), locales.Proxy(), locales.HTTPS(), locales.Tools(), locales.Automation(), locales.Advanced()}
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
		ui.Tabs(c, &a.settingsTab, settingsTabLabels()...).Label(locales.Settings())
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
	group(c, p, locales.ProxyPort(), func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.NumberInput(c, &drafts.port, 1024, 65535, 1).Width(120).Label(locales.Port())
			if ui.Button(c, locales.Apply()).Disabled(int(drafts.port) == a.proxy.Port()).Clicked() {
				port := int(drafts.port)
				addr, network := a.set.ListenAddr(port)
				if err := a.proxy.SetListen(addr, network); err != nil {
					a.toast(locales.PortError(strconv.Itoa(port), err.Error()))
					_ = a.proxy.SetListen(a.set.ListenAddr(a.set.Port))
				} else {
					a.updateSettings(func(s *settings.Settings) { s.Port = port })
					a.proxyErr = ""
					a.toast(locales.ListensOnPort(strconv.Itoa(port)))
					if a.systemProxyOn() || a.overrode {
						a.setSystemProxy(true)
					}
				}
			}
			ui.Text(c, locales.ListeningOn(a.proxyAddress())).TextColor(p.muted)
		})
	})
	group(c, p, locales.OnLaunch(), func() {
		a.settingSwitch(c, locales.OverrideTheMacOSProxy(), locales.AndGiveItBackOnQuit(), a.set.OverrideSystemProxy, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.OverrideSystemProxy = on })
		})
		a.settingSwitch(c, locales.OpenTheLastSession(), locales.KeepTheFlowsOfTheLast(), a.set.OpenLastSession, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.OpenLastSession = on })
		})
		a.settingSwitch(c, locales.StartWithRecordingPaused(), "", a.set.StartPaused, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.StartPaused = on })
		})
	})
	group(c, p, locales.Window(), func() {
		a.settingRow(c, locales.Appearance(), "", func() {
			mode := map[string]int{settings.AppearanceSystem: 0, settings.AppearanceLight: 1, settings.AppearanceDark: 2}[a.set.Appearance]
			if ui.Segmented(c, &mode, locales.System(), locales.Light(), locales.Dark()).Label(locales.Appearance()).Changed() {
				a.setAppearance([]string{settings.AppearanceSystem, settings.AppearanceLight, settings.AppearanceDark}[mode])
			}
		})
		a.languageSetting(c)
		a.settingSwitch(c, locales.KeepTheWindowOnTop(), "", a.set.StayOnTop, a.setStayOnTop)
		a.menuBarSettings(c)
	})
	group(c, p, locales.AppIcon(), func() {
		ui.Text(c, locales.ShownInTheDockAndIn()).FontSize(11).TextColor(p.muted)
		a.appIconPicker(c, p)
	})
	group(c, p, locales.Flows(), func() {
		a.settingSwitch(c, locales.SelectNewRequestsAsTheyArrive(), locales.AutoSelect(), a.set.AutoSelect, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.AutoSelect = on })
		})
		a.settingRow(c, locales.KeepAtMost(), locales.TheOldestFlowsGoFirst(), func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				if ui.NumberInput(c, &drafts.maxFlows, 1000, 1_000_000, 1000).Width(110).Label(locales.MostFlows()).Changed() {
					n := int(drafts.maxFlows)
					a.updateSettings(func(s *settings.Settings) { s.MaxFlows = n })
					a.store.SetLimit(n)
				}
				ui.Text(c, locales.FlowsUnit()).TextColor(p.text2)
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
			r := ui.RadioBase(c.Key("app-icon-"+icon.id), &choice, icon.id).Label(appIconName(icon.id, icon.name)).
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
				ui.Text(c, appIconName(icon.id, icon.name)).FontSize(11).TextColor(map[bool]ui.Color{true: p.text, false: p.muted}[chosen])
			})
		}
	}).Label(locales.AppIcon()).Row().Wrap().Gap(4)
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
	group(c, p, locales.MacOSProxy(), func() {
		on := a.systemProxyOn()
		a.settingSwitch(c, locales.OverrideTheMacOSProxy(), locales.SendThisMacsHTTPAndHTTPS(), on, a.setSystemProxy)
		installed := privileged.Installed()
		status := locales.NotInstalledTheFirstChangeTo()
		if installed {
			status = locales.InstalledProxyGoChangesTheMacOSProxy()
		}
		a.settingRow(c, locales.Helper(), status, func() {
			if installed && ui.Button(c, locales.Remove()).Tooltip(locales.UninstallProxyGosHelperTheNextChange()).Clicked() {
				a.removeHelper()
			}
		})
		ui.Text(c, locales.BypassTheProxyFor()).TextColor(p.text2)
		ui.TextArea(c, &drafts.bypass).Height(70).Label(locales.BypassedHosts()).Placeholder("localhost, *.local, 10.0.0.0/8")
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, locales.ApplyBypassList()).Clicked() {
				list := lines(drafts.bypass)
				a.rules.Update(func(d *rules.Data) { d.Bypass = list })
				if on {
					a.setSystemProxy(true)
				}
			}
			if ui.Button(c, locales.ResetToDefault()).Clicked() {
				drafts.bypass = strings.Join(rules.DefaultBypass, "\n")
			}
		})
	})
	group(c, p, locales.SOCKS5Proxy(), func() {
		a.settingSwitch(c, locales.ListenForSOCKS5(), locales.ForAppsThatOnlySpeakSOCKS(), d.Socks.Enabled, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.Socks.Enabled = on })
		})
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, locales.Port()).TextColor(p.text2)
			ui.NumberInput(c, &drafts.socksPort, 1024, 65535, 1).Width(120).Label(locales.SOCKSPort())
			if ui.Button(c, locales.Apply()).Disabled(int(drafts.socksPort) == d.Socks.Port).Clicked() {
				port := int(drafts.socksPort)
				a.rules.Update(func(d *rules.Data) { d.Socks.Port = port })
			}
			if port := a.proxy.SocksPort(); port > 0 {
				ui.Text(c, locales.ListeningOn(fmt.Sprintf("%s:%d", a.proxyHost(), port))).TextColor(p.green)
			}
		})
	})
	group(c, p, locales.ExternalProxy(), func() {
		up := d.Upstream
		a.settingSwitch(c, locales.SendProxyGosTrafficThroughAnotherProxy(), locales.AsACorporateProxyOrAnother(), up.Enabled, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.Upstream.Enabled = on })
		})
		field := func(label string, v string, set func(string)) {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, label).TextColor(p.text2).Width(110)
				editing := drafts.upEditing == label
				val := v
				if !editing {
					val = rules.MaskProxyPassword(v)
				}
				in := ui.TextInput(c.Key(label), &val).Placeholder(locales.UpstreamProxyPlaceholder()).Label(label).Grow(1)
				if in.Changed() {
					set(rules.UnmaskProxyPassword(val, v))
				}
				switch {
				case in.Focused() && !editing:
					drafts.upEditing = label
					a.invalidate()
				case !in.Focused() && editing:
					drafts.upEditing = ""
					a.invalidate()
				}
			})
		}
		field(locales.HTTPProxy(), up.HTTP, func(v string) { a.rules.Update(func(d *rules.Data) { d.Upstream.HTTP = strings.TrimSpace(v) }) })
		field(locales.HTTPSProxy(), up.HTTPS, func(v string) { a.rules.Update(func(d *rules.Data) { d.Upstream.HTTPS = strings.TrimSpace(v) }) })
		a.pacField(c, p, d)
		ui.Text(c, locales.ConnectDirectlyTo()).TextColor(p.text2)
		ui.TextArea(c, &drafts.upBypass).Height(52).Label(locales.ExternalProxyBypass()).Placeholder("*.internal, localhost")
		if ui.Button(c, locales.Apply()).AlignSelf(ui.Start).Clicked() {
			list := lines(drafts.upBypass)
			a.rules.Update(func(d *rules.Data) { d.Upstream.Bypass = list })
		}
	})
	group(c, p, locales.AccessControl(), func() {
		modes := []string{rules.AccessAll, rules.AccessAsk, rules.AccessLocal, rules.AccessList}
		names := []string{locales.AnyDevice(), locales.AskAboutEachNewDevice(), locales.ThisMacOnly(), locales.ThisMacAndTheDevicesListed()}
		choice := names[max(slices.Index(modes, d.Access.Mode), 0)]
		a.settingRow(c, locales.WhoMayConnect(), map[string]string{
			rules.AccessAsk: locales.ProxyGoAsksBeforeADeviceNot(),
		}[d.Access.Mode], func() {
			if ui.Select(c, &choice, names).Label(locales.WhoMayConnect()).Width(250).Changed() {
				m := modes[slices.Index(names, choice)]
				a.rules.Update(func(d *rules.Data) { d.Access.Mode = m })
			}
		})
		if joined := strings.Join(d.Access.IPs, "\n"); joined != drafts.accessFrom {
			drafts.access, drafts.accessFrom = joined, joined
		}
		if d.Access.Mode == rules.AccessList || d.Access.Mode == rules.AccessAsk {
			ui.TextArea(c, &drafts.access).Height(64).Label(locales.AllowedAddresses()).Placeholder("192.168.1.20\n10.0.0.0/24")
			if ui.Button(c, locales.Apply()).AlignSelf(ui.Start).Clicked() {
				list := lines(drafts.access)
				a.rules.Update(func(d *rules.Data) { d.Access.IPs = list })
			}
		}
		if a.set.ListenLocalhost {
			ui.Text(c, locales.OnlyThisMacCanConnectWhile()).FontSize(11).TextColor(p.muted)
		} else {
			ui.Text(c, locales.DevicesConnectTo(a.proxyAddress())).FontSize(11).TextColor(p.muted)
		}
	})
}

func (a *App) httpsSettings(c *ui.Context, p palette, d *rules.Data) {
	group(c, p, locales.Decryption(), func() {
		a.settingSwitch(c, locales.SSLProxying(), locales.DecryptTheHostsOnTheSSL(), d.SSL.Enabled, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.SSL.Enabled = on })
		})
		if ui.Button(c, locales.SSLProxyingListEllipsis()).AlignSelf(ui.Start).Clicked() {
			a.openWindow("ssl")
		}
		a.settingSwitch(c, "HTTP/2", locales.SpeakHTTP2WithClientsAnd(), !d.DisableHTTP2, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.DisableHTTP2 = !on })
		})
		a.settingSwitch(c, locales.AcceptAnyServerCertificate(), locales.ConnectToServersWithSelfSigned(), d.InsecureTLS, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.InsecureTLS = on })
		})
	})
	group(c, p, locales.TLSKeyLogging(), func() {
		path := filepath.Join(a.dir, "sslkeylog.txt")
		a.settingSwitch(c, locales.WriteTLSSecretsToAKey(), locales.WiresharkReadsItToDecryptCaptured(), d.KeyLogPath != "", func(on bool) {
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
				if ui.Button(c, locales.Reveal()).Clicked() {
					revealInFinder(d.KeyLogPath)
				}
			})
		}
	})
	group(c, p, locales.Certificates(), func() {
		a.certificateButtons(c, d)
		a.leafSettings(c, p, d)
	})
	group(c, p, locales.Caching(), func() {
		a.settingSwitch(c, locales.NoCaching(), locales.StripConditionalRequestHeadersAndMark(), d.NoCaching, a.setNoCaching)
	})
}

func (a *App) toolSettings(c *ui.Context, p palette, d *rules.Data) {
	group(c, p, locales.Diagnostics(), func() {
		a.settingSwitch(c, locales.DiagnosticHeaders(), locales.AddXProxyGoHeadersToThe(), d.DiagnosticHeaders, func(on bool) {
			a.rules.Update(func(d *rules.Data) { d.DiagnosticHeaders = on })
		})
	})
	group(c, p, locales.Tools(), func() {
		ui.Text(c, locales.SwitchAToolOffToStop()).FontSize(11).TextColor(p.muted)
		for _, t := range rules.AllTools {
			ui.Row(c.Key(t.ID)).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Text(c, toolName(t.ID)).Grow(1)
				if ui.Button(c, locales.RulesEllipsis()).Clicked() {
					a.openWindow(t.ID)
				}
				on := d.ToolOn(t.ID)
				if ui.Switch(c, &on).Label(toolName(t.ID)).Changed() {
					a.setTool(t.ID, on)
				}
			})
		}
	})
}

func (a *App) advancedSettings(c *ui.Context, p palette) {
	group(c, p, locales.RulesAndSettings(), func() {
		ui.Text(c, locales.BackUpEveryToolsRulesAnd()).TextColor(p.text2)
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, locales.ExportEllipsis()).Clicked() {
				a.exportRules()
			}
			if ui.Button(c, locales.ImportEllipsis()).Clicked() {
				a.importRules()
			}
		})
	})
	group(c, p, locales.Data(), func() {
		ui.Text(c, a.dir).FontSize(11).TextColor(p.text2).Selectable()
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, locales.OpenDataFolder()).Clicked() {
				openPath(a.dir)
			}
			if ui.Button(c, locales.ClearRecentSessions()).Clicked() {
				a.updateSettings(func(s *settings.Settings) { s.RecentSessions = nil })
				a.refreshRecentMenu()
			}
			if ui.Button(c, locales.ResetNetworkProxy()).Tooltip(locales.TurnTheMacOSProxyOff()).Clicked() {
				a.resetSystemProxy()
			}
		})
	})
}

var certTabs = []string{"This Mac", "iOS Device", "iOS Simulator", "Android", "Android Emulator", "Other"}

func certTabLabels() []string {
	return []string{locales.ThisMac(), locales.IOSDevice(), locales.IOSSimulator(), locales.Android(), locales.AndroidEmulator(), locales.Other()}
}

func (a *App) certificateWindow(c *ui.Context) {
	p := a.pal
	a.windowHeader(c, locales.Certificate(), locales.DevicesAndAppsMustTrustProxyGos(), nil)
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
					ui.Text(c, locales.CertificateExpires(a.certs.NotAfter())).FontSize(11).TextColor(p.muted)
				})
				if a.certTrusted {
					ui.Text(c, locales.TrustedOnThisMac()).FontSize(11).FontWeight(650).TextColor(p.green).Background(p.greenSoft).Padding(2, 8).Radius(5)
				} else {
					ui.Text(c, locales.NotTrustedOnThisMac()).FontSize(11).FontWeight(650).TextColor(p.yellow).Background(p.yellowSoft).Padding(2, 8).Radius(5)
				}
			})
			ui.Text(c, "SHA-256 "+a.certs.Fingerprint()).FontSize(10.5).TextColor(p.muted).Selectable().Wrap()
			ui.Row(c).Gap(8).Children(func() {
				if !a.certTrusted {
					if ui.PrimaryButton(c, locales.InstallOnThisMacEllipsis()).Clicked() {
						a.installCertificate()
					}
				} else if ui.Button(c, locales.RemoveFromThisMac()).Clicked() {
					a.uninstallCertificate()
				}
				ui.MenuButton(c, locales.Export(), func(m *ui.Menu) {
					for _, f := range [][2]string{{"pem", locales.RootCertificateAsPEMEllipsis()}, {"der", locales.RootCertificateAsDEREllipsis()}, {"p12", locales.RootCertificateAsP12Ellipsis()}, {"key", locales.PrivateKeyEllipsis()}} {
						if m.Item(f[1]).Chosen() {
							a.exportCertificate(f[0])
						}
					}
				})
				if ui.Button(c, locales.RevealInFinder()).Clicked() {
					revealInFinder(a.certs.CertPath())
				}
				ui.MenuButton(c, locales.More(), func(m *ui.Menu) {
					if m.Item(locales.UseYourOwnRootCertificateEllipsis()).Chosen() {
						a.rootImport = rootImport{open: true}
					}
					if m.Item(locales.CustomServerCertificatesEllipsis()).Chosen() {
						a.openWindow("servercerts")
					}
					if m.Item(locales.AutomaticSetupEllipsis()).Chosen() {
						a.openWindow("setup")
					}
					m.Separator()
					if m.Item(locales.ResetCertificateEllipsis()).Chosen() {
						a.regenerateCertificate()
					}
				})
				if ui.Button(c, locales.CheckAgain()).Clicked() {
					a.checkTrust()
				}
			})
		})
	})
	ui.Row(c).FillWidth().Padding(0, windowInset, 8, windowInset).Children(func() {
		ui.Tabs(c, &a.certTab, certTabLabels()...).Label(locales.Platform())
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
					ui.Text(c, locales.ProxyGoTakesOnlyThisMacsConnections()).TextColor(p.yellow).Wrap().Grow(1)
				})
			}
			switch certTabs[a.certTab] {
			case "This Mac":
				step(1, locales.CertMacStep1())
				step(2, locales.CertMacStep2(addr))
				step(3, locales.CertMacStep3())
			case "iOS Device":
				step(1, locales.CertIOSStep1(primaryIP(), strconv.Itoa(a.proxy.Port())))
				step(2, locales.CertIOSStep2())
				step(3, locales.CertIOSStep3())
				step(4, locales.CertIOSStep4())
			case "iOS Simulator":
				step(1, locales.BootTheSimulatorThenRun())
				code(c, p, "xcrun simctl keychain booted add-root-cert '"+a.certs.CertPath()+"'")
				if ui.Button(c, locales.CopyCommand()).AlignSelf(ui.Start).Clicked() {
					a.copy("xcrun simctl keychain booted add-root-cert '"+a.certs.CertPath()+"'", locales.CopiedTheCommand())
				}
				step(2, locales.TheSimulatorUsesTheMacsProxy())
				a.simulatorInstall(c)
			case "Android":
				step(1, locales.CertAndroidStep1(primaryIP(), strconv.Itoa(a.proxy.Port())))
				step(2, locales.CertAndroidStep2())
				step(3, locales.CertAndroidStep3())
				step(4, locales.CertAndroidStep4())
				code(c, p, "<network-security-config>\n  <debug-overrides>\n    <trust-anchors>\n      <certificates src=\"user\" />\n    </trust-anchors>\n  </debug-overrides>\n</network-security-config>")
				a.androidInstall(c, false)
			case "Android Emulator":
				step(1, locales.StartTheEmulatorWithProxyGoAs())
				code(c, p, "emulator -avd <name> -http-proxy http://127.0.0.1:"+strconv.Itoa(a.proxy.Port()))
				step(2, locales.PushTheCertificateAndInstallIt())
				code(c, p, "adb push '"+a.certs.CertPath()+"' /sdcard/Download/proxygo-ca.pem")
				a.androidInstall(c, true)
			case "Other":
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, locales.AutomaticSetupOpensATerminalA()).TextColor(p.text2).Grow(1).Wrap()
					if ui.Button(c, locales.AutomaticSetupEllipsis()).Clicked() {
						a.openWindow("setup")
					}
				})
				a.firefoxTrust(c)
				a.javaInstall(c)
				ui.Text(c, locales.ToolsThatIgnoreTheMacOSKeychain()).TextColor(p.text2).Margin(8, 0, 0, 0)
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
