package app

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/cli"
	"proxygo/internal/privileged"
	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/locales"
)

const cliLink = "/usr/local/bin/" + cli.Name

func (a *App) automationSettings(c *ui.Context, p palette) {
	if a.automationErr != "" {
		ui.Text(c, a.automationErr).FontSize(11).TextColor(p.red).Wrap()
	}
	group(c, p, locales.MCPServer(), func() {
		ui.Text(c, locales.LetAIAssistantsOnThisMac()).FontSize(11).TextColor(p.muted).Wrap()
		status := locales.OffAssistantsCannotConnect()
		switch running := a.mcp != nil && a.mcp.Running(); {
		case a.set.MCP && running:
			status = locales.RunningConnectAClientBelow()
		case a.set.MCP:
			status = locales.NotRunningSeeTheMessageAbove()
		}
		a.settingSwitch(c, locales.ServeMCP(), status, a.set.MCP, func(on bool) {
			_ = a.setMCP(on)
		})
		a.settingSwitch(c, locales.ServeAtALoopbackURLToo(), locales.ForClientsThatConnectOverHTTP(), a.set.MCPHTTP, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.MCPHTTP = on })
			if a.set.MCP {
				_ = a.setMCP(true)
			}
		})
		if u := a.mcpURL(); u != "" {
			a.settingRow(c, locales.URL(), u, func() {
				if ui.Button(c, locales.Copy()).Clicked() {
					a.copy(u, locales.CopiedTheURL())
				}
			})
		}
		a.settingSwitch(c, locales.ShowCredentialsToAssistants(), locales.AuthorizationHeadersCookiesTokensAndPasswords(), a.set.MCPShowSecrets, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.MCPShowSecrets = on })
		})
		a.settingRow(c, locales.ConnectAClient(), locales.TheCommandForClaudeCodeAnd(), func() {
			if ui.Button(c, locales.CopyConfiguration()).Clicked() {
				a.copy(cli.MCPConfig(), locales.CopiedTheConfiguration())
			}
		})
	})
	group(c, p, locales.CommandLineTool(), func() {
		ui.Text(c, locales.ProxyGoCLIRecordsExportsTogglesTools()).FontSize(11).TextColor(p.muted).Wrap()
		status, installed := cliStatus()
		a.settingRow(c, cli.Name, status, func() {
			label := map[bool]string{true: locales.Reinstall(), false: locales.Install()}[installed]
			if ui.Button(c, label).Tooltip(locales.LinkToThisProxyGo(cliLink)).Clicked() {
				a.installCLI()
			}
		})
		code(c, p, cli.Name+" status\n"+cli.Name+" export-log --format har --output session.har\n"+cli.Name+" help")
	})
}

func (a *App) mcpURL() string {
	if a.mcp == nil {
		return ""
	}
	return a.mcp.URL()
}

func cliStatus() (string, bool) {
	exe, err := cliTarget()
	if err != nil {
		return locales.InstallFromProxyGoAppThisCopy(), false
	}
	target, err := os.Readlink(cliLink)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return locales.NotInstalled(), false
	case err != nil:
		return locales.IsNotProxyGosLink(cliLink), false
	case target != exe:
		return locales.RunsAnotherCopy(cliLink, target), false
	}
	return locales.InstalledAt(cliLink), true
}

func (a *App) installCLI() {
	go func() {
		err := linkCLI()
		a.do(func() {
			if err != nil {
				a.toast(locales.CommandLineToolError(err.Error()))
				return
			}
			a.toast(locales.InstalledName(cliLink))
		})
	}()
}

func linkCLI() error {
	exe, err := cliTarget()
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(cliLink); err == nil && fi.Mode()&fs.ModeSymlink == 0 {
		return fmt.Errorf("%s is a file, not a link: remove it first", cliLink)
	}
	tmp := cliLink + ".proxygo-new"
	_ = os.Remove(tmp)
	if err := os.Symlink(exe, tmp); err == nil {
		if err := os.Rename(tmp, cliLink); err == nil {
			return nil
		}
		_ = os.Remove(tmp)
	}
	return privileged.LinkCLI()
}

func (a *App) listenSettings(c *ui.Context, p palette) {
	group(c, p, locales.Listening(), func() {
		apply := func(fn func(*settings.Settings)) {
			before := a.set
			a.updateSettings(fn)
			addr, network := a.set.ListenAddr(a.proxy.Port())
			if err := a.proxy.SetListen(addr, network); err != nil {
				a.toast(locales.CannotListenThere(err.Error()))
				a.updateSettings(func(s *settings.Settings) {
					s.ListenLocalhost, s.ListenIPv4Only = before.ListenLocalhost, before.ListenIPv4Only
				})
				_ = a.proxy.SetListen(a.set.ListenAddr(a.proxy.Port()))
			}
		}
		a.settingSwitch(c, locales.OnlyThisMac(), locales.ListenOn127001(), a.set.ListenLocalhost, func(on bool) {
			apply(func(s *settings.Settings) { s.ListenLocalhost = on })
		})
		a.settingSwitch(c, locales.Ipv4Only(), locales.LeaveIPv6OutForNetworksWhere(), a.set.ListenIPv4Only, func(on bool) {
			apply(func(s *settings.Settings) { s.ListenIPv4Only = on })
		})
	})
}

func (a *App) pacField(c *ui.Context, p palette, d *rules.Data) {
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, locales.PACURL()).TextColor(p.text2).Width(110)
		in := ui.TextInput(c.Key("pac"), &a.drafts.pac).Placeholder(locales.HTTPWpadWpadDatOrFile()).Label(locales.PACURL()).Grow(1)
		pac := strings.TrimSpace(a.drafts.pac)
		apply := ui.Button(c, locales.Apply()).Disabled(pac == d.Upstream.PACURL).Clicked()
		if (in.Submitted() || apply) && pac != d.Upstream.PACURL {
			if pac != "" {
				if u, err := url.Parse(pac); err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "file") {
					a.toast(locales.APACURLStartsWithHTTP())
					return
				}
			}
			a.rules.Update(func(d *rules.Data) { d.Upstream.PACURL = pac })
		}
	})
	ui.Text(c, locales.AProxyAutoConfigScriptChooses()).FontSize(11).TextColor(p.muted).Wrap()
}

func (a *App) leafSettings(c *ui.Context, p palette, d *rules.Data) {
	days := float64(int(d.LeafValidity().Hours() / 24))
	a.settingRow(c, locales.HostCertificatesLast(), locales.ApplePlatformsRefuseServerCertificatesOf(), func() {
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			if ui.NumberInput(c, &days, 1, rules.DefaultLeafDays, 1).Width(120).Label(locales.Days()).Changed() {
				n := int(days)
				a.rules.Update(func(d *rules.Data) { d.LeafValidityDays = n })
			}
			ui.Text(c, locales.DaysUnit()).TextColor(p.text2)
		})
	})
}

func (a *App) certificateButtons(c *ui.Context, d *rules.Data) {
	ui.Row(c).Gap(8).Wrap().Children(func() {
		if ui.Button(c, locales.ProxyGoCertificateEllipsis()).Clicked() {
			a.openWindow("certificate")
		}
		if ui.Button(c, locales.ClientCertificatesCount(len(d.ClientCerts))).Clicked() {
			a.openWindow("clientcerts")
		}
		if ui.Button(c, locales.ServerCertificatesCount(len(d.ServerCerts))).Clicked() {
			a.openWindow("servercerts")
		}
		if ui.Button(c, locales.UseYourOwnRootEllipsis()).Clicked() {
			a.rootImport = rootImport{open: true}
			a.certTab = 0
			a.openWindow("certificate")
		}
	})
	if a.certs != nil {
		ui.Text(c, locales.SigningWith(a.certs.CommonName(), shorten(a.certs.Fingerprint(), 23))).FontSize(11).TextColor(a.pal.muted).SingleLine()
	}
}

func (a *App) memorySettings(c *ui.Context, p palette) {
	mb := float64(a.set.MemoryLimitMB)
	a.settingRow(c, locales.KeepMessagesUnder(), locales.PastItTheOldestFlowsNot(), func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			if ui.NumberInput(c, &mb, 0, 65536, 128).Width(110).Label(locales.MemoryLimitInMegabytes()).Changed() {
				n := int(mb)
				a.updateSettings(func(s *settings.Settings) { s.MemoryLimitMB = n })
				a.store.SetMemoryLimit(int64(n) << 20)
			}
			ui.Text(c, "MB").TextColor(p.text2)
		})
	})
}
