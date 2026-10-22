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
)

const cliLink = "/usr/local/bin/" + cli.Name

func (a *App) automationSettings(c *ui.Context, p palette) {
	if a.automationErr != "" {
		ui.Text(c, a.automationErr).FontSize(11).TextColor(p.red).Wrap()
	}
	group(c, p, "MCP Server", func() {
		ui.Text(c, "Let AI assistants on this Mac, as Claude Code or Claude Desktop, read the flows and add rules, through the Model Context Protocol.").FontSize(11).TextColor(p.muted).Wrap()
		status := "Off: assistants cannot connect."
		switch running := a.mcp != nil && a.mcp.Running(); {
		case a.set.MCP && running:
			status = "Running: connect a client below."
		case a.set.MCP:
			status = "Not running: see the message above."
		}
		a.settingSwitch(c, "Serve MCP", status, a.set.MCP, func(on bool) {
			_ = a.setMCP(on)
		})
		a.settingSwitch(c, "Serve at a loopback URL too", "For clients that connect over HTTP rather than start a command. Each launch picks a port and a token.", a.set.MCPHTTP, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.MCPHTTP = on })
			if a.set.MCP {
				_ = a.setMCP(true)
			}
		})
		if u := a.mcpURL(); u != "" {
			a.settingRow(c, "URL", u, func() {
				if ui.Button(c, "Copy").Clicked() {
					a.copy(u, "the URL")
				}
			})
		}
		a.settingSwitch(c, "Show credentials to assistants", "Authorization headers, cookies, tokens and passwords go as they are. Off, ProxyGo redacts them.", a.set.MCPShowSecrets, func(on bool) {
			a.updateSettings(func(s *settings.Settings) { s.MCPShowSecrets = on })
		})
		a.settingRow(c, "Connect a client", "The command for Claude Code, and the JSON for other clients.", func() {
			if ui.Button(c, "Copy Configuration").Clicked() {
				a.copy(cli.MCPConfig(), "the configuration")
			}
		})
	})
	group(c, p, "Command-Line Tool", func() {
		ui.Text(c, "proxygo-cli records, exports, toggles tools and adds rules from a terminal or a script, talking to ProxyGo while it runs.").FontSize(11).TextColor(p.muted).Wrap()
		status, installed := cliStatus()
		a.settingRow(c, cli.Name, status, func() {
			label := map[bool]string{true: "Reinstall", false: "Install"}[installed]
			if ui.Button(c, label).Tooltip("Link " + cliLink + " to this ProxyGo; macOS may ask for your password").Clicked() {
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
		return "Install from ProxyGo.app: this copy runs outside an app.", false
	}
	target, err := os.Readlink(cliLink)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "Not installed.", false
	case err != nil:
		return cliLink + " is not ProxyGo's link: Install replaces only a link.", false
	case target != exe:
		return cliLink + " runs another copy, " + target + ".", false
	}
	return "Installed at " + cliLink + ".", true
}

func (a *App) installCLI() {
	go func() {
		err := linkCLI()
		a.do(func() {
			if err != nil {
				a.toast("Command-line tool: " + err.Error())
				return
			}
			a.toast("Installed " + cliLink)
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
	group(c, p, "Listening", func() {
		apply := func(fn func(*settings.Settings)) {
			before := a.set
			a.updateSettings(fn)
			addr, network := a.set.ListenAddr(a.proxy.Port())
			if err := a.proxy.SetListen(addr, network); err != nil {
				a.toast("Cannot listen there: " + err.Error())
				a.updateSettings(func(s *settings.Settings) {
					s.ListenLocalhost, s.ListenIPv4Only = before.ListenLocalhost, before.ListenIPv4Only
				})
				_ = a.proxy.SetListen(a.set.ListenAddr(a.proxy.Port()))
			}
		}
		a.settingSwitch(c, "Only this Mac", "Listen on 127.0.0.1: phones and other computers cannot connect.", a.set.ListenLocalhost, func(on bool) {
			apply(func(s *settings.Settings) { s.ListenLocalhost = on })
		})
		a.settingSwitch(c, "IPv4 only", "Leave IPv6 out, for networks where it misbehaves.", a.set.ListenIPv4Only, func(on bool) {
			apply(func(s *settings.Settings) { s.ListenIPv4Only = on })
		})
	})
}

func (a *App) pacField(c *ui.Context, p palette, d *rules.Data) {
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "PAC URL").TextColor(p.text2).Width(110)
		in := ui.TextInput(c.Key("pac"), &a.drafts.pac).Placeholder("http://wpad/wpad.dat, or file:///path/proxy.pac").Label("PAC URL").Grow(1)
		pac := strings.TrimSpace(a.drafts.pac)
		apply := ui.Button(c, "Apply").Disabled(pac == d.Upstream.PACURL).Clicked()
		if (in.Submitted() || apply) && pac != d.Upstream.PACURL {
			if pac != "" {
				if u, err := url.Parse(pac); err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "file") {
					a.toast("A PAC URL starts with http://, https:// or file://")
					return
				}
			}
			a.rules.Update(func(d *rules.Data) { d.Upstream.PACURL = pac })
		}
	})
	ui.Text(c, "A proxy auto-config script chooses the proxy for each request, before the HTTP and HTTPS proxies above.").FontSize(11).TextColor(p.muted).Wrap()
}

func (a *App) leafSettings(c *ui.Context, p palette, d *rules.Data) {
	days := float64(int(d.LeafValidity().Hours() / 24))
	a.settingRow(c, "Host certificates last", "Apple platforms refuse server certificates of more than 398 days.", func() {
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			if ui.NumberInput(c, &days, 1, rules.DefaultLeafDays, 1).Width(120).Label("Days").Changed() {
				n := int(days)
				a.rules.Update(func(d *rules.Data) { d.LeafValidityDays = n })
			}
			ui.Text(c, "days").TextColor(p.text2)
		})
	})
}

func (a *App) certificateButtons(c *ui.Context, d *rules.Data) {
	ui.Row(c).Gap(8).Wrap().Children(func() {
		if ui.Button(c, "ProxyGo Certificate…").Clicked() {
			a.openWindow("certificate")
		}
		if ui.Button(c, fmt.Sprintf("Client Certificates (%d)…", len(d.ClientCerts))).Clicked() {
			a.openWindow("clientcerts")
		}
		if ui.Button(c, fmt.Sprintf("Server Certificates (%d)…", len(d.ServerCerts))).Clicked() {
			a.openWindow("servercerts")
		}
		if ui.Button(c, "Use Your Own Root…").Clicked() {
			a.rootImport = rootImport{open: true}
			a.certTab = 0
			a.openWindow("certificate")
		}
	})
	if a.certs != nil {
		ui.Text(c, "Signing with "+a.certs.CommonName()+", SHA-256 "+shorten(a.certs.Fingerprint(), 23)).FontSize(11).TextColor(a.pal.muted).SingleLine()
	}
}

func (a *App) memorySettings(c *ui.Context, p palette) {
	mb := float64(a.set.MemoryLimitMB)
	a.settingRow(c, "Keep messages under", "Past it, the oldest flows not saved go. 0 keeps every flow, up to the count above.", func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			if ui.NumberInput(c, &mb, 0, 65536, 128).Width(110).Label("Memory limit in megabytes").Changed() {
				n := int(mb)
				a.updateSettings(func(s *settings.Settings) { s.MemoryLimitMB = n })
				a.store.SetMemoryLimit(int64(n) << 20)
			}
			ui.Text(c, "MB").TextColor(p.text2)
		})
	})
}
