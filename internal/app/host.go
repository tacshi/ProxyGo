package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxygo/internal/certs"
	"proxygo/internal/control"
	"proxygo/internal/flow"
	"proxygo/internal/mcp"
	"proxygo/internal/privileged"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/session"
	"proxygo/internal/settings"
	"proxygo/internal/store"
	"proxygo/internal/systemproxy"
)

var _ control.Host = (*App)(nil)

var Version = "0.1.0"

func (a *App) call(fn func()) {
	if a.win == nil {
		fn()
		return
	}
	done := make(chan struct{})
	a.do(func() {
		defer close(done)
		fn()
	})
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
}

func (a *App) Store() *store.Store   { return a.store }
func (a *App) Rules() *rules.Store   { return a.rules }
func (a *App) Proxy() *proxy.Server  { return a.proxy }
func (a *App) Certs() *certs.Manager { return a.certs }
func (a *App) Version() string       { return Version }

func (a *App) ProxyAddress() (string, int) {
	if a.localOnly.Load() {
		return "127.0.0.1", a.proxy.Port()
	}
	return primaryIP(), a.proxy.Port()
}

func (a *App) Recording() bool { return !a.proxyPaused.Load() }

func (a *App) SetRecording(on bool) { a.call(func() { a.setPaused(!on) }) }

func (a *App) SystemProxy() bool {
	var on bool
	a.call(func() { on = a.systemProxyOn() })
	return on
}

func (a *App) SetSystemProxy(on bool) error { return a.applySystemProxy(on, false) }

func (a *App) ClearSession() { a.call(a.clearFlows) }

func (a *App) Selected() []*flow.Flow {
	var out []*flow.Flow
	a.call(func() { out = a.chosenFlows() })
	return out
}

func (a *App) MCP() bool { return a.mcpOn.Load() }

func (a *App) SetMCP(on bool) error {
	var err error
	a.call(func() { err = a.setMCP(on) })
	return err
}

var windowNames = map[string]string{
	"breakpoint": "breakpoint", "maplocal": "maplocal", "map-local": "maplocal", "map-remote": "mapremote",
	"scripting": "scripting", "block-list": "block", "allow-list": "allow", "reverse-proxy": "reverse",
	"network-condition": "network", "dns-spoofing": "dns", "ssl-proxying": "ssl", "compose": "compose",
	"certificate": "certificate", "settings": "settings", "setup": "setup", "protobuf": "protobuf",
	"breakpoint-templates": "bptemplates", "blocked-apps": "blockedapps", "custom-certificates": "servercerts",
	"client-certificates": "clientcerts", "diff": "diff",
}

func (a *App) Open(window string) error {
	tab := -1
	if w, t, ok := strings.Cut(window, ":"); ok {
		window = w
		tab = map[string]int{"general": 0, "proxy": 1, "https": 2, "tools": 3, "automation": 4, "advanced": 5}[t]
	}
	if window == "no-caching" {
		window, tab = "settings", 2
	}
	kind, ok := windowNames[window]
	if !ok {
		return fmt.Errorf("no window %q", window)
	}
	a.call(func() {
		if tab >= 0 && kind == "settings" {
			a.settingsTab = tab
		}
		a.openWindow(kind)
		if a.win != nil {
			a.win.Show()
		}
	})
	return nil
}

func (a *App) Export(path, format string, flows []*flow.Flow) error {
	var icons map[string]string
	a.call(func() { icons = a.iconStrings() })
	return session.Export(path, format, flows, icons)
}

func (a *App) startServers() {
	srv, err := control.Serve(a, control.SocketPath(a.dir))
	if err != nil {
		a.automationErr = "Command-line tool: " + err.Error()
	} else {
		a.control = srv
	}
	a.mcp = mcp.New(a, a.dir)
	a.mcp.Redact = func() bool { return !a.mcpShowSecrets.Load() }
	a.syncAtomics()
	if a.set.MCP {
		if err := a.mcp.Start(a.set.MCPHTTP); err != nil {
			a.automationErr = "MCP: " + err.Error()
		}
	}
}

func (a *App) stopServers() {
	if a.control != nil {
		a.control.Close()
	}
	if a.mcp != nil {
		a.mcp.Stop()
	}
}

func (a *App) setMCP(on bool) error {
	a.updateSettings(func(s *settings.Settings) { s.MCP = on })
	if a.mcp == nil {
		return nil
	}
	a.mcp.Stop()
	a.automationErr = ""
	if !on {
		return nil
	}
	if err := a.mcp.Start(a.set.MCPHTTP); err != nil {
		a.automationErr = "MCP: " + err.Error()
		return err
	}
	return nil
}

func (a *App) syncAtomics() {
	a.mcpOn.Store(a.set.MCP)
	a.mcpShowSecrets.Store(a.set.MCPShowSecrets)
	a.localOnly.Store(a.set.ListenLocalhost)
}

func (a *App) proxyStatePath() string { return filepath.Join(a.dir, "system-proxy.json") }

func (a *App) applySystemProxy(on, reset bool) error {
	var cfg systemproxy.Config
	var first bool
	var before systemproxy.State
	a.call(func() {
		cfg = systemproxy.Config{Host: "127.0.0.1", Port: a.proxy.Port(), Bypass: a.rules.Current().Bypass}
		if s := a.proxy.SocksPort(); s > 0 {
			cfg.SOCKSPort = s
		}
		first, before = on && !a.overrode, a.sysBefore
	})
	var err error
	var prev systemproxy.State
	switch {
	case on:
		prev = systemproxy.Status()
		err = privileged.EnableProxy(cfg)
	case reset:
		err = privileged.DisableProxy()
	default:
		err = privileged.RestoreProxy(before)
	}
	st := systemproxy.Status()
	a.call(func() {
		a.sys, a.sysKnown = st, true
		if first && err == nil {
			a.sysBefore = prev
			if a.isProxyGo(prev) {
				a.sysBefore = systemproxy.State{}
			}
		}
		switch {
		case errors.Is(err, privileged.ErrCanceled):
		case err != nil:
			a.toast("System proxy: " + err.Error())
		case on:
			a.overrode = true
			_ = systemproxy.Save(a.proxyStatePath(), systemproxy.Saved{Before: a.sysBefore, Host: cfg.Host, Port: cfg.Port})
			a.toast("macOS now uses ProxyGo as its proxy")
		default:
			a.overrode = false
			systemproxy.Forget(a.proxyStatePath())
			a.toast("macOS no longer uses ProxyGo")
		}
	})
	return err
}

func (a *App) recoverSystemProxy() {
	saved, ok := systemproxy.Load(a.proxyStatePath())
	if !ok {
		return
	}
	st := systemproxy.Status()
	if !st.PointsAt(saved.Host, saved.Port) && !st.PointsAt("127.0.0.1", saved.Port) {
		systemproxy.Forget(a.proxyStatePath())
		return
	}
	a.do(func() {
		a.sys, a.sysKnown = st, true
		if a.set.OverrideSystemProxy {
			a.sysBefore, a.overrode = saved.Before, true
			return
		}
		a.sysBefore, a.overrode = saved.Before, true
		go func() {
			if err := a.applySystemProxy(false, false); err == nil {
				a.do(func() { a.toast("Gave macOS back the proxy ProxyGo had when it last quit unexpectedly") })
			}
		}()
	})
}

var errNoCLI = errors.New("ProxyGo's executable is not in an app")

func cliTarget() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if !strings.Contains(exe, ".app/") {
		return exe, errNoCLI
	}
	return exe, nil
}
