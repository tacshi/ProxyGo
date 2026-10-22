package autosetup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Config struct {
	Proxy      string
	CA, Bundle string
	Dir        string
}

func Env(c Config) map[string]string {
	bundle := c.Bundle
	if bundle == "" {
		bundle = c.CA
	}
	return map[string]string{
		"HTTP_PROXY": c.Proxy, "HTTPS_PROXY": c.Proxy, "ALL_PROXY": c.Proxy,
		"http_proxy": c.Proxy, "https_proxy": c.Proxy, "all_proxy": c.Proxy,
		"NODE_USE_ENV_PROXY":  "1",
		"NODE_EXTRA_CA_CERTS": c.CA,
		"SSL_CERT_FILE":       bundle, "REQUESTS_CA_BUNDLE": bundle, "CURL_CA_BUNDLE": bundle,
		"GIT_SSL_CAINFO": bundle, "AWS_CA_BUNDLE": bundle, "DENO_CERT": bundle, "PIP_CERT": bundle,
		"PROXYGO": "1",
	}
}

func Shell(c Config, fish bool) string {
	env := Env(c)
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if fish {
			fmt.Fprintf(&b, "set -gx %s %s\n", k, quote(env[k]))
		} else {
			fmt.Fprintf(&b, "export %s=%s\n", k, quote(env[k]))
		}
	}
	return b.String()
}

func Unset(c Config) string {
	keys := make([]string, 0)
	for k := range Env(c) {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "unset " + strings.Join(keys, " ") + "\n"
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

var Terminals = []string{"Terminal", "iTerm"}

var Run = func(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func OpenTerminal(c Config, terminal string) error {
	if terminal == "" {
		terminal = "Terminal"
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(c.Dir, "ProxyGo Terminal.command")
	script := "#!/bin/sh\n# Opened by ProxyGo: this shell's tools go through ProxyGo.\n" + Shell(c, false) +
		"clear\necho 'This shell sends its traffic through ProxyGo at " + strings.ReplaceAll(c.Proxy, "'", "") + ".'\n" +
		"exec \"${SHELL:-/bin/zsh}\" -l\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return err
	}
	return Run("open", "-a", terminal, path)
}

type Browser struct {
	Name, App string
}

var Browsers = []Browser{
	{"Google Chrome", "Google Chrome"},
	{"Microsoft Edge", "Microsoft Edge"},
	{"Brave", "Brave Browser"},
	{"Chromium", "Chromium"},
	{"Arc", "Arc"},
}

func Installed(app string) bool {
	home, _ := os.UserHomeDir()
	for _, dir := range []string{"/Applications", filepath.Join(home, "Applications")} {
		if _, err := os.Stat(filepath.Join(dir, app+".app")); err == nil {
			return true
		}
	}
	return false
}

func ChromiumArgs(c Config, profile string) []string {
	return []string{
		"--user-data-dir=" + profile,
		"--proxy-server=" + c.Proxy,
		"--proxy-bypass-list=<-loopback>",
		"--no-first-run", "--no-default-browser-check",
	}
}

func OpenBrowser(c Config, b Browser) error {
	profile := filepath.Join(c.Dir, "Browsers", b.Name)
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return err
	}
	return Run("open", append([]string{"-na", b.App, "--args"}, ChromiumArgs(c, profile)...)...)
}

func FirefoxPrefs(host string, port int) string {
	return fmt.Sprintf(`// Written by ProxyGo.
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", %q);
user_pref("network.proxy.http_port", %d);
user_pref("network.proxy.ssl", %q);
user_pref("network.proxy.ssl_port", %d);
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.allow_hijacking_localhost", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("security.enterprise_roots.enabled", true);
user_pref("browser.shell.checkDefaultBrowser", false);
`, host, port, host, port)
}

func OpenFirefox(c Config, host string, port int) error {
	profile := filepath.Join(c.Dir, "Browsers", "Firefox")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(profile, "user.js"), []byte(FirefoxPrefs(host, port)), 0o600); err != nil {
		return err
	}
	return Run("open", "-na", "Firefox", "--args", "-profile", profile, "-no-remote")
}

func ElectronArgs(c Config) (env []string, args []string) {
	env = []string{"NODE_EXTRA_CA_CERTS=" + c.CA, "NODE_USE_ENV_PROXY=1", "HTTPS_PROXY=" + c.Proxy, "HTTP_PROXY=" + c.Proxy}
	args = []string{"--proxy-server=" + c.Proxy, "--proxy-bypass-list=<-loopback>"}
	return env, args
}

func IsElectron(app string) bool {
	_, err := os.Stat(filepath.Join(app, "Contents", "Frameworks", "Electron Framework.framework"))
	return err == nil
}

func OpenElectron(c Config, app string) error {
	if !IsElectron(app) {
		return fmt.Errorf("%s is not an Electron app", filepath.Base(app))
	}
	env, args := ElectronArgs(c)
	cmd := []string{"-na", app}
	for _, e := range env {
		cmd = append(cmd, "--env", e)
	}
	cmd = append(cmd, "--args")
	return Run("open", append(cmd, args...)...)
}
