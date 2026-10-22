package autosetup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func config(t *testing.T) Config {
	return Config{Proxy: "http://127.0.0.1:9090", CA: "/ca/proxygo-ca.pem", Bundle: "/ca/bundle.pem", Dir: t.TempDir()}
}

func TestShell(t *testing.T) {
	c := config(t)
	sh := Shell(c, false)
	for _, want := range []string{"export HTTPS_PROXY='http://127.0.0.1:9090'\n", "export NODE_EXTRA_CA_CERTS='/ca/proxygo-ca.pem'\n", "export SSL_CERT_FILE='/ca/bundle.pem'\n"} {
		if !strings.Contains(sh, want) {
			t.Errorf("missing %q in\n%s", want, sh)
		}
	}
	if !strings.Contains(Shell(c, true), "set -gx HTTP_PROXY 'http://127.0.0.1:9090'\n") {
		t.Error("fish")
	}
	out, err := exec.Command("sh", "-c", Shell(c, false)+"echo $https_proxy $REQUESTS_CA_BUNDLE; "+Unset(c)+"echo [$HTTP_PROXY]").Output() // #nosec G204 -- the test runs the shell snippet it checks.
	if err != nil || string(out) != "http://127.0.0.1:9090 /ca/bundle.pem\n[]\n" {
		t.Errorf("%q %v", out, err)
	}
}

func TestOpeners(t *testing.T) {
	var ran [][]string
	orig := Run
	defer func() { Run = orig }()
	Run = func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	c := config(t)
	if err := OpenTerminal(c, "iTerm"); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(c.Dir, "ProxyGo Terminal.command")
	b, _ := os.ReadFile(script) // #nosec G304 -- a file of the test's directory.
	if fi, _ := os.Stat(script); fi.Mode()&0o100 == 0 || !strings.HasPrefix(string(b), "#!/bin/sh\n") || !strings.Contains(string(b), "exec \"${SHELL:-/bin/zsh}\" -l") {
		t.Errorf("script:\n%s", b)
	}
	if strings.Join(ran[0], " ") != "open -a iTerm "+script {
		t.Errorf("%q", ran[0])
	}
	if err := OpenBrowser(c, Browsers[0]); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ran[1], " "); !strings.Contains(got, "open -na Google Chrome --args --user-data-dir="+filepath.Join(c.Dir, "Browsers", "Google Chrome")) || !strings.Contains(got, "--proxy-server=http://127.0.0.1:9090") {
		t.Errorf("%q", got)
	}
	if err := OpenFirefox(c, "127.0.0.1", 9090); err != nil {
		t.Fatal(err)
	}
	prefs, _ := os.ReadFile(filepath.Join(c.Dir, "Browsers", "Firefox", "user.js"))
	if !strings.Contains(string(prefs), `user_pref("network.proxy.ssl_port", 9090);`) {
		t.Errorf("prefs %s", prefs)
	}
	app := filepath.Join(t.TempDir(), "Chat.app")
	if err := OpenElectron(c, app); err == nil {
		t.Error("not an Electron app")
	}
	_ = os.MkdirAll(filepath.Join(app, "Contents", "Frameworks", "Electron Framework.framework"), 0o750)
	if err := OpenElectron(c, app); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ran[3], " "); !strings.Contains(got, "--env NODE_EXTRA_CA_CERTS=/ca/proxygo-ca.pem") || !strings.HasSuffix(got, "--args --proxy-server=http://127.0.0.1:9090 --proxy-bypass-list=<-loopback>") {
		t.Errorf("%q", got)
	}
}
