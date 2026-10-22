package privileged

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"proxygo/internal/systemproxy"
)

func TestDaemonPlist(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("plutil is macOS only")
	}
	path := filepath.Join(t.TempDir(), "helper.plist")
	if err := os.WriteFile(path, []byte(daemonPlist("com.example.proxygo.helper", "/Library/PrivilegedHelperTools/com.example.proxygo.helper", 501)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil { // #nosec G204 -- plutil, given the plist the test wrote.
		t.Fatalf("plutil -lint: %v\n%s", err, out)
	}
	out, err := exec.Command("plutil", "-extract", "ProgramArguments", "json", "-o", "-", path).Output() // #nosec G204 -- plutil, given the plist the test wrote.
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(out)), `["\/Library\/PrivilegedHelperTools\/com.example.proxygo.helper","privileged-helper","com.example.proxygo.helper","501"]`; got != want {
		t.Fatalf("ProgramArguments = %s, want %s", got, want)
	}
}

func TestHandleRefusesRemoteProxies(t *testing.T) {
	s := &server{label: "test"}
	for _, cfg := range []systemproxy.Config{
		{Host: "evil.example", Port: 8080},
		{Host: "10.0.0.1", Port: 8080},
		{Host: "127.0.0.1", Port: 0},
		{Host: "127.0.0.1", Port: 70000},
		{Host: "127.0.0.1", Port: 9090, SOCKSPort: -1},
	} {
		if err := s.handle(Request{Op: "enable", Config: cfg}, peer{}); err == nil {
			t.Errorf("enable %+v: want an error", cfg)
		}
	}
	if err := s.handle(Request{Op: "run", Config: systemproxy.Config{}}, peer{}); err == nil {
		t.Error("unknown op: want an error")
	}
	if err := s.handle(Request{Op: "link-cli"}, peer{path: "/tmp/proxygo"}); err == nil {
		t.Error("link-cli outside an app: want an error")
	}
}

func TestPeerIsThisProcess(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("code signing checks are macOS only")
	}
	self, err := ownCDHash()
	if err != nil {
		t.Skip(err)
	}
	dir, err := os.MkdirTemp("/tmp", "pg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan peer, 1)
	errs := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer func() { _ = c.Close() }()
		p, err := peerOf(c.(*net.UnixConn))
		if err != nil {
			errs <- err
			return
		}
		got <- p
	}()
	c, err := net.Dial("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	select {
	case err := <-errs:
		t.Fatal(err)
	case p := <-got:
		if p.uid != os.Getuid() {
			t.Errorf("uid = %d, want %d", p.uid, os.Getuid())
		}
		if !bytes.Equal(p.cdhash, self) {
			t.Errorf("cdhash = %x, want %x", p.cdhash, self)
		}
		exe, _ := executable()
		if p.path != exe {
			t.Errorf("path = %q, want %q", p.path, exe)
		}
	}
}

func TestWatchRestoresProxyWhenAppDies(t *testing.T) {
	var mu sync.Mutex
	alive, restored := true, make(chan systemproxy.State, 1)
	cfg := systemproxy.Config{Host: "127.0.0.1", Port: 9090}
	before := systemproxy.State{HTTP: true, Host: "corp.example", Port: 3128}
	s := &server{
		every:   5 * time.Millisecond,
		alive:   func(int) bool { mu.Lock(); defer mu.Unlock(); return alive },
		status:  func() systemproxy.State { return systemproxy.State{HTTP: true, Host: "127.0.0.1", Port: 9090} },
		restore: func(st systemproxy.State) error { restored <- st; return nil },
	}
	s.mu.Lock()
	s.watch(42, cfg, before)
	s.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if len(restored) != 0 {
		t.Fatal("restored while the app runs")
	}
	mu.Lock()
	alive = false
	mu.Unlock()
	select {
	case st := <-restored:
		if st.Host != before.Host || st.Port != before.Port {
			t.Fatalf("restored %+v", st)
		}
	case <-time.After(time.Second):
		t.Fatal("not restored after the app died")
	}

	s.mu.Lock()
	s.watch(43, cfg, before)
	s.watched = nil
	s.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if len(restored) != 0 {
		t.Fatal("restored after the app gave the proxy back itself")
	}
}

func TestAppBundle(t *testing.T) {
	for exe, want := range map[string]string{
		"/Applications/ProxyGo.app/Contents/MacOS/ProxyGo":         "/Applications/ProxyGo.app",
		"/Users/me/build/ProxyGo-debug.app/Contents/MacOS/ProxyGo": "/Users/me/build/ProxyGo-debug.app",
		"/Users/me/go/bin/proxygo":                                 "",
		"/tmp/x/Contents/MacOS/ProxyGo":                            "",
	} {
		if got := appBundle(exe); got != want {
			t.Errorf("appBundle(%q) = %q, want %q", exe, got, want)
		}
	}
}

func TestInstallCommandsCopyTheWholeApp(t *testing.T) {
	label := "com.example.proxygo.helper"
	script := strings.Join(installCommands(label, "/Applications/ProxyGo.app/Contents/MacOS/ProxyGo", 501), " && ")
	program := "/Library/PrivilegedHelperTools/com.example.proxygo.helper.app/Contents/MacOS/ProxyGo"
	for _, want := range []string{
		"/usr/bin/ditto --noextattr --noqtn '/Applications/ProxyGo.app' '/Library/PrivilegedHelperTools/com.example.proxygo.helper.app.new'",
		"<string>" + program + "</string>",
		"/bin/rm -f '/Library/PrivilegedHelperTools/com.example.proxygo.helper'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "/bin/cp -X") {
		t.Errorf("an app's executable is copied without its bundle:\n%s", script)
	}
	lone := strings.Join(installCommands(label, "/Users/me/go/bin/proxygo", 501), " && ")
	if !strings.Contains(lone, "<string>/Library/PrivilegedHelperTools/com.example.proxygo.helper</string>") {
		t.Errorf("a bare executable is not installed on its own:\n%s", lone)
	}
}
