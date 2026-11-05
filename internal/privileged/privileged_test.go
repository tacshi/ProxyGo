package privileged

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
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
	if err := os.WriteFile(path, []byte(daemonPlist("app.capyvibe.proxygo.helper", "/Library/PrivilegedHelperTools/app.capyvibe.proxygo.helper", 501)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil { // #nosec G204 -- plutil, given the plist the test wrote.
		t.Fatalf("plutil -lint: %v\n%s", err, out)
	}
	out, err := exec.Command("plutil", "-extract", "ProgramArguments", "json", "-o", "-", path).Output() // #nosec G204 -- plutil, given the plist the test wrote.
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(out)), `["\/Library\/PrivilegedHelperTools\/app.capyvibe.proxygo.helper","privileged-helper","app.capyvibe.proxygo.helper","501"]`; got != want {
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

type fakeSystem struct {
	mu       sync.Mutex
	alive    bool
	services systemproxy.Snapshot
	reads    int
	readErr  error
	restored chan systemproxy.Snapshot
}

func newFakeSystem(services systemproxy.Snapshot) *fakeSystem {
	return &fakeSystem{alive: true, services: services, restored: make(chan systemproxy.Snapshot, 4)}
}

func (f *fakeSystem) status() systemproxy.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.services["Wi-Fi"]
	return systemproxy.State{HTTP: w.Web.On, HTTPS: w.Secure.On, Host: w.Web.Host, Port: w.Web.Port}
}

func (f *fakeSystem) server(t *testing.T) *server {
	return &server{
		label: "test",
		path:  filepath.Join(t.TempDir(), "proxy.json"),
		every: 5 * time.Millisecond,
		sys: system{
			alive:  func(int) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.alive },
			status: f.status,
			read: func() (systemproxy.Snapshot, error) {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.reads++
				return maps.Clone(f.services), f.readErr
			},
			enable: func(cfg systemproxy.Config) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				proxy := systemproxy.Endpoint{On: true, Host: cfg.Host, Port: cfg.Port}
				for name := range f.services {
					f.services[name] = systemproxy.Service{Web: proxy, Secure: proxy, Bypass: cfg.Bypass}
				}
				return nil
			},
			disable: func() error { return nil },
			restore: func(b systemproxy.Snapshot) error {
				f.mu.Lock()
				f.services = maps.Clone(b)
				f.mu.Unlock()
				f.restored <- b
				return nil
			},
		},
	}
}

func corpServices() systemproxy.Snapshot {
	corp := systemproxy.Endpoint{On: true, Host: "corp.example", Port: 3128}
	local := systemproxy.Endpoint{On: true, Host: "127.0.0.1", Port: 7890}
	return systemproxy.Snapshot{
		"Wi-Fi": {Web: corp, Secure: corp},
		"Surge": {Web: local, Secure: local, SOCKS: local, Bypass: []string{"*.local", "127.*"}},
		"LAN":   {Web: systemproxy.Endpoint{Host: "127.0.0.1", Port: 7890}},
	}
}

func sameServices(t *testing.T, got, want systemproxy.Snapshot) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if !bytes.Equal(g, w) {
		t.Fatalf("restored\n %s\nwant\n %s", g, w)
	}
}

func TestWatchRestoresProxyWhenAppDies(t *testing.T) {
	f := newFakeSystem(corpServices())
	s := f.server(t)
	s.mu.Lock()
	err := s.handle(Request{Op: "enable", Config: systemproxy.Config{Host: "127.0.0.1", Port: 9090}}, peer{pid: 42})
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if len(f.restored) != 0 {
		t.Fatal("restored while the app runs")
	}
	f.mu.Lock()
	f.alive = false
	f.mu.Unlock()
	select {
	case b := <-f.restored:
		sameServices(t, b, corpServices())
	case <-time.After(time.Second):
		t.Fatal("not restored after the app died")
	}

	f.mu.Lock()
	f.alive = true
	f.mu.Unlock()
	s.mu.Lock()
	err = s.handle(Request{Op: "enable", Config: systemproxy.Config{Host: "127.0.0.1", Port: 9090}}, peer{pid: 43})
	if err == nil {
		err = s.handle(Request{Op: "restore"}, peer{pid: 43})
	}
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	<-f.restored
	f.mu.Lock()
	f.alive = false
	f.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if len(f.restored) != 0 {
		t.Fatal("restored again after the app gave the proxy back itself")
	}
}

func TestHelperRestoresEachServiceItSaw(t *testing.T) {
	f := newFakeSystem(corpServices())
	s := f.server(t)
	cfg := systemproxy.Config{Host: "127.0.0.1", Port: 9090, Bypass: []string{"localhost"}}
	if err := s.handle(Request{Op: "enable", Config: cfg}, peer{}); err != nil {
		t.Fatal(err)
	}
	if err := s.handle(Request{Op: "enable", Config: cfg}, peer{}); err != nil {
		t.Fatal(err)
	}
	moved := cfg
	moved.Port = 9091
	if err := s.handle(Request{Op: "enable", Config: moved}, peer{}); err != nil {
		t.Fatal(err)
	}
	if f.reads != 1 {
		t.Errorf("read the settings %d times: ProxyGo's own would replace them", f.reads)
	}
	saved, ok := systemproxy.Load(s.path)
	if !ok || saved.Port != 9091 {
		t.Fatalf("saved %+v %v", saved, ok)
	}
	sameServices(t, saved.Before, corpServices())

	restarted := f.server(t)
	restarted.path = s.path
	if saved, ok := systemproxy.Load(restarted.path); ok {
		restarted.saved = &saved
	}
	if err := restarted.handle(Request{Op: "restore"}, peer{}); err != nil {
		t.Fatal(err)
	}
	sameServices(t, <-f.restored, corpServices())
	if _, ok := systemproxy.Load(s.path); ok {
		t.Error("the saved settings outlive the restore")
	}
	if err := restarted.handle(Request{Op: "restore"}, peer{}); err != nil {
		t.Fatal(err)
	}
	if b := <-f.restored; len(b) != 0 {
		t.Errorf("a restore with nothing saved restores %+v", b)
	}
}

func TestHelperDoesNotRememberItsOwnProxy(t *testing.T) {
	ours := systemproxy.Endpoint{On: true, Host: "127.0.0.1", Port: 9090}
	surge := systemproxy.Endpoint{On: true, Host: "127.0.0.1", Port: 7890}
	f := newFakeSystem(systemproxy.Snapshot{"Wi-Fi": {Web: ours, Secure: ours}, "Surge": {Web: surge, Secure: ours}})
	s := f.server(t)
	if err := s.handle(Request{Op: "enable", Config: systemproxy.Config{Host: "127.0.0.1", Port: 9090}}, peer{}); err != nil {
		t.Fatal(err)
	}
	if err := s.handle(Request{Op: "restore"}, peer{}); err != nil {
		t.Fatal(err)
	}
	off := ours
	off.On = false
	sameServices(t, <-f.restored, systemproxy.Snapshot{"Wi-Fi": {Web: off, Secure: off}, "Surge": {Web: surge, Secure: off}})
}

func TestHelperRefusesWhatItCannotRestore(t *testing.T) {
	f := newFakeSystem(corpServices())
	f.readErr = errors.New("networksetup failed")
	s := f.server(t)
	if err := s.handle(Request{Op: "enable", Config: systemproxy.Config{Host: "127.0.0.1", Port: 9090}}, peer{}); err == nil {
		t.Fatal("enable without a snapshot: want an error")
	}
	sameServices(t, f.services, corpServices())
	if _, ok := systemproxy.Load(s.path); ok {
		t.Error("saved settings it could not read")
	}
}

func TestRequestCarriesNoProxyState(t *testing.T) {
	var req Request
	if err := json.Unmarshal([]byte(`{"op":"restore","state":{"http":true,"host":"evil.example","port":8080},"before":{"Wi-Fi":{"web":{"on":true,"host":"evil.example","port":8080}}},"services":{"Wi-Fi":{"web":{"on":true,"host":"evil.example","port":8080}}}}`), &req); err != nil {
		t.Fatal(err)
	}
	f := newFakeSystem(systemproxy.Snapshot{})
	s := f.server(t)
	if err := s.handle(req, peer{}); err != nil {
		t.Fatal(err)
	}
	if b := <-f.restored; len(b) != 0 {
		t.Errorf("restored a state the client sent: %+v", b)
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
	label := "app.capyvibe.proxygo.helper"
	script := strings.Join(installCommands(label, "/Applications/ProxyGo.app/Contents/MacOS/ProxyGo", 501), " && ")
	program := "/Library/PrivilegedHelperTools/app.capyvibe.proxygo.helper.app/Contents/MacOS/ProxyGo"
	for _, want := range []string{
		"/usr/bin/ditto --noextattr --noqtn '/Applications/ProxyGo.app' '/Library/PrivilegedHelperTools/app.capyvibe.proxygo.helper.app.new'",
		"<string>" + program + "</string>",
		"/bin/rm -f '/Library/PrivilegedHelperTools/app.capyvibe.proxygo.helper'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "/bin/cp -X") {
		t.Errorf("an app's executable is copied without its bundle:\n%s", script)
	}
	lone := strings.Join(installCommands(label, "/Users/me/go/bin/proxygo", 501), " && ")
	if !strings.Contains(lone, "<string>/Library/PrivilegedHelperTools/app.capyvibe.proxygo.helper</string>") {
		t.Errorf("a bare executable is not installed on its own:\n%s", lone)
	}
}

func TestInstallRemovesTheFormerHelper(t *testing.T) {
	for label, former := range map[string]string{
		"app.capyvibe.proxygo.helper":       "com.example.proxygo.helper",
		"app.capyvibe.proxygo.debug.helper": "com.example.proxygo.debug.helper",
	} {
		if got := formerLabel(label); got != former {
			t.Errorf("formerLabel(%q) = %q, want %q", label, got, former)
		}
		script := strings.Join(installCommands(label, "/Applications/ProxyGo.app/Contents/MacOS/ProxyGo", 501), " && ")
		for _, want := range []string{
			"/bin/launchctl bootout 'system/" + former + "'",
			"/bin/rm -rf '/Library/PrivilegedHelperTools/" + former + ".app'",
			"'/Library/LaunchDaemons/" + former + ".plist'",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("install script for %s lacks %q", label, want)
			}
		}
	}
	if got := formerLabel("com.example.other.helper"); got != "" {
		t.Errorf("formerLabel of another app = %q", got)
	}
}
