package privileged

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
