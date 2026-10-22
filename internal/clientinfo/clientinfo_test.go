package clientinfo

import (
	"os"
	"runtime"
	"testing"
)

func TestParseLsof(t *testing.T) {
	out := "p501\ncSafari\nn127.0.0.1:52001->127.0.0.1:9090\nn[::1]:52002->[::1]:9090\np77\ncnode\nn127.0.0.1:60000->1.2.3.4:443\n"
	ports, pids := parseLsof([]byte(out))
	if ports[52001] != 501 || ports[52002] != 501 || ports[60000] != 77 || !pids[501] || !pids[77] {
		t.Fatalf("ports %v pids %v", ports, pids)
	}
}

func TestNames(t *testing.T) {
	p := "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
	if appName(p) != "Google Chrome Helper" {
		t.Fatalf("app name %q", appName(p))
	}
	if BundlePath(p) != "/Applications/Google Chrome.app" {
		t.Fatalf("bundle %q", BundlePath(p))
	}
	if appName("/usr/bin/curl") != "" || BundlePath("/usr/bin/curl") != "" {
		t.Fatal("non-app path")
	}
}

func TestBundleID(t *testing.T) {
	if id := BundleID("/System/Applications/Calculator.app/Contents/MacOS/Calculator"); id != "com.apple.calculator" {
		t.Skipf("Calculator's bundle identifier: %q", id)
	}
	if BundleID("/usr/bin/curl") != "" {
		t.Error("a program outside an app has none")
	}
}

func TestExecutablePath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if got := executablePath(os.Getpid()); got != self {
		t.Fatalf("executablePath = %q, want %q", got, self)
	}
}
