package systemproxy

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const scutil = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 9090
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 9090
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 1
  SOCKSPort : 8889
  SOCKSProxy : 127.0.0.1
}`

func TestParseScutil(t *testing.T) {
	st := parseScutil(scutil)
	if !st.Enabled() || !st.SOCKS || st.Port != 9090 || st.SOCKSPort != 8889 || st.Host != "127.0.0.1" {
		t.Fatalf("%+v", st)
	}
	if !slices.Equal(st.Bypass, []string{"*.local", "169.254/16"}) {
		t.Fatalf("bypass %v", st.Bypass)
	}
	if !st.PointsAt("localhost", 9090) || st.PointsAt("127.0.0.1", 9091) || st.PointsAt("10.0.0.2", 9090) {
		t.Fatal("PointsAt")
	}
	if parseScutil("<dictionary> {\n}").Enabled() {
		t.Fatal("empty dictionary enabled")
	}
}

func TestCommands(t *testing.T) {
	services := parseServices("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\n")
	if !slices.Equal(services, []string{"Wi-Fi", "USB 10/100/1000 LAN"}) {
		t.Fatalf("services %v", services)
	}
	cmds := EnableCommands([]string{"Wi-Fi", "Bob's LAN"}, Config{Host: "127.0.0.1", Port: 9090, SOCKSPort: 8889, Bypass: []string{"localhost", "*.local"}})
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"networksetup -setwebproxy 'Wi-Fi' '127.0.0.1' 9090",
		"networksetup -setsecurewebproxy 'Bob'\\''s LAN' '127.0.0.1' 9090",
		"networksetup -setsocksfirewallproxy 'Wi-Fi' '127.0.0.1' 8889",
		"networksetup -setproxybypassdomains 'Wi-Fi' 'localhost' '*.local'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	off := EnableCommands([]string{"Wi-Fi"}, Config{Host: "127.0.0.1", Port: 9090})
	if !slices.Contains(off, "networksetup -setsocksfirewallproxystate 'Wi-Fi' off") || !slices.Contains(off, "networksetup -setproxybypassdomains 'Wi-Fi' Empty") {
		t.Fatalf("%v", off)
	}
	if len(DisableCommands([]string{"Wi-Fi"})) != 3 {
		t.Fatal("disable commands")
	}
}

func TestRestoreCommands(t *testing.T) {
	if got := RestoreCommands([]string{"Wi-Fi"}, State{}); !slices.Equal(got, DisableCommands([]string{"Wi-Fi"})) {
		t.Fatalf("no proxy before: %v", got)
	}
	corp := State{HTTP: true, HTTPS: true, Host: "proxy.corp", Port: 3128, Bypass: []string{"*.corp"}}
	joined := strings.Join(RestoreCommands([]string{"Wi-Fi"}, corp), "\n")
	for _, want := range []string{
		"networksetup -setwebproxy 'Wi-Fi' 'proxy.corp' 3128",
		"networksetup -setsecurewebproxy 'Wi-Fi' 'proxy.corp' 3128",
		"networksetup -setsocksfirewallproxystate 'Wi-Fi' off",
		"networksetup -setproxybypassdomains 'Wi-Fi' '*.corp'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
}

func TestAutoProxyAndSaved(t *testing.T) {
	st := parseScutil("<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad/proxy.pac\n}")
	if st.AutoProxyURL != "http://wpad/proxy.pac" || st.Enabled() {
		t.Fatalf("%+v", st)
	}
	joined := strings.Join(RestoreCommands([]string{"Wi-Fi"}, st), "\n")
	if !strings.Contains(joined, "networksetup -setautoproxyurl 'Wi-Fi' 'http://wpad/proxy.pac'") || !strings.Contains(joined, "-setwebproxystate 'Wi-Fi' off") {
		t.Errorf("restore:\n%s", joined)
	}
	if !slices.Contains(EnableCommands([]string{"Wi-Fi"}, Config{Host: "127.0.0.1", Port: 9090}), "networksetup -setautoproxystate 'Wi-Fi' off") {
		t.Error("ProxyGo turns an auto-config file off")
	}
	path := filepath.Join(t.TempDir(), "system-proxy.json")
	if _, ok := Load(path); ok {
		t.Fatal("nothing saved yet")
	}
	if err := Save(path, Saved{Before: st, Host: "127.0.0.1", Port: 9090}); err != nil {
		t.Fatal(err)
	}
	got, ok := Load(path)
	if !ok || got.Before.AutoProxyURL != st.AutoProxyURL || got.Port != 9090 {
		t.Errorf("%+v %v", got, ok)
	}
	Forget(path)
	if _, ok := Load(path); ok {
		t.Error("forgotten")
	}
}
