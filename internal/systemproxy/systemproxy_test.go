package systemproxy

import (
	"os"
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

func TestReadParsers(t *testing.T) {
	e, err := parseEndpoint("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\nAuthenticated Proxy Enabled: 0\n")
	if err != nil || e != (Endpoint{On: true, Host: "127.0.0.1", Port: 7890}) {
		t.Fatalf("%+v %v", e, err)
	}
	if e, err := parseEndpoint("Enabled: No\nServer: (null)\nPort: 0\nAuthenticated Proxy Enabled: 0\n"); err != nil || e != (Endpoint{}) {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := parseEndpoint("** Error: Unable to find item in network database.\n"); err == nil {
		t.Error("an error message read as settings")
	}
	if url, on, err := parseAuto("URL: http://wpad/proxy.pac\nEnabled: Yes\n"); err != nil || url != "http://wpad/proxy.pac" || !on {
		t.Errorf("%q %v %v", url, on, err)
	}
	if url, on, err := parseAuto("URL: (null)\nEnabled: No\n"); err != nil || url != "" || on {
		t.Errorf("%q %v %v", url, on, err)
	}
	if _, _, err := parseAuto("** Error: The parameters were not valid.\n"); err == nil {
		t.Error("an error message read as settings")
	}
	if got := parseBypass("There aren't any bypass domains set on Wi-Fi.\n"); got != nil {
		t.Errorf("%q", got)
	}
	if got := parseBypass("*.local\n127.*\n172.16.*\n"); !slices.Equal(got, []string{"*.local", "127.*", "172.16.*"}) {
		t.Errorf("%q", got)
	}
}

func TestRestoreCommands(t *testing.T) {
	if got := RestoreCommands([]string{"Wi-Fi"}, nil); !slices.Equal(got, DisableCommands([]string{"Wi-Fi"})) {
		t.Fatalf("nothing saved: %v", got)
	}
	local := Endpoint{On: true, Host: "127.0.0.1", Port: 7890}
	stale := Endpoint{Host: "127.0.0.1", Port: 7890}
	got := RestoreCommands([]string{"Wi-Fi", "Surge", "New"}, Snapshot{
		"Wi-Fi": {Web: stale, Secure: stale, SOCKS: stale},
		"Surge": {Web: local, Secure: local, SOCKS: local, Bypass: []string{"*.local", "Bob's"}, AutoURL: "http://wpad/p.pac", AutoOn: true},
	})
	want := []string{
		"networksetup -setwebproxy 'Wi-Fi' '127.0.0.1' 7890",
		"networksetup -setwebproxystate 'Wi-Fi' off",
		"networksetup -setsecurewebproxy 'Wi-Fi' '127.0.0.1' 7890",
		"networksetup -setsecurewebproxystate 'Wi-Fi' off",
		"networksetup -setsocksfirewallproxy 'Wi-Fi' '127.0.0.1' 7890",
		"networksetup -setsocksfirewallproxystate 'Wi-Fi' off",
		"networksetup -setproxybypassdomains 'Wi-Fi' Empty",
		"networksetup -setautoproxystate 'Wi-Fi' off",
		"networksetup -setwebproxy 'Surge' '127.0.0.1' 7890",
		"networksetup -setwebproxystate 'Surge' on",
		"networksetup -setsecurewebproxy 'Surge' '127.0.0.1' 7890",
		"networksetup -setsecurewebproxystate 'Surge' on",
		"networksetup -setsocksfirewallproxy 'Surge' '127.0.0.1' 7890",
		"networksetup -setsocksfirewallproxystate 'Surge' on",
		"networksetup -setproxybypassdomains 'Surge' '*.local' 'Bob'\\''s'",
		"networksetup -setautoproxyurl 'Surge' 'http://wpad/p.pac'",
		"networksetup -setwebproxystate 'New' off",
		"networksetup -setsecurewebproxystate 'New' off",
		"networksetup -setsocksfirewallproxystate 'New' off",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWithout(t *testing.T) {
	ours := Endpoint{On: true, Host: "localhost", Port: 9090}
	socks := Endpoint{On: true, Host: "127.0.0.1", Port: 8889}
	other := Endpoint{On: true, Host: "127.0.0.1", Port: 7890}
	before := Snapshot{"Wi-Fi": {Web: ours, Secure: other, SOCKS: socks}}
	got := before.Without(Config{Host: "127.0.0.1", Port: 9090, SOCKSPort: 8889})["Wi-Fi"]
	if got.Web.On || !got.Secure.On || got.SOCKS.On {
		t.Errorf("%+v", got)
	}
	if !before["Wi-Fi"].Web.On {
		t.Error("Without changed its receiver")
	}
}

func TestParseScutilIgnoresTheDisabledProtocol(t *testing.T) {
	st := parseScutil("<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 3128\n  HTTPProxy : corp\n  HTTPSEnable : 0\n  HTTPSPort : 9090\n  HTTPSProxy : 127.0.0.1\n}")
	if st.Host != "corp" || st.Port != 3128 || st.PointsAt("127.0.0.1", 9090) {
		t.Errorf("%+v", st)
	}
}

func TestAutoProxyAndSaved(t *testing.T) {
	st := parseScutil("<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad/proxy.pac\n}")
	if st.AutoProxyURL != "http://wpad/proxy.pac" || st.Enabled() {
		t.Fatalf("%+v", st)
	}
	if !slices.Contains(EnableCommands([]string{"Wi-Fi"}, Config{Host: "127.0.0.1", Port: 9090}), "networksetup -setautoproxystate 'Wi-Fi' off") {
		t.Error("ProxyGo turns an auto-config file off")
	}
	path := filepath.Join(t.TempDir(), "system-proxy.json")
	if _, ok := Load(path); ok {
		t.Fatal("nothing saved yet")
	}
	before := Snapshot{"Wi-Fi": {Web: Endpoint{On: true, Host: "corp", Port: 3128}, Bypass: []string{"*.corp"}, AutoURL: "http://wpad/proxy.pac", AutoOn: true}}
	if err := Save(path, Saved{Before: before, Host: "127.0.0.1", Port: 9090}); err != nil {
		t.Fatal(err)
	}
	got, ok := Load(path)
	if !ok || got.Port != 9090 || got.Before["Wi-Fi"].Web.Host != "corp" || got.Before["Wi-Fi"].Bypass[0] != "*.corp" || !got.Before["Wi-Fi"].AutoOn {
		t.Errorf("%+v %v", got, ok)
	}
	Forget(path)
	if _, ok := Load(path); ok {
		t.Error("forgotten")
	}
	if err := os.WriteFile(path, []byte(`{"before":{"http":true,"host":"corp","port":3128},"host":"127.0.0.1","port":9090}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := Load(path); !ok || got.Port != 9090 || len(got.Before) != 0 {
		t.Errorf("a file from before: %+v %v", got, ok)
	}
}
