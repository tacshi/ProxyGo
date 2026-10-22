package certs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeCommands(t *testing.T, answers map[string]string, fail map[string]string) *[]string {
	t.Helper()
	var ran []string
	orig := Command
	t.Cleanup(func() { Command = orig })
	Command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		line := filepath.Base(name) + " " + strings.Join(args, " ")
		ran = append(ran, line)
		for prefix, out := range fail {
			if strings.HasPrefix(line, prefix) {
				return []byte(out), errors.New("exit status 1")
			}
		}
		for prefix, out := range answers {
			if strings.HasPrefix(line, prefix) {
				return []byte(out), nil
			}
		}
		return nil, nil
	}
	return &ran
}

func TestInstallTargets(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ran := fakeCommands(t, map[string]string{
		"xcrun simctl list": `{"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-27-0":[{"udid":"U1","name":"iPhone 17","state":"Booted"},{"udid":"U2","name":"iPad","state":"Shutdown"}]}}`,
		"adb devices":       "List of devices attached\nemulator-5554 device product:sdk model:Pixel_9 device:emu\nR58 unauthorized usb:1\n",
		"java_home -V":      "Matching Java Virtual Machines (2):\n    24 (arm64) \"Oracle\" - \"OpenJDK 24\" /jdk/24/Contents/Home\n    21 (arm64) \"Temurin\" - \"21\" /jdk/21/Contents/Home\n",
		"java_home":         "/jdk/24/Contents/Home\n",
	}, map[string]string{"keytool -importcert": "keytool error: java.io.FileNotFoundException: cacerts (Permission denied)"})

	sims, err := BootedSimulators(context.Background())
	if err != nil || len(sims) != 1 || sims[0].UDID != "U1" || sims[0].Runtime != "iOS-27-0" {
		t.Errorf("simulators %+v %v", sims, err)
	}
	if err := m.InstallSimulator(context.Background(), "U1"); err != nil {
		t.Error(err)
	}
	devs, err := AndroidDevices(context.Background())
	if err != nil || len(devs) != 1 || devs[0].Model != "Pixel 9" || !devs[0].Emulator {
		t.Errorf("devices %+v", devs)
	}
	if err := m.InstallAndroid(context.Background(), "emulator-5554"); err != nil {
		t.Error(err)
	}
	if homes := JavaHomes(context.Background()); len(homes) != 2 || homes[0] != "/jdk/24/Contents/Home" || homes[1] != "/jdk/21/Contents/Home" {
		t.Errorf("Java homes %v", homes)
	}
	if err := m.InstallJava(context.Background(), "/jdk/24/Contents/Home"); !errors.Is(err, ErrNeedsAdmin) {
		t.Errorf("a store needing an administrator: %v", err)
	}
	joined := strings.Join(*ran, "\n")
	for _, want := range []string{
		"xcrun simctl keychain U1 add-root-cert " + m.CertPath(),
		"adb -s emulator-5554 push " + filepath.Join(m.Dir(), "proxygo-ca.crt") + " " + AndroidCertPath,
		"adb -s emulator-5554 shell am start -a android.settings.SECURITY_SETTINGS",
		"keytool -importcert -noprompt -cacerts -storepass changeit -alias proxygo-",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("did not run %q in\n%s", want, joined)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(m.Dir(), "proxygo-ca.crt")); len(b) == 0 || b[0] != 0x30 {
		t.Error("Android gets the certificate in DER")
	}
}

func TestTrustInFirefox(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	profiles := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	_ = os.MkdirAll(filepath.Join(profiles, "a.default"), 0o750)
	_ = os.MkdirAll(filepath.Join(profiles, "b.dev"), 0o750)
	_ = os.WriteFile(filepath.Join(profiles, "b.dev", "user.js"), []byte(`user_pref("x", 1);`), 0o600)
	changed, err := TrustInFirefox()
	if err != nil || len(changed) != 2 {
		t.Fatalf("%v %v", changed, err)
	}
	b, _ := os.ReadFile(filepath.Join(profiles, "b.dev", "user.js")) // #nosec G304 -- a file of the test's directory.
	if !strings.HasPrefix(string(b), `user_pref("x", 1);`+"\n") || !strings.Contains(string(b), firefoxPref) {
		t.Errorf("user.js %q", b)
	}
	if again, _ := TrustInFirefox(); len(again) != 0 {
		t.Error("the setting was added twice")
	}
}

func TestBundle(t *testing.T) {
	m, _ := New(t.TempDir())
	path, err := m.Bundle()
	if err != nil {
		t.Skip(err)
	}
	b, _ := os.ReadFile(path) // #nosec G304 -- a file of the test's directory.
	if strings.Count(string(b), "BEGIN CERTIFICATE") < 10 || !strings.HasSuffix(string(b), string(m.CertPEM())) {
		t.Errorf("bundle of %d certificates", strings.Count(string(b), "BEGIN CERTIFICATE"))
	}
}
