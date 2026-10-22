package certs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Simulator struct {
	UDID, Name, Runtime string
}

var Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- callers name a fixed tool and pass arguments, never shell text.
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	out, err := Command(ctx, name, args...)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return string(out), fmt.Errorf("%s: %s", filepath.Base(name), msg)
	}
	return string(out), nil
}

func BootedSimulators(ctx context.Context) ([]Simulator, error) {
	out, err := runCmd(ctx, "xcrun", "simctl", "list", "devices", "booted", "-j")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Devices map[string][]struct {
			UDID  string `json:"udid"`
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"devices"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("simctl: %w", err)
	}
	var sims []Simulator
	for runtime, devs := range doc.Devices {
		for _, d := range devs {
			if d.State == "Booted" {
				sims = append(sims, Simulator{UDID: d.UDID, Name: d.Name, Runtime: strings.TrimPrefix(runtime, "com.apple.CoreSimulator.SimRuntime.")})
			}
		}
	}
	return sims, nil
}

func (m *Manager) InstallSimulator(ctx context.Context, udid string) error {
	if udid == "" {
		udid = "booted"
	}
	_, err := runCmd(ctx, "xcrun", "simctl", "keychain", udid, "add-root-cert", m.certPath)
	return err
}

type AndroidDevice struct {
	Serial, Model string
	Emulator      bool
}

func AndroidDevices(ctx context.Context) ([]AndroidDevice, error) {
	out, err := runCmd(ctx, "adb", "devices", "-l")
	if err != nil {
		return nil, err
	}
	var devs []AndroidDevice
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "device" {
			continue
		}
		d := AndroidDevice{Serial: fields[0], Emulator: strings.HasPrefix(fields[0], "emulator-")}
		for _, f := range fields[2:] {
			if model, ok := strings.CutPrefix(f, "model:"); ok {
				d.Model = strings.ReplaceAll(model, "_", " ")
			}
		}
		devs = append(devs, d)
	}
	return devs, nil
}

const AndroidCertPath = "/sdcard/Download/proxygo-ca.crt"

func (m *Manager) InstallAndroid(ctx context.Context, serial string) error {
	der := filepath.Join(m.dir, "proxygo-ca.crt")
	if err := os.WriteFile(der, m.CertDER(), 0o644); err != nil { // #nosec G306 -- the public CA certificate, which other tools read.
		return err
	}
	adb := func(args ...string) error {
		if serial != "" {
			args = append([]string{"-s", serial}, args...)
		}
		_, err := runCmd(ctx, "adb", args...)
		return err
	}
	if err := adb("push", der, AndroidCertPath); err != nil {
		return err
	}
	_ = adb("shell", "am", "start", "-a", "android.settings.SECURITY_SETTINGS")
	return nil
}

func JavaHomes(ctx context.Context) []string {
	var homes []string
	if out, err := runCmd(ctx, "/usr/libexec/java_home"); err == nil {
		homes = append(homes, strings.TrimSpace(out))
	}
	out, _ := Command(ctx, "/usr/libexec/java_home", "-V")
	for line := range strings.SplitSeq(string(out), "\n") {
		if i := strings.Index(line, " /"); i >= 0 && strings.HasSuffix(strings.TrimSpace(line), "/Contents/Home") {
			if h := strings.TrimSpace(line[i:]); !contains(homes, h) {
				homes = append(homes, h)
			}
		}
	}
	return homes
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (m *Manager) javaAlias() string {
	sum := sha256.Sum256(m.CertDER())
	return "proxygo-" + hex.EncodeToString(sum[:4])
}

var ErrNeedsAdmin = errors.New("the Java installation's trust store needs an administrator to change")

func (m *Manager) InstallJava(ctx context.Context, javaHome string) error {
	keytool := filepath.Join(javaHome, "bin", "keytool")
	out, err := runCmd(ctx, keytool, m.javaArgs()...)
	switch {
	case err == nil:
		return nil
	case strings.Contains(out, "already exists"):
		return nil
	case strings.Contains(out, "Permission denied") || strings.Contains(out, "AccessDenied") || strings.Contains(out, "not permitted"):
		return ErrNeedsAdmin
	}
	return err
}

func (m *Manager) javaArgs() []string {
	return []string{"-importcert", "-noprompt", "-cacerts", "-storepass", "changeit", "-alias", m.javaAlias(), "-file", m.certPath}
}

func (m *Manager) InstallJavaAsAdmin(ctx context.Context, javaHome string) error {
	parts := []string{shellQuote(filepath.Join(javaHome, "bin", "keytool"))}
	for _, a := range m.javaArgs() {
		parts = append(parts, shellQuote(a))
	}
	script := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(strings.Join(parts, " "))
	out, err := runCmd(ctx, "osascript", "-e", `do shell script "`+script+`" with administrator privileges`)
	if err != nil && strings.Contains(out, "already exists") {
		return nil
	}
	return err
}

func (m *Manager) JavaTrusts(ctx context.Context, javaHome string) bool {
	_, err := runCmd(ctx, filepath.Join(javaHome, "bin", "keytool"), "-list", "-cacerts", "-storepass", "changeit", "-alias", m.javaAlias())
	return err == nil
}

func FirefoxProfiles() []string {
	home, _ := os.UserHomeDir()
	dirs, _ := filepath.Glob(filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles", "*"))
	var out []string
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			out = append(out, d)
		}
	}
	return out
}

const firefoxPref = `user_pref("security.enterprise_roots.enabled", true);`

func TrustInFirefox() ([]string, error) {
	var changed []string
	for _, p := range FirefoxProfiles() {
		path := filepath.Join(p, "user.js")
		b, err := os.ReadFile(path) // #nosec G304 -- a Firefox profile's own user.js.
		if err != nil && !os.IsNotExist(err) {
			return changed, err
		}
		if bytes.Contains(b, []byte("security.enterprise_roots.enabled")) {
			continue
		}
		if len(b) > 0 && !bytes.HasSuffix(b, []byte("\n")) {
			b = append(b, '\n')
		}
		b = append(b, "// Added by ProxyGo: trust the certificates macOS trusts.\n"+firefoxPref+"\n"...)
		if err := os.WriteFile(path, b, 0o644); err != nil { // #nosec G306 -- Firefox's own profile file, kept readable as Firefox writes it.
			return changed, err
		}
		changed = append(changed, filepath.Base(p))
	}
	return changed, nil
}

func (m *Manager) Bundle() (string, error) {
	path := filepath.Join(m.dir, "proxygo-bundle.pem")
	var b bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	roots, err := runCmd(ctx, "security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain")
	if err != nil || !strings.Contains(roots, "BEGIN CERTIFICATE") {
		data, ferr := os.ReadFile("/etc/ssl/cert.pem")
		if ferr != nil {
			return "", fmt.Errorf("no system roots: %w", cmpErr(err, ferr))
		}
		roots = string(data)
	}
	b.WriteString(roots)
	if !strings.HasSuffix(roots, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("# ProxyGo\n")
	b.Write(m.CertPEM())
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil { // #nosec G306 -- public certificates that other tools read as their CA bundle.
		return "", err
	}
	return path, nil
}

func cmpErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
