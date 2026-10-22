package app

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/autosetup"
	"proxygo/internal/certs"
)

type devices struct {
	loading map[string]bool
	at      time.Time
	sims    []certs.Simulator
	android []certs.AndroidDevice
	java    []javaHome
	errs    map[string]string
	busy    map[string]bool
	done    map[string]bool
}

type javaHome struct {
	path    string
	trusted bool
}

func (a *App) refreshDevices(force bool) {
	d := &a.devices
	if a.certs == nil || len(d.loading) > 0 || !force && !d.at.IsZero() && time.Since(d.at) < 5*time.Second {
		return
	}
	d.at = time.Now()
	d.loading = map[string]bool{"sim": true, "android": true, "java": true}
	if d.errs == nil {
		d.errs = map[string]string{}
	}
	m := a.certs
	look := func(kind string, list func(ctx context.Context) error) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := list(ctx)
			a.do(func() {
				delete(d.loading, kind)
				d.errs[kind] = ""
				if err != nil {
					d.errs[kind] = err.Error()
				}
			})
		}()
	}
	look("sim", func(ctx context.Context) error {
		sims, err := certs.BootedSimulators(ctx)
		a.do(func() { d.sims = sims })
		return err
	})
	look("android", func(ctx context.Context) error {
		devs, err := certs.AndroidDevices(ctx)
		a.do(func() { d.android = devs })
		return err
	})
	look("java", func(ctx context.Context) error {
		var java []javaHome
		for _, h := range certs.JavaHomes(ctx) {
			java = append(java, javaHome{path: h, trusted: m.JavaTrusts(ctx, h)})
		}
		a.do(func() { d.java = java })
		return nil
	})
}

func (a *App) installOn(key string, install func(ctx context.Context) error, ok string) {
	d := &a.devices
	if d.busy == nil {
		d.busy, d.done = map[string]bool{}, map[string]bool{}
	}
	if d.busy[key] {
		return
	}
	d.busy[key] = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		err := install(ctx)
		a.do(func() {
			delete(d.busy, key)
			if err != nil {
				a.toast(err.Error())
				return
			}
			d.done[key] = true
			a.toast(ok)
			d.at = time.Time{}
		})
	}()
}

func (a *App) deviceRow(c *ui.Context, key, name, detail, button string, done bool, install func()) {
	p := a.pal
	ui.Row(c.Key(key)).FillWidth().Padding(8, 12).Gap(10).Radius(6).Background(p.surface).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Shrink(1).Gap(2).Children(func() {
			ui.Text(c, name).FontWeight(600).SingleLine()
			if detail != "" {
				ui.Text(c, detail).FontSize(11).TextColor(p.muted).SingleLine()
			}
		})
		switch {
		case a.devices.busy[key]:
			ui.Spinner(c)
		case done:
			ui.Text(c, "Installed").FontSize(11).FontWeight(650).TextColor(p.green).Background(p.greenSoft).Padding(2, 8).Radius(5)
		}
		if ui.Button(c, button).Disabled(a.devices.busy[key]).Clicked() {
			install()
		}
	})
}

func (a *App) deviceList(c *ui.Context, kind, none string, n int, rows func()) {
	p := a.pal
	a.refreshDevices(false)
	loading := a.devices.loading[kind]
	ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Margin(8, 0, 0, 0).Children(func() {
		ui.Text(c, "Install directly").FontWeight(650).Grow(1)
		if loading {
			ui.Spinner(c)
		}
		if ui.Button(c, "Refresh").Clicked() {
			a.refreshDevices(true)
		}
	})
	switch {
	case n > 0:
		rows()
	case loading:
	case a.devices.errs[kind] != "":
		ui.Text(c, a.devices.errs[kind]).FontSize(11).TextColor(p.muted).Wrap()
	default:
		ui.Text(c, none).FontSize(11).TextColor(p.muted).Wrap()
	}
}

func (a *App) simulatorInstall(c *ui.Context) {
	sims := a.devices.sims
	a.deviceList(c, "sim", "No simulator is booted. Boot one in Xcode, then Refresh.", len(sims), func() {
		for _, s := range sims {
			key := "sim:" + s.UDID
			a.deviceRow(c, key, s.Name, runtimeName(s.Runtime), "Install", a.devices.done[key], func() {
				udid := s.UDID
				a.installOn(key, func(ctx context.Context) error { return a.certs.InstallSimulator(ctx, udid) }, s.Name+" trusts ProxyGo's certificate")
			})
		}
	})
}

func (a *App) androidInstall(c *ui.Context, emulators bool) {
	var devs []certs.AndroidDevice
	for _, d := range a.devices.android {
		if d.Emulator == emulators {
			devs = append(devs, d)
		}
	}
	none := map[bool]string{true: "No emulator is running, or adb is not on the PATH.", false: "No device is connected with USB debugging on."}[emulators]
	a.deviceList(c, "android", none, len(devs), func() {
		for _, d := range devs {
			key := "android:" + d.Serial
			a.deviceRow(c, key, cmpString(d.Model, d.Serial), d.Serial, "Push Certificate", a.devices.done[key], func() {
				serial := d.Serial
				a.installOn(key, func(ctx context.Context) error { return a.certs.InstallAndroid(ctx, serial) },
					"Pushed to "+certs.AndroidCertPath+": install it in the Security settings that opened")
			})
		}
		ui.Text(c, "Android installs a CA certificate only by the user's hand: Push Certificate copies it to Downloads and opens Settings › Security.").FontSize(11).TextColor(a.pal.muted).Wrap()
	})
}

func runtimeName(r string) string {
	os, version, ok := strings.Cut(r, "-")
	if !ok {
		return r
	}
	return os + " " + strings.ReplaceAll(version, "-", ".")
}

func cmpString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (a *App) javaInstall(c *ui.Context) {
	homes := a.devices.java
	a.deviceList(c, "java", "No Java installation found.", len(homes), func() {
		for _, h := range homes {
			key := "java:" + h.path
			name := filepath.Base(strings.TrimSuffix(strings.TrimSuffix(h.path, "/Contents/Home"), "/"))
			a.deviceRow(c, key, name, h.path, "Install", h.trusted || a.devices.done[key], func() {
				home := h.path
				a.installOn(key, func(ctx context.Context) error {
					err := a.certs.InstallJava(ctx, home)
					if errors.Is(err, certs.ErrNeedsAdmin) {
						err = a.certs.InstallJavaAsAdmin(ctx, home)
					}
					return err
				}, name+" trusts ProxyGo's certificate")
			})
		}
	})
}

func (a *App) firefoxTrust(c *ui.Context) {
	profiles := certs.FirefoxProfiles()
	if len(profiles) == 0 {
		return
	}
	a.deviceRow(c, "firefox", "Firefox", plural(len(profiles), "profile", "profiles")+": trust the certificates this Mac trusts", "Trust", a.devices.done["firefox"], func() {
		a.installOn("firefox", func(context.Context) error {
			_, err := certs.TrustInFirefox()
			return err
		}, "Firefox trusts this Mac's certificates once it starts again")
	})
}

type rootImport struct {
	open                       bool
	p12                        bool
	certPath, keyPath, p12Path string
	password                   string
	err                        string
}

func rootSummary(r *rootImport) (string, error) {
	var cert *x509.Certificate
	if r.p12 {
		tc, err := certs.LoadP12(r.p12Path, r.password)
		if err != nil {
			return "", err
		}
		cert = tc.Leaf
	} else {
		b, err := os.ReadFile(r.certPath)
		if err != nil {
			return "", err
		}
		for {
			var block *pem.Block
			block, b = pem.Decode(b)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					return "", err
				}
				break
			}
		}
		if cert == nil {
			return "", errors.New("the file holds no PEM certificate")
		}
	}
	sum := sha256.Sum256(cert.Raw)
	fp := strings.ToUpper(hex.EncodeToString(sum[:]))
	var pairs []string
	for i := 0; i < len(fp); i += 2 {
		pairs = append(pairs, fp[i:i+2])
	}
	name := cert.Subject.CommonName
	if org := strings.Join(cert.Subject.Organization, ", "); org != "" {
		name += " · " + org
	}
	return fmt.Sprintf("%s\nValid %s to %s\nSHA-256 %s", name, cert.NotBefore.Format(time.DateOnly), cert.NotAfter.Format(time.DateOnly), strings.Join(pairs, ":")), nil
}

func (a *App) rootImportView(c *ui.Context) {
	r := &a.rootImport
	if !r.open {
		return
	}
	p := a.pal
	ui.Modal(c, &r.open, func() {
		ui.Column(c).Width(sheetWidth(c, 560)).Gap(10).Children(func() {
			ui.Text(c, "Use Your Own Root Certificate").FontSize(15).FontWeight(650)
			ui.Text(c, "ProxyGo signs the hosts' certificates with a certificate authority you trust already, as your company's. Devices that trusted ProxyGo's own root must trust this one.").TextColor(p.muted).Wrap()
			format := map[bool]int{true: 1}[r.p12]
			ui.Form(c, func() {
				ui.Field(c, "Format", func() {
					if ui.Segmented(c, &format, "PEM Files", "PKCS#12 (.p12)").Label("Format").AlignSelf(ui.Start).Changed() {
						r.p12, r.err = format == 1, ""
					}
				})
				pick := func(label, placeholder string, v *string) {
					ui.Field(c, label, func() {
						ui.Row(c).Gap(6).Children(func() {
							ui.TextInput(c, v).Placeholder(placeholder).Label(label).Grow(1)
							if ui.Button(c, "Choose…").Clicked() {
								a.choosePath("certificate", false, func(p string) { *v = p })
							}
						})
					})
				}
				if format == 0 {
					pick("Certificate", "ca.pem", &r.certPath)
					pick("Private Key", "ca-key.pem, if not in the certificate file", &r.keyPath)
				} else {
					pick("Bundle", "ca.p12", &r.p12Path)
					ui.Field(c, "Password", func() {
						ui.TextInput(c, &r.password).Placeholder("The bundle's password").Label("Bundle password").Password()
					})
				}
			})
			ready := !r.p12 && r.certPath != "" || r.p12 && r.p12Path != ""
			summary := ""
			if ready {
				s, err := rootSummary(r)
				if err != nil {
					ui.Text(c, err.Error()).FontSize(11).TextColor(p.red).Wrap()
					ready = false
				} else {
					summary = s
					ui.Text(c, "Check it is your certificate before it replaces ProxyGo's:").FontSize(11).TextColor(p.text2)
					code(c, p, summary)
				}
			}
			if r.err != "" {
				ui.Text(c, r.err).FontSize(11).TextColor(p.red).Wrap()
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "Cancel").Clicked() {
					r.open = false
				}
				if ui.PrimaryButton(c, "Replace ProxyGo's Root").Disabled(!ready).Clicked() {
					if err := a.importRoot(r); err != nil {
						r.err = err.Error()
						return
					}
					r.open = false
					a.toast("ProxyGo now signs with " + a.certs.CommonName() + ": devices must trust it")
					a.checkTrust()
				}
			})
		})
	})
}

func (a *App) importRoot(r *rootImport) error {
	if r.p12 {
		data, err := os.ReadFile(r.p12Path)
		if err != nil {
			return err
		}
		return a.certs.ImportRootP12(data, r.password)
	}
	certPEM, err := os.ReadFile(r.certPath)
	if err != nil {
		return err
	}
	keyPEM := certPEM
	if r.keyPath != "" {
		if keyPEM, err = os.ReadFile(r.keyPath); err != nil {
			return err
		}
	}
	return a.certs.ImportRoot(certPEM, keyPEM)
}

func (a *App) setupConfig() (autosetup.Config, error) {
	if a.certs == nil {
		return autosetup.Config{}, errors.New("ProxyGo has no certificate")
	}
	bundle, err := a.certs.Bundle()
	if err != nil {
		bundle = ""
	}
	return autosetup.Config{
		Proxy: "http://127.0.0.1:" + strconv.Itoa(a.proxy.Port()), CA: a.certs.CertPath(), Bundle: bundle,
		Dir: filepath.Join(a.dir, "setup"),
	}, nil
}

func (a *App) runSetup(what string, start func(autosetup.Config) error) {
	go func() {
		cfg, err := a.setupConfig()
		if err == nil {
			err = start(cfg)
		}
		a.do(func() {
			if err != nil {
				a.toast(what + ": " + err.Error())
				return
			}
			a.toast("Opened " + what + " through ProxyGo")
		})
	}()
}

func (a *App) setupWindow(c *ui.Context) {
	p := a.pal
	a.windowHeader(c, "Automatic Setup", "Open a terminal, a browser or an Electron app that goes through ProxyGo and trusts its certificate, leaving the macOS proxy alone.", nil)
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(0, windowInset, windowInset, windowInset).Gap(8).Children(func() {
			section := func(title string) {
				ui.Text(c, title).FontWeight(650).Margin(10, 0, 2, 0)
			}
			section("Terminal")
			ui.Text(c, "curl, Node.js, Python, Ruby, Go, Git and the AWS CLI read the proxy and the certificate from the shell's environment.").FontSize(11).TextColor(p.muted).Wrap()
			ui.Row(c).Gap(8).Children(func() {
				for _, t := range autosetup.Terminals {
					if t != "Terminal" && !autosetup.Installed(t) {
						continue
					}
					if ui.Button(c, "Open "+t).Clicked() {
						term := t
						a.runSetup(term, func(cfg autosetup.Config) error { return autosetup.OpenTerminal(cfg, term) })
					}
				}
				ui.MenuButton(c, "Copy Commands", func(m *ui.Menu) {
					for _, sh := range []string{"zsh / bash", "fish"} {
						if m.Item("For " + sh).Chosen() {
							fish := sh == "fish"
							go func() {
								cfg, err := a.setupConfig()
								a.do(func() {
									if err != nil {
										a.toast(err.Error())
										return
									}
									a.copy(autosetup.Shell(cfg, fish), "the commands")
								})
							}()
						}
					}
				})
			})
			section("Browsers")
			ui.Text(c, "Each opens in a profile of its own, with its own cookies and sign-ins: yours stay as they are.").FontSize(11).TextColor(p.muted).Wrap()
			var shown int
			for _, b := range autosetup.Browsers {
				if !autosetup.Installed(b.App) {
					continue
				}
				shown++
				a.deviceRow(c, "browser:"+b.Name, b.Name, "Trusts the certificates this Mac trusts", "Open", false, func() {
					br := b
					a.runSetup(br.Name, func(cfg autosetup.Config) error { return autosetup.OpenBrowser(cfg, br) })
				})
			}
			if autosetup.Installed("Firefox") {
				shown++
				a.deviceRow(c, "browser:firefox", "Firefox", "Its own profile, set to trust this Mac's certificates", "Open", false, func() {
					a.runSetup("Firefox", func(cfg autosetup.Config) error { return autosetup.OpenFirefox(cfg, "127.0.0.1", a.proxy.Port()) })
				})
			}
			if shown == 0 {
				ui.Text(c, "No Chromium browser or Firefox is in Applications.").FontSize(11).TextColor(p.muted)
			}
			if !a.certTrusted {
				ui.Text(c, "Browsers trust ProxyGo's certificate once it is installed on this Mac.").FontSize(11).TextColor(p.yellow).Wrap()
			}
			section("Electron Apps")
			ui.Text(c, "Slack, VS Code, Discord, Notion: a new instance goes through ProxyGo. Quit the app first, as most allow one instance.").FontSize(11).TextColor(p.muted).Wrap()
			apps := electronApps()
			for _, app := range apps {
				name := strings.TrimSuffix(filepath.Base(app), ".app")
				a.deviceRow(c, "electron:"+app, name, app, "Open", false, func() {
					path := app
					a.runSetup(name, func(cfg autosetup.Config) error { return autosetup.OpenElectron(cfg, path) })
				})
			}
			if ui.Button(c, "Choose an App…").AlignSelf(ui.Start).Clicked() {
				a.chooseElectronApp()
			}
		})
	})
}

var electronApps = sync.OnceValue(func() []string {
	home, _ := os.UserHomeDir()
	var out []string
	for _, dir := range []string{"/Applications", filepath.Join(home, "Applications")} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if p := filepath.Join(dir, e.Name()); strings.HasSuffix(e.Name(), ".app") && autosetup.IsElectron(p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
})

func (a *App) chooseElectronApp() {
	parent := a.windows["setup"]
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Title: "Choose an Electron App", DefaultPath: "/Applications", Filters: []mygo.FileFilter{{Name: "Applications", Extensions: []string{"app"}}}})
		if err != nil || len(paths) == 0 {
			return
		}
		app := paths[0]
		a.do(func() {
			a.runSetup(strings.TrimSuffix(filepath.Base(app), ".app"), func(cfg autosetup.Config) error { return autosetup.OpenElectron(cfg, app) })
		})
	}()
}
