package app

import (
	"cmp"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"
	"github.com/egoist/mygo/proxygoui/editor"

	"proxygo/internal/certs"
	"proxygo/internal/rules"
)

func tplID(r *rules.BreakpointTemplate) string { return r.ID }
func appID(r *rules.AppRule) string            { return r.ID }
func pbID(r *rules.ProtobufRule) string        { return r.ID }
func scID(r *rules.ServerCertificate) string   { return r.ID }

func init() {
	ruleKinds["bptemplates"] = &ruleKind{
		title: "Breakpoint Templates", add: "New Template",
		about: "Requests and responses to apply at a breakpoint: answer a paused request at once, or replace what was paused.",
		empty: "No templates yet", hint: "Add one here, or save a paused request or response as one.",
		columns: []ui.TableColumn{{Title: "Name", Width: 200}, {Title: "Kind", Width: 90}, {Title: "Message"}},
		ids:     func(d *rules.Data) []string { return ids(d.BreakpointTemplates, tplID) },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.BreakpointTemplates, id, tplID)
			first, _, _ := strings.Cut(strings.TrimSpace(r.Raw), "\n")
			return []string{r.Name, map[bool]string{true: "Response", false: "Request"}[r.Response], first}
		},
		fresh: func() any {
			return &rules.BreakpointTemplate{ID: rules.NewID(), Response: true, Raw: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \n}"}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.BreakpointTemplates, id, tplID)) },
		form:   templateForm,
		save: func(d *rules.Data, v any) {
			d.BreakpointTemplates = putByID(d.BreakpointTemplates, v.(*rules.BreakpointTemplate), tplID)
		},
		remove: func(d *rules.Data, id string) { d.BreakpointTemplates = dropByID(d.BreakpointTemplates, id, tplID) },
	}
	ruleKinds["blockedapps"] = &ruleKind{
		title: "Blocked Apps", add: "Block an App",
		about:   "Stop an app's traffic, whatever it asks for, as a flow's Block this App. The Block List's switch turns these off too.",
		hint:    "Add one here, or from a flow's menu › Block this App.",
		columns: []ui.TableColumn{{Title: "App", Width: 180}, {Title: "Bundle Identifier"}, {Title: "Action", Width: 140}},
		ids:     func(d *rules.Data) []string { return ids(d.BlockedApps, appID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.BlockedApps, id, appID).Enabled },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.BlockedApps, id, appID)
			return []string{r.AppName, cmp.Or(r.BundleID, "(by name)"), map[string]string{rules.BlockDisplay: "Block & Display", rules.BlockHide: "Block & Hide"}[cmp.Or(r.Action, rules.BlockDisplay)]}
		},
		fresh:  func() any { return &rules.AppRule{ID: rules.NewID(), Enabled: true, Action: rules.BlockDisplay} },
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.BlockedApps, id, appID)) },
		form:   blockedAppForm,
		save:   func(d *rules.Data, v any) { d.BlockedApps = putByID(d.BlockedApps, v.(*rules.AppRule), appID) },
		remove: func(d *rules.Data, id string) { d.BlockedApps = dropByID(d.BlockedApps, id, appID) },
	}
	ruleKinds["protobuf"] = &ruleKind{
		title: "Protobuf", add: "New Rule", noun: "Protobuf Rule",
		about:   "Decode matching flows' protobuf bodies as their message types, from the .proto files or descriptor sets imported.",
		hint:    "Add one here, or choose a message type on a protobuf body.",
		columns: []ui.TableColumn{{Title: "Name", Width: 150}, {Title: "Matching Rule"}, {Title: "Request", Width: 150}, {Title: "Response", Width: 150}},
		ids:     func(d *rules.Data) []string { return ids(d.Protobuf, pbID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.Protobuf, id, pbID).Enabled },
		matcher: func(d *rules.Data, id string) *rules.Matcher { return &byID(d.Protobuf, id, pbID).Matcher },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.Protobuf, id, pbID)
			return []string{r.Name, matchSummary(r.Matcher), cmp.Or(r.RequestType, "—"), cmp.Or(r.ResponseType, "—")}
		},
		extra: protobufSchemasMenu,
		fresh: func() any {
			return &rules.ProtobufRule{ID: rules.NewID(), Enabled: true, Matcher: rules.Matcher{URL: "https://"}}
		},
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.Protobuf, id, pbID)) },
		form:   protobufForm,
		save:   func(d *rules.Data, v any) { d.Protobuf = putByID(d.Protobuf, v.(*rules.ProtobufRule), pbID) },
		remove: func(d *rules.Data, id string) { d.Protobuf = dropByID(d.Protobuf, id, pbID) },
	}
	ruleKinds["servercerts"] = &ruleKind{
		title: "Custom Server Certificates", add: "Add Certificate",
		about: "Present a server's own certificate to clients for its hosts, instead of one ProxyGo signs: for apps that pin it.",
		empty: "No certificates yet", hint: "Add a server's certificate and its key, as PEM files or a .p12.",
		columns: []ui.TableColumn{{Title: "Hosts", Width: 220}, {Title: "Certificate"}, {Title: "Format", Width: 80}},
		ids:     func(d *rules.Data) []string { return ids(d.ServerCerts, scID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.ServerCerts, id, scID).Enabled },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.ServerCerts, id, scID)
			hosts := cmp.Or(strings.Join(r.Hosts, ", "), "(the certificate's names)")
			if r.P12Path != "" {
				return []string{hosts, r.P12Path, "P12"}
			}
			return []string{hosts, r.CertPath, "PEM"}
		},
		fresh:  func() any { return &rules.ServerCertificate{ID: rules.NewID(), Enabled: true} },
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.ServerCerts, id, scID)) },
		form:   serverCertForm,
		save:   func(d *rules.Data, v any) { d.ServerCerts = putByID(d.ServerCerts, v.(*rules.ServerCertificate), scID) },
		remove: func(d *rules.Data, id string) {
			if r := byID(d.ServerCerts, id, scID); r != nil && r.PasswordRef != "" {
				_ = certs.Keychain.Delete(r.PasswordRef)
			}
			d.ServerCerts = dropByID(d.ServerCerts, id, scID)
		},
	}
	windowSpecs["bptemplates"] = windowSpec{"Breakpoint Templates", 860, 600}
	windowSpecs["blockedapps"] = windowSpec{"Blocked Apps", 760, 500}
	windowSpecs["protobuf"] = windowSpec{"Protobuf", 900, 600}
	windowSpecs["servercerts"] = windowSpec{"Custom Server Certificates", 820, 540}
}

func templateTitle(r *rules.BreakpointTemplate) string {
	first, _, _ := strings.Cut(strings.TrimSpace(r.Raw), "\n")
	first = strings.TrimPrefix(strings.TrimPrefix(first, "HTTP/1.1 "), "HTTP/2 ")
	return cmp.Or(shorten(strings.TrimSuffix(first, " HTTP/1.1"), 60), "Template")
}

func templateForm(a *App, c *ui.Context, t *toolState) string {
	p := a.pal
	r := t.draft.(*rules.BreakpointTemplate)
	kind := map[bool]int{true: 1}[r.Response]
	ui.Form(c, func() {
		ui.Field(c, "Name", func() {
			ui.TextInput(c, &r.Name).Placeholder("Named after its first line when empty").Label("Name").AutoFocus()
		})
		ui.Field(c, "Kind", func() {
			if ui.Segmented(c, &kind, "Request", "Response").Label("Template kind").AlignSelf(ui.Start).Changed() {
				r.Response = kind == 1
				if text := strings.TrimSpace(t.body.Buffer.String()); text == "" || strings.HasPrefix(text, "HTTP/") != r.Response {
					t.body.Buffer.Set(map[bool]string{true: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \n}", false: "POST /path HTTP/1.1\nContent-Type: application/json\n\n{\n  \n}"}[r.Response])
				}
			}
		}).Description(map[bool]string{true: "At a paused request, answers it without the server; at a paused response, replaces it.", false: "Replaces a paused request. A path keeps the request's scheme and host."}[r.Response])
	})
	ui.Column(c).FillWidth().Height(260).Radius(6).Border(1, p.border).Clip().Children(func() {
		editor.View(c.Key("template"), t.body).Fill()
	})
	probe := *r
	probe.Raw = t.body.Buffer.String()
	if _, err := probe.Parse(); err != nil {
		ui.Text(c, err.Error()).FontSize(11).TextColor(p.red).Wrap()
		return err.Error()
	}
	return ""
}

func blockedAppForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.AppRule)
	action := map[string]string{rules.BlockDisplay: "Block & Display (answer 403)", rules.BlockHide: "Block & Hide (drop the connection)"}[cmp.Or(r.Action, rules.BlockDisplay)]
	var seen []string
	for name := range a.sourceTree().apps {
		seen = append(seen, name)
	}
	slices.Sort(seen)
	ui.Form(c, func() {
		ui.Field(c, "App", func() {
			ui.Autocomplete(c, &r.AppName, seen).Placeholder("Safari").Label("App name").AutoFocus()
		})
		ui.Field(c, "Bundle Identifier", func() {
			ui.TextInput(c, &r.BundleID).Placeholder("com.apple.Safari (optional)").Label("Bundle identifier")
		}).Description("With one, the app is blocked whatever its process is called; without, by its name.")
		ui.Field(c, "Action", func() {
			if ui.Select(c, &action, []string{"Block & Display (answer 403)", "Block & Hide (drop the connection)"}).Label("Action").Changed() {
				r.Action = map[bool]string{true: rules.BlockHide, false: rules.BlockDisplay}[strings.HasPrefix(action, "Block & Hide")]
			}
		})
	})
	if strings.TrimSpace(r.AppName) == "" && strings.TrimSpace(r.BundleID) == "" {
		return "Enter the app's name or bundle identifier."
	}
	return ""
}

func protobufForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.ProtobufRule)
	invalid := a.matcherForm(c, t, &r.Name, &r.Matcher)
	const raw = "Raw fields"
	types := append([]string{raw}, a.schemas.Messages()...)
	picker := func(label string, v *string) {
		choice := cmp.Or(*v, raw)
		if !slices.Contains(types, choice) {
			types = append(types, choice)
		}
		if ui.Combobox(c, &choice, types).Label(label).Changed() {
			*v = choice
			if choice == raw {
				*v = ""
			}
		}
	}
	payloads := []string{"Automatic", "Single message", "Length-delimited messages", "gRPC frames"}
	values := []string{"", "single", "delimited", "grpc"}
	payload := payloads[max(slices.Index(values, r.Payload), 0)]
	ui.Form(c, func() {
		ui.Field(c, "Request Type", func() { picker("Request message type", &r.RequestType) })
		ui.Field(c, "Response Type", func() { picker("Response message type", &r.ResponseType) }).Description("For WebSocket messages, the request type is what the client sends, the response type what the server does.")
		ui.Field(c, "Payload", func() {
			if ui.Select(c, &payload, payloads).Label("Payload").Width(240).Changed() {
				r.Payload = values[slices.Index(payloads, payload)]
			}
		}).Description("Automatic reads gRPC's frames for gRPC, and one message otherwise.")
	})
	if len(a.schemas.Messages()) == 0 {
		ui.Text(c, "Import a .proto file or a descriptor set to choose message types.").FontSize(11).TextColor(a.pal.yellow)
	}
	return invalid
}

func protobufSchemasMenu(a *App, c *ui.Context) {
	list := a.schemas.List()
	if ui.Button(c, "Import Schema…").Tooltip("Import a .proto file, with the files it imports beside it, or a descriptor set (protoc --descriptor_set_out)").Clicked() {
		a.importSchema()
	}
	ui.MenuButton(c, fmt.Sprintf("Schemas (%d)", len(list)), func(m *ui.Menu) {
		if len(list) == 0 {
			m.Item("No schemas imported").Disabled(true)
		}
		for _, s := range list {
			m.Submenu(s.Name, func(m *ui.Menu) {
				m.Item(s.Source).Disabled(true)
				m.Item("Imported " + s.Imported.Format(time.DateTime)).Disabled(true)
				m.Separator()
				if m.Item("Remove").Chosen() {
					if err := a.schemas.Remove(s.ID); err != nil {
						a.toast("Cannot remove " + s.Name + ": " + err.Error())
					}
				}
			})
		}
		if err := a.schemas.Err(); err != nil {
			m.Separator()
			m.Item("The schemas do not link: " + err.Error()).Disabled(true)
		}
	})
}

func (a *App) importSchema() {
	parent := a.windows["protobuf"]
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent: parent, Title: "Import a Protobuf Schema", Multiple: true,
			Filters: []mygo.FileFilter{
				{Name: "Protobuf Schemas", Extensions: []string{"proto", "desc", "pb", "binpb", "protoset"}},
				{Name: "All Files", Extensions: []string{"*"}},
			},
		})
		if err != nil {
			return
		}
		for _, path := range paths {
			s, err := a.schemas.Import(path)
			a.do(func() {
				if err != nil {
					a.toast("Cannot import " + filepath.Base(path) + ": " + err.Error())
					return
				}
				a.toast("Imported " + s.Name)
			})
		}
	}()
}

func serverCertForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.ServerCertificate)
	hosts := strings.Join(r.Hosts, ", ")
	return a.certFields(c, t, "servercerts", func() {
		ui.Field(c, "Hosts", func() {
			if ui.TextInput(c, &hosts).Placeholder("api.example.com, *.example.com").Label("Hosts").AutoFocus().Changed() {
				r.Hosts = nil
				for h := range strings.SplitSeq(hosts, ",") {
					if h = strings.TrimSpace(h); h != "" {
						r.Hosts = append(r.Hosts, h)
					}
				}
			}
		}).Description("Empty uses the names the certificate is valid for.")
	}, &r.CertPath, &r.KeyPath, &r.P12Path, &r.PasswordRef, r.Hosts)
}

func (a *App) certFields(c *ui.Context, t *toolState, kind string, lead func(), certPath, keyPath, p12Path, ref *string, hosts []string) string {
	p := a.pal
	format := min(t.tab, 1)
	ui.Form(c, func() {
		lead()
		ui.Field(c, "Format", func() {
			if ui.Segmented(c, &format, "PEM Files", "PKCS#12 (.p12)").Label("Format").AlignSelf(ui.Start).Changed() {
				t.tab = format
			}
		})
		file := func(label, placeholder string, v *string) {
			ui.Field(c, label, func() {
				ui.Row(c).Gap(6).Children(func() {
					ui.TextInput(c, v).Placeholder(placeholder).Label(label).Grow(1)
					if ui.Button(c, "Choose…").Clicked() {
						a.choosePath(kind, false, func(p string) { *v = p })
					}
				})
			})
		}
		if format == 0 {
			file("Certificate", "server.pem, the chain after the certificate", certPath)
			file("Private Key", "server-key.pem, if not in the certificate file", keyPath)
			return
		}
		file("Bundle", "server.p12", p12Path)
		ui.Field(c, "Password", func() {
			placeholder := "The bundle's password"
			if *ref != "" {
				placeholder = "Kept in the keychain; type to change it"
			}
			ui.TextInput(c, &t.secret).Placeholder(placeholder).Label("Bundle password").Password()
		}).Description("Kept in the macOS keychain, never in ProxyGo's rules or their exports.")
	})
	if format == 0 {
		*p12Path = ""
		if *certPath == "" {
			return "Choose the certificate."
		}
	} else {
		*certPath, *keyPath = "", ""
		if *p12Path == "" {
			return "Choose the bundle."
		}
	}
	cert, err := a.loadDraftCert(t, *certPath, *keyPath, *p12Path, *ref)
	if err != nil {
		ui.Text(c, err.Error()).FontSize(11).TextColor(p.red).Wrap()
		return err.Error()
	}
	leaf := cert.Leaf
	if leaf == nil {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if leaf != nil {
		names := strings.Join(leaf.DNSNames, ", ")
		ui.Text(c, fmt.Sprintf("%s · valid for %s · until %s", leaf.Subject.CommonName, cmp.Or(names, "no names"), leaf.NotAfter.Format(time.DateOnly))).FontSize(11).TextColor(p.muted).Wrap()
		for _, h := range hosts {
			if !certs.Covers(cert, strings.TrimPrefix(h, "*.")) && leaf.VerifyHostname(h) != nil {
				ui.Text(c, "The certificate is not valid for "+h+": clients will refuse it.").FontSize(11).TextColor(p.yellow).Wrap()
			}
		}
		if time.Now().After(leaf.NotAfter) {
			ui.Text(c, "The certificate has expired.").FontSize(11).TextColor(p.yellow)
		}
	}
	return ""
}

func (a *App) loadDraftCert(t *toolState, certPath, keyPath, p12Path, ref string) (*tls.Certificate, error) {
	if p12Path == "" {
		if _, err := os.Stat(expandHome(certPath)); err != nil {
			return nil, fmt.Errorf("the certificate file does not exist")
		}
		if keyPath != "" {
			if _, err := os.Stat(expandHome(keyPath)); err != nil {
				return nil, fmt.Errorf("the key file does not exist")
			}
		}
		cert, err := certs.LoadPEM(expandHome(certPath), expandHome(keyPath))
		return cert, pemError(err)
	}
	if _, err := os.Stat(expandHome(p12Path)); err != nil {
		return nil, fmt.Errorf("the bundle does not exist")
	}
	password := t.secret
	if password == "" && ref != "" {
		password, _ = certs.Keychain.Get(ref)
	}
	return certs.LoadP12(expandHome(p12Path), password)
}

func pemError(err error) error {
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), "may have been switched"):
		return errors.New("the certificate file holds a key: the two files may be switched")
	case strings.Contains(err.Error(), "found a certificate rather than a key"):
		return errors.New("the certificate file holds no private key: choose the key's file")
	case strings.Contains(err.Error(), "does not match"):
		return errors.New("the private key is not the certificate's")
	case strings.Contains(err.Error(), "failed to find any PEM data in key"):
		return errors.New("the key file holds no PEM private key")
	case strings.Contains(err.Error(), "failed to find any PEM data in certificate"), strings.Contains(err.Error(), "failed to find certificate PEM data"):
		return errors.New("the certificate file holds no PEM certificate")
	}
	return err
}

func (a *App) saveSecret(t *toolState) error {
	if t.secret == "" {
		return nil
	}
	var ref *string
	var id string
	switch r := t.draft.(type) {
	case *rules.ServerCertificate:
		ref, id = &r.PasswordRef, "server-"+r.ID
		if r.P12Path == "" {
			return nil
		}
	case *rules.ClientCertificate:
		ref, id = &r.PasswordRef, "client-"+r.ID
		if r.P12Path == "" {
			return nil
		}
	default:
		return nil
	}
	if *ref == "" {
		*ref = id
	}
	if err := certs.Keychain.Set(*ref, t.secret); err != nil {
		return err
	}
	t.secret = ""
	return nil
}

func (a *App) folderField(c *ui.Context, inUse []string, folder *string) string {
	var folders []string
	for _, f := range inUse {
		if f != "" && !slices.Contains(folders, f) {
			folders = append(folders, f)
		}
	}
	slices.Sort(folders)
	_, problem := rules.CleanFolder(*folder)
	ui.Field(c, "Folder", func() {
		ui.Autocomplete(c, folder, folders).Placeholder("None").Label("Folder")
	}).Description(fmt.Sprintf("Group rules, as API/v1, to switch them on and off together. Folders nest %d deep.", rules.MaxFolderDepth)).Error(problem)
	return problem
}

func ruleFolders[T any](list []*T, folder func(*T) string) []string {
	var out []string
	for _, r := range list {
		if r != nil {
			out = append(out, folder(r))
		}
	}
	return out
}
