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
	"proxygo/locales"
)

func tplID(r *rules.BreakpointTemplate) string { return r.ID }
func appID(r *rules.AppRule) string            { return r.ID }
func pbID(r *rules.ProtobufRule) string        { return r.ID }
func scID(r *rules.ServerCertificate) string   { return r.ID }

func init() {
	ruleKinds["bptemplates"] = &ruleKind{
		title: locales.BreakpointTemplates, add: locales.NewTemplate,
		about: locales.RequestsAndResponsesToApplyAt,
		empty: locales.NoTemplatesYet, hint: locales.AddOneHereOrSaveA,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnName(), Width: 200}, {Title: locales.Kind(), Width: 90}, {Title: locales.Message()}}
		},
		ids: func(d *rules.Data) []string { return ids(d.BreakpointTemplates, tplID) },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.BreakpointTemplates, id, tplID)
			first, _, _ := strings.Cut(strings.TrimSpace(r.Raw), "\n")
			return []string{r.Name, map[bool]string{true: locales.PhaseResponse(), false: locales.PhaseRequest()}[r.Response], first}
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
		title: locales.BlockedApps, add: locales.BlockAnApp,
		about: locales.StopAnAppsTrafficWhateverIt,
		hint:  locales.AddOneHereOrFromA,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.App(), Width: 180}, {Title: locales.BundleIdentifier()}, {Title: locales.ColumnAction(), Width: 140}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.BlockedApps, appID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.BlockedApps, id, appID).Enabled },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.BlockedApps, id, appID)
			return []string{r.AppName, cmp.Or(r.BundleID, locales.ByName()), map[string]string{rules.BlockDisplay: locales.BlockAndDisplay(), rules.BlockHide: locales.BlockAndHide()}[cmp.Or(r.Action, rules.BlockDisplay)]}
		},
		fresh:  func() any { return &rules.AppRule{ID: rules.NewID(), Enabled: true, Action: rules.BlockDisplay} },
		copyOf: func(d *rules.Data, id string) any { return clone(byID(d.BlockedApps, id, appID)) },
		form:   blockedAppForm,
		save:   func(d *rules.Data, v any) { d.BlockedApps = putByID(d.BlockedApps, v.(*rules.AppRule), appID) },
		remove: func(d *rules.Data, id string) { d.BlockedApps = dropByID(d.BlockedApps, id, appID) },
	}
	ruleKinds["protobuf"] = &ruleKind{
		title: locales.Protobuf, add: locales.NewRule, noun: locales.ProtobufRule,
		about: locales.DecodeMatchingFlowsProtobufBodiesAs,
		hint:  locales.AddOneHereOrChooseA,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.ColumnName(), Width: 150}, {Title: locales.ColumnMatchingRule()}, {Title: locales.PhaseRequest(), Width: 150}, {Title: locales.PhaseResponse(), Width: 150}}
		},
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
		title: locales.CustomServerCertificates, add: locales.AddCertificate,
		about: locales.PresentAServersOwnCertificateTo,
		empty: locales.NoCertificatesYet, hint: locales.AddAServersCertificateAndIts,
		columns: func() []ui.TableColumn {
			return []ui.TableColumn{{Title: locales.Hosts(), Width: 220}, {Title: locales.ColumnCertificate()}, {Title: locales.Format(), Width: 80}}
		},
		ids:     func(d *rules.Data) []string { return ids(d.ServerCerts, scID) },
		enabled: func(d *rules.Data, id string) *bool { return &byID(d.ServerCerts, id, scID).Enabled },
		cells: func(d *rules.Data, id string) []string {
			r := byID(d.ServerCerts, id, scID)
			hosts := cmp.Or(strings.Join(r.Hosts, ", "), locales.TheCertificatesNames())
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
	windowSpecs["bptemplates"] = windowSpec{locales.BreakpointTemplates, 860, 600}
	windowSpecs["blockedapps"] = windowSpec{locales.BlockedApps, 760, 500}
	windowSpecs["protobuf"] = windowSpec{locales.Protobuf, 900, 600}
	windowSpecs["servercerts"] = windowSpec{locales.CustomServerCertificates, 820, 540}
}

func templateTitle(r *rules.BreakpointTemplate) string {
	first, _, _ := strings.Cut(strings.TrimSpace(r.Raw), "\n")
	first = strings.TrimPrefix(strings.TrimPrefix(first, "HTTP/1.1 "), "HTTP/2 ")
	return cmp.Or(shorten(strings.TrimSuffix(first, " HTTP/1.1"), 60), locales.Template())
}

func templateForm(a *App, c *ui.Context, t *toolState) string {
	p := a.pal
	r := t.draft.(*rules.BreakpointTemplate)
	kind := map[bool]int{true: 1}[r.Response]
	ui.Form(c, func() {
		ui.Field(c, locales.ColumnName(), func() {
			ui.TextInput(c, &r.Name).Placeholder(locales.NamedAfterItsFirstLineWhen()).Label(locales.ColumnName()).AutoFocus()
		})
		ui.Field(c, locales.Kind(), func() {
			if ui.Segmented(c, &kind, locales.PhaseRequest(), locales.PhaseResponse()).Label(locales.TemplateKind()).AlignSelf(ui.Start).Changed() {
				r.Response = kind == 1
				if text := strings.TrimSpace(t.body.Buffer.String()); text == "" || strings.HasPrefix(text, "HTTP/") != r.Response {
					t.body.Buffer.Set(map[bool]string{true: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \n}", false: "POST /path HTTP/1.1\nContent-Type: application/json\n\n{\n  \n}"}[r.Response])
				}
			}
		}).Description(map[bool]string{true: locales.AtAPausedRequestAnswersIt(), false: locales.ReplacesAPausedRequestAPath()}[r.Response])
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
	display, hide := locales.BlockAndDisplayAnswer403(), locales.BlockAndHideDropTheConnection()
	action := map[string]string{rules.BlockDisplay: display, rules.BlockHide: hide}[cmp.Or(r.Action, rules.BlockDisplay)]
	var seen []string
	for name := range a.sourceTree().apps {
		seen = append(seen, name)
	}
	slices.Sort(seen)
	ui.Form(c, func() {
		ui.Field(c, locales.App(), func() {
			ui.Autocomplete(c, &r.AppName, seen).Placeholder("Safari").Label(locales.AppName()).AutoFocus()
		})
		ui.Field(c, locales.BundleIdentifier(), func() {
			ui.TextInput(c, &r.BundleID).Placeholder(locales.ComAppleSafariOptional()).Label(locales.BundleIdentifierLabel())
		}).Description(locales.WithOneTheAppIsBlocked())
		ui.Field(c, locales.ColumnAction(), func() {
			if ui.Select(c, &action, []string{display, hide}).Label(locales.ColumnAction()).Changed() {
				r.Action = map[bool]string{true: rules.BlockHide, false: rules.BlockDisplay}[action == hide]
			}
		})
	})
	if strings.TrimSpace(r.AppName) == "" && strings.TrimSpace(r.BundleID) == "" {
		return locales.EnterTheAppsNameOrBundle()
	}
	return ""
}

func protobufForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.ProtobufRule)
	invalid := a.matcherForm(c, t, &r.Name, &r.Matcher)
	raw := locales.RawFields()
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
	payloads := []string{locales.PayloadAutomatic(), locales.SingleMessage(), locales.LengthDelimitedMessages(), locales.GRPCFrames()}
	values := []string{"", "single", "delimited", "grpc"}
	payload := payloads[max(slices.Index(values, r.Payload), 0)]
	ui.Form(c, func() {
		ui.Field(c, locales.RequestType(), func() { picker(locales.RequestMessageType(), &r.RequestType) })
		ui.Field(c, locales.ResponseType(), func() { picker(locales.ResponseMessageType(), &r.ResponseType) }).Description(locales.ForWebSocketMessagesTheRequestType())
		ui.Field(c, locales.Payload(), func() {
			if ui.Select(c, &payload, payloads).Label(locales.Payload()).Width(240).Changed() {
				r.Payload = values[slices.Index(payloads, payload)]
			}
		}).Description(locales.AutomaticReadsGRPCsFramesForGRPC())
	})
	if len(a.schemas.Messages()) == 0 {
		ui.Text(c, locales.ImportAProtoFileOrA()).FontSize(11).TextColor(a.pal.yellow)
	}
	return invalid
}

func protobufSchemasMenu(a *App, c *ui.Context) {
	list := a.schemas.List()
	if ui.Button(c, locales.ImportSchemaEllipsis()).Tooltip(locales.ImportAProtoFileWithThe()).Clicked() {
		a.importSchema()
	}
	ui.MenuButton(c, locales.SchemasCount(len(list)), func(m *ui.Menu) {
		if len(list) == 0 {
			m.Item(locales.NoSchemasImported()).Disabled(true)
		}
		for _, s := range list {
			m.Submenu(s.Name, func(m *ui.Menu) {
				m.Item(s.Source).Disabled(true)
				m.Item(locales.ImportedAt(s.Imported)).Disabled(true)
				m.Separator()
				if m.Item(locales.Remove()).Chosen() {
					if err := a.schemas.Remove(s.ID); err != nil {
						a.toast(locales.CannotRemove(s.Name, err.Error()))
					}
				}
			})
		}
		if err := a.schemas.Err(); err != nil {
			m.Separator()
			m.Item(locales.TheSchemasDoNotLink(err.Error())).Disabled(true)
		}
	})
}

func (a *App) importSchema() {
	parent := a.windows["protobuf"]
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent: parent, Title: locales.ImportAProtobufSchema(), Multiple: true,
			Filters: []mygo.FileFilter{
				{Name: locales.ProtobufSchemas(), Extensions: []string{"proto", "desc", "pb", "binpb", "protoset"}},
				{Name: locales.AllFiles(), Extensions: []string{"*"}},
			},
		})
		if err != nil {
			return
		}
		for _, path := range paths {
			s, err := a.schemas.Import(path)
			a.do(func() {
				if err != nil {
					a.toast(locales.CannotImport(filepath.Base(path), err.Error()))
					return
				}
				a.toast(locales.ImportedName(s.Name))
			})
		}
	}()
}

func serverCertForm(a *App, c *ui.Context, t *toolState) string {
	r := t.draft.(*rules.ServerCertificate)
	hosts := strings.Join(r.Hosts, ", ")
	return a.certFields(c, t, "servercerts", func() {
		ui.Field(c, locales.Hosts(), func() {
			if ui.TextInput(c, &hosts).Placeholder("api.example.com, *.example.com").Label(locales.Hosts()).AutoFocus().Changed() {
				r.Hosts = nil
				for h := range strings.SplitSeq(hosts, ",") {
					if h = strings.TrimSpace(h); h != "" {
						r.Hosts = append(r.Hosts, h)
					}
				}
			}
		}).Description(locales.EmptyUsesTheNamesTheCertificate())
	}, &r.CertPath, &r.KeyPath, &r.P12Path, &r.PasswordRef, r.Hosts)
}

func (a *App) certFields(c *ui.Context, t *toolState, kind string, lead func(), certPath, keyPath, p12Path, ref *string, hosts []string) string {
	p := a.pal
	format := min(t.tab, 1)
	ui.Form(c, func() {
		lead()
		ui.Field(c, locales.Format(), func() {
			if ui.Segmented(c, &format, locales.PEMFiles(), "PKCS#12 (.p12)").Label(locales.Format()).AlignSelf(ui.Start).Changed() {
				t.tab = format
			}
		})
		file := func(label, placeholder string, v *string) {
			ui.Field(c, label, func() {
				ui.Row(c).Gap(6).Children(func() {
					ui.TextInput(c, v).Placeholder(placeholder).Label(label).Grow(1)
					if ui.Button(c, locales.ChooseEllipsis()).Clicked() {
						a.choosePath(kind, false, func(p string) { *v = p })
					}
				})
			})
		}
		if format == 0 {
			file(locales.Certificate(), locales.ServerPEMTheChainAfterThe(), certPath)
			file(locales.PrivateKey(), locales.ServerKeyPEMIfNotIn(), keyPath)
			return
		}
		file(locales.Bundle(), "server.p12", p12Path)
		ui.Field(c, locales.Password(), func() {
			placeholder := locales.TheBundlesPassword()
			if *ref != "" {
				placeholder = locales.KeptInTheKeychainTypeTo()
			}
			ui.TextInput(c, &t.secret).Placeholder(placeholder).Label(locales.BundlePassword()).Password()
		}).Description(locales.KeptInTheMacOSKeychainNever())
	})
	if format == 0 {
		*p12Path = ""
		if *certPath == "" {
			return locales.ChooseTheCertificate()
		}
	} else {
		*certPath, *keyPath = "", ""
		if *p12Path == "" {
			return locales.ChooseTheBundle()
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
		ui.Text(c, locales.CertificateSummary(leaf.Subject.CommonName, cmp.Or(names, locales.NoNames()), leaf.NotAfter)).FontSize(11).TextColor(p.muted).Wrap()
		for _, h := range hosts {
			if !certs.Covers(cert, strings.TrimPrefix(h, "*.")) && leaf.VerifyHostname(h) != nil {
				ui.Text(c, locales.CertificateNotValidFor(h)).FontSize(11).TextColor(p.yellow).Wrap()
			}
		}
		if time.Now().After(leaf.NotAfter) {
			ui.Text(c, locales.TheCertificateHasExpired()).FontSize(11).TextColor(p.yellow)
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
		return errors.New(locales.TheCertificateFileHoldsAKey())
	case strings.Contains(err.Error(), "found a certificate rather than a key"):
		return errors.New(locales.TheCertificateFileHoldsNoPrivate())
	case strings.Contains(err.Error(), "does not match"):
		return errors.New(locales.ThePrivateKeyIsNotThe())
	case strings.Contains(err.Error(), "failed to find any PEM data in key"):
		return errors.New(locales.TheKeyFileHoldsNoPEM())
	case strings.Contains(err.Error(), "failed to find any PEM data in certificate"), strings.Contains(err.Error(), "failed to find certificate PEM data"):
		return errors.New(locales.TheCertificateFileHoldsNoPEM())
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
	if problem != "" {
		problem = locales.FoldersNestDeepAtMost(rules.MaxFolderDepth)
	}
	ui.Field(c, locales.ColumnFolder(), func() {
		ui.Autocomplete(c, folder, folders).Placeholder(locales.None()).Label(locales.ColumnFolder())
	}).Description(locales.FolderDescription(rules.MaxFolderDepth)).Error(problem)
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
