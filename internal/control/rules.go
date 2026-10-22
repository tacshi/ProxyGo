package control

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"

	"proxygo/internal/certs"
	"proxygo/internal/rules"
)

var Tools = map[string]string{
	"breakpoint": rules.ToolBreakpoint, "maplocal": rules.ToolMapLocal, "map-local": rules.ToolMapLocal,
	"map-remote": rules.ToolMapRemote, "scripting": rules.ToolScripting, "block-list": rules.ToolBlock,
	"allow-list": rules.ToolAllow, "reverse-proxy": rules.ToolReverse, "network-condition": rules.ToolNetwork,
	"dns-spoofing": rules.ToolDNS, "no-caching": "no-caching", "ssl-proxying": "ssl-proxying",
}

func SetTool(s *rules.Store, name string, on bool) error {
	id, ok := Tools[name]
	if !ok {
		return fmt.Errorf("unknown tool %q", name)
	}
	s.Update(func(d *rules.Data) {
		switch id {
		case "no-caching":
			d.NoCaching = on
		case "ssl-proxying":
			d.SSL.Enabled = on
		default:
			if d.DisabledTools == nil {
				d.DisabledTools = map[string]bool{}
			}
			if on {
				delete(d.DisabledTools, id)
			} else {
				d.DisabledTools[id] = true
			}
		}
	})
	return nil
}

func ToolStatus(d *rules.Data) map[string]bool {
	out := map[string]bool{"no-caching": d.NoCaching, "ssl-proxying": d.SSL.Enabled, "external-proxy": d.Upstream.Enabled}
	for name, id := range Tools {
		if name == "maplocal" || id == "no-caching" || id == "ssl-proxying" {
			continue
		}
		out[name] = d.ToolOn(id)
	}
	return out
}

var ruleLists = map[string]string{
	"block-list": "Block", "allow-list": "Allow", "ssl-proxying": "SSL.Rules", "map-local": "MapLocal",
	"map-remote": "MapRemote", "breakpoint": "Breakpoints", "scripting": "Scripts",
	"network-condition": "NetworkConditions", "reverse-proxy": "ReverseProxies", "protobuf": "Protobuf",
	"dns-spoofing": "DNS", "blocked-apps": "BlockedApps", "client-certificates": "ClientCerts",
	"server-certificates": "ServerCerts", "breakpoint-templates": "BreakpointTemplates",
}

func RuleTools() []string {
	names := make([]string, 0, len(ruleLists))
	for n := range ruleLists {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func list(d *rules.Data, tool string) (reflect.Value, error) {
	field, ok := ruleLists[tool]
	if !ok {
		return reflect.Value{}, fmt.Errorf("unknown rules %q: use %s", tool, strings.Join(RuleTools(), ", "))
	}
	v := reflect.ValueOf(d).Elem()
	for name := range strings.SplitSeq(field, ".") {
		v = v.FieldByName(name)
	}
	return v, nil
}

func ruleID(r reflect.Value) string { return r.Elem().FieldByName("ID").String() }

func RuleCall(s *rules.Store, op, tool, id string, rule []byte) (any, error) {
	snap := s.Snapshot()
	l, err := list(&snap, tool)
	if err != nil {
		return nil, err
	}
	find := func(l reflect.Value) (int, error) {
		for i := range l.Len() {
			if !l.Index(i).IsNil() && ruleID(l.Index(i)) == id {
				return i, nil
			}
		}
		return -1, fmt.Errorf("no %s rule %q", tool, id)
	}
	switch op {
	case "list":
		return l.Interface(), nil
	case "get":
		i, err := find(l)
		if err != nil {
			return nil, err
		}
		return l.Index(i).Interface(), nil
	}
	var out any
	var opErr error
	s.Update(func(d *rules.Data) {
		l, _ := list(d, tool)
		switch op {
		case "create":
			r := reflect.New(l.Type().Elem().Elem())
			if f := r.Elem().FieldByName("Enabled"); f.IsValid() {
				f.SetBool(true)
			}
			if err := json.Unmarshal(rule, r.Interface()); err != nil {
				opErr = fmt.Errorf("bad rule: %w", err)
				return
			}
			if f := r.Elem().FieldByName("ID"); f.String() == "" || slices.ContainsFunc(ruleIDs(l), func(x string) bool { return x == f.String() }) {
				f.SetString(rules.NewID())
			}
			if opErr = validRule(r.Interface()); opErr != nil {
				return
			}
			l.Set(reflect.Append(l, r))
			out = r.Interface()
		case "update", "delete", "enable", "disable":
			i, err := find(l)
			if err != nil {
				opErr = err
				return
			}
			r := l.Index(i)
			switch op {
			case "update":
				keep := ruleID(r)
				cp := reflect.New(r.Elem().Type())
				cp.Elem().Set(r.Elem())
				if err := json.Unmarshal(rule, cp.Interface()); err != nil {
					opErr = fmt.Errorf("bad rule: %w", err)
					return
				}
				cp.Elem().FieldByName("ID").SetString(keep)
				if opErr = validRule(cp.Interface()); opErr != nil {
					return
				}
				r.Elem().Set(cp.Elem())
				out = r.Interface()
			case "delete":
				l.Set(reflect.AppendSlice(l.Slice(0, i), l.Slice(i+1, l.Len())))
				out = map[string]string{"deleted": id}
			default:
				f := r.Elem().FieldByName("Enabled")
				if !f.IsValid() {
					opErr = fmt.Errorf("%s rules cannot be switched", tool)
					return
				}
				f.SetBool(op == "enable")
				out = r.Interface()
			}
		default:
			opErr = fmt.Errorf("unknown operation %q", op)
		}
	})
	if opErr != nil {
		return nil, opErr
	}
	return out, nil
}

func ruleIDs(l reflect.Value) []string {
	var out []string
	for i := range l.Len() {
		if !l.Index(i).IsNil() {
			out = append(out, ruleID(l.Index(i)))
		}
	}
	return out
}

func validRule(r any) error {
	v := reflect.ValueOf(r).Elem()
	if m := v.FieldByName("Matcher"); m.IsValid() {
		if msg := m.Interface().(rules.Matcher).Valid(); msg != "" {
			return errors.New(msg)
		}
	}
	if sr, ok := r.(*rules.SSLRule); ok && strings.TrimSpace(sr.Target) == "" {
		return errors.New("enter the host to decrypt")
	}
	if dr, ok := r.(*rules.DNSRule); ok && (dr.Host == "" || dr.IP == "") {
		return errors.New("a DNS Spoofing rule needs a host and an address")
	}
	return nil
}

func ExportRules(s *rules.Store, path string, enabledOnly bool) error {
	if !enabledOnly {
		return s.Export(path)
	}
	d := s.Snapshot()
	for _, tool := range RuleTools() {
		l, _ := list(&d, tool)
		kept := reflect.MakeSlice(l.Type(), 0, l.Len())
		for i := range l.Len() {
			r := l.Index(i)
			if r.IsNil() {
				continue
			}
			if f := r.Elem().FieldByName("Enabled"); f.IsValid() && !f.Bool() {
				continue
			}
			kept = reflect.Append(kept, r)
		}
		l.Set(kept)
	}
	b, err := json.Marshal(d, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func ImportRules(s *rules.Store, path string, override bool) error {
	if override {
		return s.Import(path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var in rules.Data
	if err := json.Unmarshal(b, &in); err != nil {
		return fmt.Errorf("not a ProxyGo settings file: %w", err)
	}
	s.Update(func(d *rules.Data) {
		for _, tool := range RuleTools() {
			from, _ := list(&in, tool)
			to, _ := list(d, tool)
			have := ruleIDs(to)
			for i := range from.Len() {
				r := from.Index(i)
				if r.IsNil() {
					continue
				}
				if f := r.Elem().FieldByName("ID"); slices.Contains(have, f.String()) || f.String() == "" {
					f.SetString(rules.NewID())
				}
				to.Set(reflect.Append(to, r))
			}
		}
	})
	return nil
}

type CertParams struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Password string `json:"password"`
	Host     string `json:"host"`
	ID       string `json:"id"`
}

func CertCall(h Host, op string, p CertParams) (any, error) {
	if p.Kind != "server" && p.Kind != "client" {
		return nil, errors.New("the kind is server or client")
	}
	s := h.Rules()
	remove := func(d *rules.Data, id string) {
		if p.Kind == "server" {
			d.ServerCerts = slices.DeleteFunc(d.ServerCerts, func(c *rules.ServerCertificate) bool {
				if id == "" || c.ID == id {
					_ = certs.Keychain.Delete(c.PasswordRef)
					return true
				}
				return false
			})
			return
		}
		d.ClientCerts = slices.DeleteFunc(d.ClientCerts, func(c *rules.ClientCertificate) bool {
			if id == "" || c.ID == id {
				if c.PasswordRef != "" {
					_ = certs.Keychain.Delete(c.PasswordRef)
				}
				return true
			}
			return false
		})
	}
	if op == "remove" {
		s.Update(func(d *rules.Data) { remove(d, p.ID) })
		return nil, nil
	}
	if op != "add" && op != "replace" {
		return nil, fmt.Errorf("unknown operation %q", op)
	}
	if p.Kind == "client" && strings.TrimSpace(p.Host) == "" {
		return nil, errors.New("a client certificate needs its server's host")
	}
	if _, err := certs.LoadP12(p.Path, p.Password); err != nil {
		return nil, err
	}
	id := rules.NewID()
	ref := "custom-cert-" + id
	if err := certs.Keychain.Set(ref, p.Password); err != nil {
		return nil, err
	}
	var out any
	s.Update(func(d *rules.Data) {
		if op == "replace" {
			remove(d, "")
		}
		if p.Kind == "server" {
			sc := &rules.ServerCertificate{ID: id, Enabled: true, P12Path: p.Path, PasswordRef: ref}
			for h := range strings.SplitSeq(p.Host, ",") {
				if h = strings.TrimSpace(h); h != "" {
					sc.Hosts = append(sc.Hosts, h)
				}
			}
			d.ServerCerts = append(d.ServerCerts, sc)
			out = sc
			return
		}
		cc := &rules.ClientCertificate{ID: id, Enabled: true, Host: strings.TrimSpace(p.Host), P12Path: p.Path, PasswordRef: ref}
		d.ClientCerts = append(d.ClientCerts, cc)
		out = cc
	})
	return out, nil
}
