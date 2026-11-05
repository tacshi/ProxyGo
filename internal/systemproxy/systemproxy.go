package systemproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type State struct {
	HTTP         bool     `json:"http,omitempty"`
	HTTPS        bool     `json:"https,omitempty"`
	SOCKS        bool     `json:"socks,omitempty"`
	Host         string   `json:"host,omitempty"`
	Port         int      `json:"port,omitempty"`
	SOCKSPort    int      `json:"socks_port,omitempty"`
	Bypass       []string `json:"bypass,omitempty"`
	AutoProxyURL string   `json:"auto_proxy_url,omitempty"`
}

func (s State) Enabled() bool { return s.HTTP || s.HTTPS }

func (s State) PointsAt(host string, port int) bool {
	return s.Enabled() && s.Port == port && sameHost(s.Host, host)
}

func sameHost(a, b string) bool {
	local := func(h string) bool { return h == "127.0.0.1" || h == "localhost" || h == "::1" }
	return a == b || local(a) && local(b)
}

func Status() State {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--proxy").Output()
	if err != nil {
		return State{}
	}
	return parseScutil(string(out))
}

func parseScutil(out string) State {
	values := map[string]string{}
	var bypass []string
	inExceptions := false
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExceptionsList") {
			inExceptions = true
			continue
		}
		if inExceptions {
			if line == "}" {
				inExceptions = false
				continue
			}
			if _, v, ok := strings.Cut(line, " : "); ok {
				bypass = append(bypass, strings.TrimSpace(v))
			}
			continue
		}
		if k, v, ok := strings.Cut(line, " : "); ok {
			values[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	st := State{
		HTTP:   values["HTTPEnable"] == "1",
		HTTPS:  values["HTTPSEnable"] == "1",
		SOCKS:  values["SOCKSEnable"] == "1",
		Bypass: bypass,
	}
	if values["ProxyAutoConfigEnable"] == "1" {
		st.AutoProxyURL = values["ProxyAutoConfigURLString"]
	}
	st.Host = values["HTTPSProxy"]
	if st.Host == "" || st.HTTP && !st.HTTPS {
		st.Host = values["HTTPProxy"]
	}
	st.Port, _ = strconv.Atoi(values["HTTPSPort"])
	if st.Port == 0 || st.HTTP && !st.HTTPS {
		st.Port, _ = strconv.Atoi(values["HTTPPort"])
	}
	st.SOCKSPort, _ = strconv.Atoi(values["SOCKSPort"])
	return st
}

type Config struct {
	Host      string
	Port      int
	SOCKSPort int
	Bypass    []string
}

func Enable(cfg Config) error {
	services, err := Services()
	if err != nil {
		return err
	}
	return run(EnableCommands(services, cfg))
}

func Disable() error {
	services, err := Services()
	if err != nil {
		return err
	}
	return run(DisableCommands(services))
}

func Restore(before Snapshot) error {
	services, err := Services()
	if err != nil {
		return err
	}
	return run(RestoreCommands(services, before))
}

func RestoreCommands(services []string, before Snapshot) []string {
	var cmds []string
	for _, name := range services {
		if s, ok := before[name]; ok {
			cmds = append(cmds, s.commands(name)...)
		} else {
			cmds = append(cmds, DisableCommands([]string{name})...)
		}
	}
	return cmds
}

type Endpoint struct {
	On   bool   `json:"on,omitzero"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitzero"`
}

type Service struct {
	Web     Endpoint `json:"web,omitzero"`
	Secure  Endpoint `json:"secure,omitzero"`
	SOCKS   Endpoint `json:"socks,omitzero"`
	Bypass  []string `json:"bypass,omitempty"`
	AutoURL string   `json:"auto_url,omitempty"`
	AutoOn  bool     `json:"auto_on,omitzero"`
}

type Snapshot map[string]Service

func (b Snapshot) Without(cfg Config) Snapshot {
	out := make(Snapshot, len(b))
	for name, s := range b {
		s.Web = s.Web.without(cfg.Host, cfg.Port)
		s.Secure = s.Secure.without(cfg.Host, cfg.Port)
		s.SOCKS = s.SOCKS.without(cfg.Host, cfg.SOCKSPort)
		out[name] = s
	}
	return out
}

func (e Endpoint) without(host string, port int) Endpoint {
	if e.Port == port && sameHost(e.Host, host) {
		e.On = false
	}
	return e
}

func (s Service) commands(name string) []string {
	q := quote(name)
	cmds := s.Web.commands("-setwebproxy", "-setwebproxystate", q)
	cmds = append(cmds, s.Secure.commands("-setsecurewebproxy", "-setsecurewebproxystate", q)...)
	cmds = append(cmds, s.SOCKS.commands("-setsocksfirewallproxy", "-setsocksfirewallproxystate", q)...)
	cmds = append(cmds, bypassCommand(q, s.Bypass))
	if s.AutoOn && s.AutoURL != "" {
		return append(cmds, "networksetup -setautoproxyurl "+q+" "+quote(s.AutoURL))
	}
	return append(cmds, "networksetup -setautoproxystate "+q+" off")
}

func (e Endpoint) commands(set, state, service string) []string {
	var cmds []string
	if e.Host != "" && e.Port > 0 {
		cmds = append(cmds, "networksetup "+set+" "+service+" "+quote(e.Host)+" "+strconv.Itoa(e.Port))
	}
	on := "off"
	if e.On {
		on = "on"
	}
	return append(cmds, "networksetup "+state+" "+service+" "+on)
}

func bypassCommand(service string, domains []string) string {
	list := "Empty"
	if len(domains) > 0 {
		quoted := make([]string, len(domains))
		for i, d := range domains {
			quoted[i] = quote(d)
		}
		list = strings.Join(quoted, " ")
	}
	return "networksetup -setproxybypassdomains " + service + " " + list
}

func Read() (Snapshot, error) {
	services, err := Services()
	if err != nil {
		return nil, err
	}
	out := make(Snapshot, len(services))
	for _, name := range services {
		s, err := readService(name)
		if err != nil {
			return nil, fmt.Errorf("reading the proxy settings of %s: %w", name, err)
		}
		out[name] = s
	}
	return out, nil
}

func readService(name string) (Service, error) {
	var s Service
	for flag, endpoint := range map[string]*Endpoint{"-getwebproxy": &s.Web, "-getsecurewebproxy": &s.Secure, "-getsocksfirewallproxy": &s.SOCKS} {
		out, err := query(flag, name)
		if err != nil {
			return s, err
		}
		if *endpoint, err = parseEndpoint(out); err != nil {
			return s, err
		}
	}
	out, err := query("-getproxybypassdomains", name)
	if err != nil {
		return s, err
	}
	s.Bypass = parseBypass(out)
	if out, err = query("-getautoproxyurl", name); err != nil {
		return s, err
	}
	s.AutoURL, s.AutoOn, err = parseAuto(out)
	return s, err
}

func query(flag, service string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", flag, service).Output() // #nosec G204 -- networksetup, given a service it listed.
	if err != nil {
		return "", fmt.Errorf("networksetup %s: %w", flag, err)
	}
	return string(out), nil
}

func fields(out string) map[string]string {
	values := map[string]string{}
	for line := range strings.Lines(out) {
		if k, v, ok := strings.Cut(line, ":"); ok {
			values[k] = strings.TrimSpace(v)
		}
	}
	return values
}

func parseEndpoint(out string) (Endpoint, error) {
	values := fields(out)
	on, ok := values["Enabled"]
	if !ok {
		return Endpoint{}, fmt.Errorf("unexpected proxy settings: %q", out)
	}
	e := Endpoint{On: on == "Yes", Host: values["Server"]}
	if e.Host == "(null)" {
		e.Host = ""
	}
	e.Port, _ = strconv.Atoi(values["Port"])
	return e, nil
}

func parseAuto(out string) (string, bool, error) {
	values := fields(out)
	on, ok := values["Enabled"]
	if !ok {
		return "", false, fmt.Errorf("unexpected auto proxy settings: %q", out)
	}
	url := values["URL"]
	if url == "(null)" {
		url = ""
	}
	return url, on == "Yes", nil
}

func parseBypass(out string) []string {
	if strings.HasPrefix(out, "There aren't any bypass domains") {
		return nil
	}
	return strings.Fields(out)
}

func EnableCommands(services []string, cfg Config) []string {
	var cmds []string
	port := strconv.Itoa(cfg.Port)
	for _, s := range services {
		q := quote(s)
		cmds = append(cmds,
			"networksetup -setwebproxy "+q+" "+quote(cfg.Host)+" "+port,
			"networksetup -setsecurewebproxy "+q+" "+quote(cfg.Host)+" "+port,
		)
		if cfg.SOCKSPort > 0 {
			cmds = append(cmds, "networksetup -setsocksfirewallproxy "+q+" "+quote(cfg.Host)+" "+strconv.Itoa(cfg.SOCKSPort))
		} else {
			cmds = append(cmds, "networksetup -setsocksfirewallproxystate "+q+" off")
		}
		cmds = append(cmds, "networksetup -setautoproxystate "+q+" off", bypassCommand(q, cfg.Bypass))
	}
	return cmds
}

func DisableCommands(services []string) []string {
	var cmds []string
	for _, s := range services {
		q := quote(s)
		cmds = append(cmds,
			"networksetup -setwebproxystate "+q+" off",
			"networksetup -setsecurewebproxystate "+q+" off",
			"networksetup -setsocksfirewallproxystate "+q+" off",
		)
	}
	return cmds
}

func run(cmds []string) error {
	if len(cmds) == 0 {
		return errors.New("no network services found")
	}
	out, err := exec.Command("/bin/sh", "-c", strings.Join(cmds, " && ")).CombinedOutput() // #nosec G204 -- networksetup commands with every value quoted.
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

func Services() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	return parseServices(string(out)), nil
}

func parseServices(out string) []string {
	var services []string
	for i, line := range slices.Collect(strings.SplitSeq(out, "\n")) {
		line = strings.TrimSpace(line)
		if i == 0 && strings.HasPrefix(line, "An asterisk") || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

type Saved struct {
	Before Snapshot `json:"services,omitempty"`
	Host   string   `json:"host"`
	Port   int      `json:"port"`
}

func Save(path string, s Saved) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func Load(path string) (Saved, bool) {
	b, err := os.ReadFile(path) // #nosec G304 -- ProxyGo's own record of the system proxy settings.
	if err != nil {
		return Saved{}, false
	}
	var s Saved
	if json.Unmarshal(b, &s) != nil {
		return Saved{}, false
	}
	return s, true
}

func Forget(path string) { _ = os.Remove(path) }
