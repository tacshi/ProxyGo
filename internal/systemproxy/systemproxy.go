package systemproxy

import (
	"context"
	"encoding/json"
	"errors"
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
	if !s.Enabled() || s.Port != port {
		return false
	}
	local := func(h string) bool { return h == "127.0.0.1" || h == "localhost" || h == "::1" }
	return s.Host == host || local(s.Host) && local(host)
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
		Host:   values["HTTPSProxy"],
		Bypass: bypass,
	}
	if values["ProxyAutoConfigEnable"] == "1" {
		st.AutoProxyURL = values["ProxyAutoConfigURLString"]
	}
	if st.Host == "" {
		st.Host = values["HTTPProxy"]
	}
	st.Port, _ = strconv.Atoi(values["HTTPSPort"])
	if st.Port == 0 {
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

func Restore(prev State) error {
	services, err := Services()
	if err != nil {
		return err
	}
	return run(RestoreCommands(services, prev))
}

func RestoreCommands(services []string, prev State) []string {
	var cmds []string
	if !prev.Enabled() {
		cmds = DisableCommands(services)
	} else {
		cfg := Config{Host: prev.Host, Port: prev.Port, Bypass: prev.Bypass}
		if prev.SOCKS {
			cfg.SOCKSPort = prev.SOCKSPort
		}
		cmds = EnableCommands(services, cfg)
	}
	if prev.AutoProxyURL != "" {
		for _, s := range services {
			cmds = append(cmds, "networksetup -setautoproxyurl "+quote(s)+" "+quote(prev.AutoProxyURL))
		}
	}
	return cmds
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
		cmds = append(cmds, "networksetup -setautoproxystate "+q+" off")
		bypass := "Empty"
		if len(cfg.Bypass) > 0 {
			quoted := make([]string, len(cfg.Bypass))
			for i, b := range cfg.Bypass {
				quoted[i] = quote(b)
			}
			bypass = strings.Join(quoted, " ")
		}
		cmds = append(cmds, "networksetup -setproxybypassdomains "+q+" "+bypass)
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
	out, err := exec.Command("/bin/sh", "-c", strings.Join(cmds, " && ")).CombinedOutput()
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
	Before State  `json:"before"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

func Save(path string, s Saved) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func Load(path string) (Saved, bool) {
	b, err := os.ReadFile(path)
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
