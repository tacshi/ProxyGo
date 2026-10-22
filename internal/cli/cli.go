package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"proxygo/internal/control"
	"proxygo/internal/settings"
)

const Name = "proxygo-cli"

func Invoked(args []string) ([]string, bool) {
	if len(args) == 0 {
		return nil, false
	}
	if filepath.Base(args[0]) == Name {
		return args[1:], true
	}
	if len(args) > 1 && args[1] == "cli" {
		return args[2:], true
	}
	return nil, false
}

func DataDir() string {
	if d := os.Getenv("PROXYGO_DATA_DIR"); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "ProxyGo")
}

type tool struct {
	dir            string
	stdin          io.Reader
	stdout, stderr io.Writer
}

func Main(args []string) int {
	return run(args, DataDir(), os.Stdin, os.Stdout, os.Stderr)
}

func run(args []string, dir string, stdin io.Reader, stdout, stderr io.Writer) int {
	for i := 0; i < len(args); i++ {
		if v, ok := strings.CutPrefix(args[i], "--data-dir="); ok {
			dir, args = v, slices.Delete(slices.Clone(args), i, i+1)
			i--
		} else if args[i] == "--data-dir" && i+1 < len(args) {
			dir, args = args[i+1], slices.Delete(slices.Clone(args), i, i+2)
			i--
		}
	}
	t := &tool{dir: dir, stdin: stdin, stdout: stdout, stderr: stderr}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if err := t.dispatch(args[0], args[1:]); err != nil {
		var u usageError
		if errors.As(err, &u) {
			fmt.Fprintf(stderr, "%s: %v\n\n%s", Name, err, usage)
			return 2
		}
		fmt.Fprintf(stderr, "%s: %v\n", Name, err)
		return 1
	}
	return 0
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

const usage = `Usage: proxygo-cli <command> [arguments]

ProxyGo:
  status                         ProxyGo's state, as JSON
  proxy-host                     the proxy's address and port, as JSON
  proxy on|off                   point macOS at ProxyGo, or give its proxy back
  recording on|off               record traffic, or pause
  http-version status            the HTTP version policy, as JSON
  http-version set <mode>        http1_only or prefer_http2
  clear-session                  remove every flow
  export-log --output <file>     write the session: --format proxygosession (default),
                                 har, raw, csv, postman, openapi or openapi-html;
                                 --mode all|domains --domains <host> …; --since <flow id>

Tools:
  <tool> on|off|open             breakpoint, maplocal, map-remote, scripting, block-list,
                                 allow-list, reverse-proxy, network-condition,
                                 no-caching, dns-spoofing, ssl-proxying
  external-proxy enable [--http <host:port>] [--https <host:port>] [--pac <url>]
  external-proxy disable|open
  rules <tool> list              the tool's rules, as JSON (tools: block-list,
  rules <tool> get <id>          allow-list, ssl-proxying, map-local, map-remote,
  rules <tool> create <json>     breakpoint, scripting, network-condition,
  rules <tool> update <id> <json>  reverse-proxy, protobuf, dns-spoofing);
  rules <tool> delete <id>       a rule is JSON as the rules file has it, or @file
  rules <tool> enable|disable [<id>]
  export --output <file> [--mode all|enabledRules]
  import --input <file> [--mode append|override]

Certificates:
  install-root-cert <p12> [--password <pw>]   use a root of your own, and trust it
  custom-cert add server|client <p12> [--password <pw>] [--host <host>]
  custom-cert replace server|client <p12> [--password <pw>] [--host <host>]
  custom-cert remove server|client [--id <id>]

MCP (Model Context Protocol):
  mcp on|off                     serve MCP to AI assistants; works while ProxyGo is closed
  mcp status                     whether MCP is on, as JSON
  mcp config                     how to add ProxyGo to Claude, Cursor and others
  mcp-server                     the stdio server MCP clients run: a bridge to ProxyGo

  --data-dir <folder>            talk to the ProxyGo keeping its data there
`

func (t *tool) sock() string { return control.SocketPath(t.dir) }

func (t *tool) call(method string, params any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := control.Dial(ctx, t.sock(), method, params)
	if err != nil {
		return err
	}
	if len(out) > 0 && string(out) != "null" {
		var b bytes.Buffer
		if json.Indent(&b, out, "", "  ") == nil {
			out = b.Bytes()
		}
		fmt.Fprintln(t.stdout, string(out))
	}
	return nil
}

func onOff(args []string, extra ...string) (string, error) {
	if len(args) != 1 {
		return "", usagef("expected on or off")
	}
	choices := append([]string{"on", "off"}, extra...)
	if !slices.Contains(choices, args[0]) {
		return "", usagef("expected %s, not %q", strings.Join(choices, " or "), args[0])
	}
	return args[0], nil
}

func (t *tool) dispatch(cmd string, args []string) error {
	switch cmd {
	case "status":
		return t.call("status", nil)
	case "proxy-host":
		return t.call("proxy.host", nil)
	case "proxy", "recording":
		mode, err := onOff(args)
		if err != nil {
			return err
		}
		method := map[string]string{"proxy": "proxy.set", "recording": "recording.set"}[cmd]
		return t.call(method, map[string]bool{"on": mode == "on"})
	case "http-version":
		switch {
		case len(args) == 1 && args[0] == "status":
			return t.call("http.version", nil)
		case len(args) == 2 && args[0] == "set":
			return t.call("http.version.set", map[string]string{"mode": args[1]})
		}
		return usagef("http-version status, or http-version set http1_only|prefer_http2")
	case "clear-session":
		return t.call("session.clear", nil)
	case "export-log":
		f, err := parseFlags(args, "output", "o", "format", "f", "mode", "m", "domains", "d", "since", "s")
		if err != nil {
			return err
		}
		out := f.get("output", "o")
		if out == "" {
			return usagef("export-log needs --output")
		}
		abs, err := filepath.Abs(out)
		if err != nil {
			return err
		}
		domains := f.all("domains", "d")
		if mode := f.get("mode", "m"); mode == "domains" && len(domains) == 0 {
			return usagef("--mode domains needs --domains")
		} else if mode == "all" {
			domains = nil
		}
		return t.call("session.export", map[string]any{"path": abs, "format": f.get("format", "f"), "domains": domains, "since": f.get("since", "s")})
	case "external-proxy":
		if len(args) == 0 {
			return usagef("external-proxy enable|disable|open")
		}
		switch args[0] {
		case "open":
			return t.call("open", map[string]string{"window": "settings:proxy"})
		case "disable":
			return t.call("external.set", map[string]any{"on": false})
		case "enable":
			f, err := parseFlags(args[1:], "http", "", "https", "", "pac", "")
			if err != nil {
				return err
			}
			p := map[string]any{"on": true}
			for _, k := range []string{"http", "https", "pac"} {
				if v, ok := f.lookup(k); ok {
					p[k] = v
				}
			}
			return t.call("external.set", p)
		}
		return usagef("external-proxy enable|disable|open")
	case "rules":
		return t.rules(args)
	case "export", "import":
		f, err := parseFlags(args, "output", "o", "input", "i", "mode", "m")
		if err != nil {
			return err
		}
		if cmd == "export" {
			out := f.get("output", "o")
			if out == "" {
				return usagef("export needs --output")
			}
			abs, _ := filepath.Abs(out)
			return t.call("rules.export", map[string]any{"path": abs, "enabledOnly": f.get("mode", "m") == "enabledRules"})
		}
		in := f.get("input", "i")
		if in == "" {
			return usagef("import needs --input")
		}
		abs, _ := filepath.Abs(in)
		return t.call("rules.import", map[string]any{"path": abs, "override": f.get("mode", "m") == "override"})
	case "install-root-cert":
		f, err := parseFlags(args, "password", "p")
		if err != nil {
			return err
		}
		if len(f.args) != 1 {
			return usagef("install-root-cert <file.p12>")
		}
		abs, _ := filepath.Abs(f.args[0])
		if err := t.call("cert.install-root", map[string]string{"path": abs, "password": f.get("password", "p")}); err != nil {
			return err
		}
		return t.call("cert.trust", nil)
	case "custom-cert":
		if len(args) < 2 {
			return usagef("custom-cert add|remove|replace server|client …")
		}
		op, kind := args[0], args[1]
		f, err := parseFlags(args[2:], "password", "p", "host", "", "id", "")
		if err != nil {
			return err
		}
		p := control.CertParams{Kind: kind, Password: f.get("password", "p"), Host: f.get("host", ""), ID: f.get("id", "")}
		if op != "remove" {
			if len(f.args) != 1 {
				return usagef("custom-cert %s %s <file.p12>", op, kind)
			}
			p.Path, _ = filepath.Abs(f.args[0])
		}
		return t.call("cert."+op, p)
	case "mcp":
		return t.mcp(args)
	case "mcp-server":
		return t.bridge()
	case "version", "--version":
		return t.call("status", nil)
	}
	if _, ok := control.Tools[cmd]; ok {
		mode, err := onOff(args, "open")
		if err != nil {
			return err
		}
		if mode == "open" {
			return t.call("open", map[string]string{"window": cmd})
		}
		return t.call("tool.set", map[string]any{"tool": cmd, "on": mode == "on"})
	}
	return usagef("unknown command %q", cmd)
}

func (t *tool) rules(args []string) error {
	if len(args) < 2 {
		return usagef("rules <tool> list|get|create|update|delete|enable|disable")
	}
	tool, op, rest := args[0], args[1], args[2:]
	p := map[string]any{"tool": tool}
	readRule := func(s string) (json.RawMessage, error) {
		if path, ok := strings.CutPrefix(s, "@"); ok {
			b, err := os.ReadFile(path)
			return b, err
		}
		if s == "-" {
			return io.ReadAll(t.stdin)
		}
		if !json.Valid([]byte(s)) {
			return nil, usagef("the rule is not JSON")
		}
		return json.RawMessage(s), nil
	}
	switch op {
	case "list":
	case "get", "delete":
		if len(rest) != 1 {
			return usagef("rules %s %s <id>", tool, op)
		}
		p["id"] = rest[0]
	case "create":
		if len(rest) != 1 {
			return usagef("rules %s create <json>", tool)
		}
		r, err := readRule(rest[0])
		if err != nil {
			return err
		}
		p["rule"] = r
	case "update":
		if len(rest) != 2 {
			return usagef("rules %s update <id> <json>", tool)
		}
		r, err := readRule(rest[1])
		if err != nil {
			return err
		}
		p["id"], p["rule"] = rest[0], r
	case "enable", "disable":
		if len(rest) == 0 {
			if _, ok := control.Tools[tool]; !ok {
				return usagef("%s cannot be switched as a whole: name a rule", tool)
			}
			return t.call("tool.set", map[string]any{"tool": tool, "on": op == "enable"})
		}
		p["id"] = rest[0]
	case "folders":
		return errors.New("rule folders are set on each rule: update its folder")
	default:
		return usagef("unknown rules operation %q", op)
	}
	return t.call("rules."+op, p)
}

func (t *tool) mcp(args []string) error {
	if len(args) == 1 && args[0] == "config" {
		fmt.Fprint(t.stdout, MCPConfig())
		return nil
	}
	if len(args) == 1 && args[0] == "status" {
		on := settings.Open(filepath.Join(t.dir, "settings.json")).Get().MCP
		running := false
		if c, err := net.Dial("unix", control.MCPSocketPath(t.dir)); err == nil {
			c.Close()
			running = true
		}
		b, _ := json.MarshalIndent(map[string]bool{"enabled": on, "serving": running}, "", "  ")
		fmt.Fprintln(t.stdout, string(b))
		return nil
	}
	mode, err := onOff(args, "status", "config")
	if err != nil {
		return err
	}
	err = t.call("mcp.set", map[string]bool{"on": mode == "on"})
	if !errors.Is(err, control.ErrNotRunning) {
		return err
	}
	return settings.Open(filepath.Join(t.dir, "settings.json")).Update(func(s *settings.Settings) { s.MCP = mode == "on" })
}

func executable() string {
	p, err := os.Executable()
	if err != nil {
		return Name
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	return p
}

func MCPCommand() []string {
	exe := executable()
	if filepath.Base(exe) == Name {
		return []string{exe, "mcp-server"}
	}
	return []string{exe, "cli", "mcp-server"}
}

func MCPConfig() string {
	cmd := MCPCommand()
	args, _ := json.Marshal(cmd[1:])
	quoted := make([]string, len(cmd))
	for i, c := range cmd {
		quoted[i] = shellQuote(c)
	}
	return fmt.Sprintf(`Claude Code:
  claude mcp add proxygo -- %s

Claude Desktop, Cursor, Windsurf and other clients, in their MCP servers JSON:
  "proxygo": {
    "command": %q,
    "args": %s
  }

Turn MCP on first: proxygo-cli mcp on, or Settings › Automation.
`, strings.Join(quoted, " "), cmd[0], args)
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " '\"\\$`!*?;&|<>()[]{}#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (t *tool) bridge() error {
	path := control.MCPSocketPath(t.dir)
	conn, err := net.Dial("unix", path)
	if err != nil {
		on := settings.Open(filepath.Join(t.dir, "settings.json")).Get().MCP
		if !on {
			return errors.New("ProxyGo's MCP server is off: turn it on in ProxyGo's Settings › Automation, or run proxygo-cli mcp on")
		}
		if _, err := net.Dial("unix", t.sock()); err == nil {
			return errors.New("ProxyGo is running, but its MCP server is not: turn it on in Settings › Automation")
		}
		if err := launch(); err != nil {
			return fmt.Errorf("ProxyGo is not running and could not be opened: %w", err)
		}
		deadline := time.Now().Add(20 * time.Second)
		for conn == nil && time.Now().Before(deadline) {
			time.Sleep(200 * time.Millisecond)
			conn, _ = net.Dial("unix", path)
		}
		if conn == nil {
			return errors.New("ProxyGo did not start its MCP server: open ProxyGo and check Settings › Automation")
		}
	}
	defer conn.Close()
	go func() {
		_, _ = io.Copy(conn, t.stdin)
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	_, _ = io.Copy(t.stdout, conn)
	return nil
}

var launch = func() error {
	exe := executable()
	if i := strings.Index(exe, ".app/"); i >= 0 {
		return exec.Command("open", "-g", exe[:i+4]).Run()
	}
	return exec.Command("open", "-g", "-a", "ProxyGo").Run()
}

type flags struct {
	values map[string][]string
	args   []string
}

func parseFlags(args []string, names ...string) (flags, error) {
	f := flags{values: map[string][]string{}}
	known := map[string]string{}
	for i := 0; i < len(names); i += 2 {
		known[names[i]] = names[i]
		if names[i+1] != "" {
			known[names[i+1]] = names[i]
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			f.args = append(f.args, a)
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		long, ok := known[name]
		if !ok {
			return f, usagef("unknown option %s", a)
		}
		if !hasValue {
			if i+1 >= len(args) {
				return f, usagef("%s needs a value", a)
			}
			i++
			value = args[i]
		}
		f.values[long] = append(f.values[long], value)
		if long == "domains" {
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				f.values[long] = append(f.values[long], args[i])
			}
		}
	}
	return f, nil
}

func (f flags) get(long, _ string) string {
	if v := f.values[long]; len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

func (f flags) lookup(long string) (string, bool) {
	v, ok := f.values[long]
	if !ok || len(v) == 0 {
		return "", false
	}
	return v[len(v)-1], true
}

func (f flags) all(long, _ string) []string { return f.values[long] }
