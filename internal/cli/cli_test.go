package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxygo/internal/control"
	"proxygo/internal/control/hosttest"
	"proxygo/internal/mcp"
	"proxygo/internal/settings"
)

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pgc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func runTool(t *testing.T, dir string, stdin io.Reader, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	code := run(append([]string{"--data-dir", dir}, args...), "", stdin, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestInvoked(t *testing.T) {
	if args, ok := Invoked([]string{"/usr/local/bin/proxygo-cli", "status"}); !ok || len(args) != 1 {
		t.Error("by name")
	}
	if args, ok := Invoked([]string{"/Applications/ProxyGo.app/Contents/MacOS/ProxyGo", "cli", "proxy", "on"}); !ok || len(args) != 2 {
		t.Error("as ProxyGo cli")
	}
	if _, ok := Invoked([]string{"/Applications/ProxyGo.app/Contents/MacOS/ProxyGo"}); ok {
		t.Error("the app")
	}
	if _, ok := Invoked([]string{"/Applications/ProxyGo.app/Contents/MacOS/ProxyGo", "-NSDocumentRevisionsDebugMode", "YES"}); ok {
		t.Error("the app, with Cocoa's arguments")
	}
}

func TestCommands(t *testing.T) {
	dir := shortDir(t)
	if code, _, stderr := runTool(t, dir, nil, "status"); code != 1 || !strings.Contains(stderr, "not running") {
		t.Fatalf("without ProxyGo: %d %q", code, stderr)
	}
	h, err := hosttest.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := control.Serve(h, control.SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	code, out, _ := runTool(t, dir, nil, "proxy-host")
	if code != 0 || !strings.Contains(out, `"port": 9090`) {
		t.Errorf("proxy-host %d %s", code, out)
	}
	if code, _, _ := runTool(t, dir, nil, "proxy", "on"); code != 0 || !h.SystemProxy() {
		t.Error("proxy on")
	}
	if code, _, stderr := runTool(t, dir, nil, "proxy", "maybe"); code != 2 || !strings.Contains(stderr, "Usage") {
		t.Errorf("a bad argument: %d %s", code, stderr)
	}
	runTool(t, dir, nil, "http-version", "set", "http1_only")
	if _, out, _ := runTool(t, dir, nil, "http-version", "status"); !strings.Contains(out, "http1_only") {
		t.Errorf("http-version %s", out)
	}
	runTool(t, dir, nil, "map-remote", "off")
	runTool(t, dir, nil, "no-caching", "on")
	if d := h.R.Current(); d.ToolOn("mapremote") || !d.NoCaching {
		t.Error("tool switches")
	}
	runTool(t, dir, nil, "breakpoint", "open")
	if o := h.Opened(); len(o) != 1 || o[0] != "breakpoint" {
		t.Errorf("open %v", o)
	}
	code, out, stderr := runTool(t, dir, nil, "rules", "map-local", "create", `{"url":"https://api.dev/x","body":"{}"}`)
	if code != 0 {
		t.Fatalf("create %s", stderr)
	}
	var rule struct{ ID string }
	json.Unmarshal([]byte(out), &rule)
	rulePath := filepath.Join(t.TempDir(), "rule.json")
	os.WriteFile(rulePath, []byte(`{"status_code":418}`), 0o644)
	if code, _, stderr := runTool(t, dir, nil, "rules", "map-local", "update", rule.ID, "@"+rulePath); code != 0 || h.R.Current().MapLocal[0].StatusCode != 418 {
		t.Errorf("update from a file: %s", stderr)
	}
	if code, _, _ := runTool(t, dir, strings.NewReader(`{"url":"ads.dev"}`), "rules", "block-list", "create", "-"); code != 0 || len(h.R.Current().Block) != 1 {
		t.Error("create from standard input")
	}
	if code, _, _ := runTool(t, dir, nil, "rules", "map-local", "disable"); code != 0 || h.R.Current().ToolOn("maplocal") {
		t.Error("disable the tool")
	}
	runTool(t, dir, nil, "external-proxy", "enable", "--http", "corp:3128", "--pac", "http://wpad/p.pac")
	if up := h.R.Current().Upstream; !up.Enabled || up.HTTP != "corp:3128" || up.PACURL != "http://wpad/p.pac" {
		t.Errorf("external proxy %+v", up)
	}
	exported := filepath.Join(t.TempDir(), "rules.json")
	if code, _, stderr := runTool(t, dir, nil, "export", "--output", exported, "--mode", "enabledRules"); code != 0 {
		t.Errorf("export %s", stderr)
	}
	if b, _ := os.ReadFile(exported); !bytes.Contains(b, []byte("ads.dev")) {
		t.Error("exported rules")
	}
	log := filepath.Join(t.TempDir(), "log.har")
	if code, _, stderr := runTool(t, dir, nil, "export-log", "-o", log, "-f", "har", "--mode", "domains", "--domains", "a.dev", "b.dev"); code != 0 {
		t.Errorf("export-log %s", stderr)
	}
	if code, _, _ := runTool(t, dir, nil, "nope"); code != 2 {
		t.Error("an unknown command")
	}
}

func TestMCPCommands(t *testing.T) {
	dir := shortDir(t)
	if code, _, stderr := runTool(t, dir, nil, "mcp", "on"); code != 0 {
		t.Fatal(stderr)
	}
	if !settings.Open(filepath.Join(dir, "settings.json")).Get().MCP {
		t.Error("mcp on while closed")
	}
	if _, out, _ := runTool(t, dir, nil, "mcp", "config"); !strings.Contains(out, "claude mcp add proxygo -- ") || !strings.Contains(out, `"args"`) {
		t.Errorf("config %s", out)
	}
	h, _ := hosttest.New(t.TempDir())
	s := mcp.New(h, dir)
	if err := s.Start(false); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan int)
	go func() {
		var errOut bytes.Buffer
		done <- run([]string{"--data-dir", dir, "mcp-server"}, "", inR, outW, &errOut)
		outW.Close()
	}()
	io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`+"\n")
	line, err := bufio.NewReader(outR).ReadString('\n')
	if err != nil || !strings.Contains(line, `"serverInfo"`) || !strings.Contains(line, `"proxygo"`) {
		t.Errorf("bridge answered %q %v", line, err)
	}
	inW.Close()
	go io.Copy(io.Discard, outR)
	if code := <-done; code != 0 {
		t.Errorf("bridge exit %d", code)
	}
	s.Stop()
	launched := false
	orig := launch
	defer func() { launch = orig }()
	launch = func() error { launched = true; return os.ErrNotExist }
	if code, _, stderr := runTool(t, dir, strings.NewReader(""), "mcp-server"); code != 1 || !launched || !strings.Contains(stderr, "could not be opened") {
		t.Errorf("a closed ProxyGo is opened: %d %v %s", code, launched, stderr)
	}
	runTool(t, dir, nil, "mcp", "off")
	if code, _, stderr := runTool(t, dir, nil, "mcp-server"); code != 1 || !strings.Contains(stderr, "MCP server is off") {
		t.Errorf("MCP off: %s", stderr)
	}
	_ = net.Dial
}
