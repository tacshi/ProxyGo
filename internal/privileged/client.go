package privileged

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"proxygo/internal/systemproxy"
)

var ErrCanceled = errors.New("authorization canceled")

var (
	errUnreachable = errors.New("ProxyGo's helper is not running")
	errStale       = errors.New("ProxyGo's helper serves another copy of ProxyGo")
)

const installPrompt = "ProxyGo installs a helper so it can change the macOS proxy without asking for your password again."

var installMu sync.Mutex

func EnableProxy(cfg systemproxy.Config, before systemproxy.State) error {
	return do(Request{Op: "enable", Config: cfg, Before: before})
}
func DisableProxy() error                       { return do(Request{Op: "disable"}) }
func RestoreProxy(prev systemproxy.State) error { return do(Request{Op: "restore", State: prev}) }
func LinkCLI() error                            { return do(Request{Op: "link-cli"}) }

func Installed() bool {
	_, err := os.Stat(plistPath(Label()))
	return err == nil
}

func Uninstall() error {
	label := Label()
	err := call(label, Request{Op: "uninstall"})
	if !needsInstall(err) {
		return err
	}
	return runAdmin(strings.Join(removeCommands(label), " && "), "ProxyGo removes its helper.")
}

func needsInstall(err error) bool {
	return errors.Is(err, errUnreachable) || errors.Is(err, errStale)
}

func do(req Request) error {
	label := Label()
	if err := call(label, req); !needsInstall(err) {
		return err
	}
	installMu.Lock()
	defer installMu.Unlock()
	if err := call(label, req); !needsInstall(err) {
		return err
	}
	if err := install(label); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := call(label, req)
		if !errors.Is(err, errUnreachable) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func call(label string, req Request) error {
	c, err := net.DialTimeout("unix", socketPath(label), time.Second)
	if err != nil {
		return errUnreachable
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return errUnreachable
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return errUnreachable
	}
	switch {
	case resp.Stale:
		return errStale
	case resp.Error != "":
		return errors.New(resp.Error)
	}
	return nil
}

func install(label string) error {
	exe, err := executable()
	if err != nil {
		return err
	}
	tool, plist := toolPath(label), plistPath(label)
	next := tool + ".new"
	cmds := []string{
		"/bin/mkdir -p " + quote(toolDir),
		"{ /bin/launchctl bootout " + quote("system/"+label) + " 2>/dev/null || true; }",
		"/bin/rm -f " + quote(next),
		"/bin/cp -X " + quote(exe) + " " + quote(next),
		"/usr/sbin/chown root:wheel " + quote(next),
		"/bin/chmod 755 " + quote(next),
		"/bin/mv -f " + quote(next) + " " + quote(tool),
		"/bin/rm -f " + quote(plist),
		"/usr/bin/printf %s " + quote(daemonPlist(label, tool, os.Getuid())) + " > " + quote(plist),
		"/usr/sbin/chown root:wheel " + quote(plist),
		"/bin/chmod 644 " + quote(plist),
		"{ /bin/launchctl bootstrap system " + quote(plist) + " || { /bin/sleep 1 && /bin/launchctl bootstrap system " + quote(plist) + "; }; }",
	}
	return runAdmin(strings.Join(cmds, " && "), installPrompt)
}

func removeCommands(label string) []string {
	return []string{
		"{ /bin/launchctl bootout " + quote("system/"+label) + " 2>/dev/null || true; }",
		"/bin/rm -f " + quote(plistPath(label)) + " " + quote(toolPath(label)) + " " + quote(socketPath(label)),
	}
}

func runAdmin(script, prompt string) error {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace
	out, err := exec.Command("osascript", "-e", `do shell script "`+esc(script)+`" with prompt "`+esc(prompt)+`" with administrator privileges`).CombinedOutput() // #nosec G204 -- ProxyGo's own install commands, quoted for the shell and escaped for AppleScript.
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "User canceled") || strings.Contains(msg, "-128") {
			return ErrCanceled
		}
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
