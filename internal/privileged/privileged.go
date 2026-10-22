package privileged

import (
	"cmp"
	"html"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"proxygo/internal/clientinfo"
	"proxygo/internal/systemproxy"
)

const Arg = "privileged-helper"

const (
	toolDir   = "/Library/PrivilegedHelperTools"
	daemonDir = "/Library/LaunchDaemons"
	runDir    = "/var/run"
)

func toolPath(label string) string   { return filepath.Join(toolDir, label) }
func bundlePath(label string) string { return filepath.Join(toolDir, label+".app") }
func plistPath(label string) string  { return filepath.Join(daemonDir, label+".plist") }
func socketPath(label string) string { return filepath.Join(runDir, label+".socket") }

type Request struct {
	Op     string             `json:"op"`
	Config systemproxy.Config `json:"config,omitzero"`
	State  systemproxy.State  `json:"state,omitzero"`
	Before systemproxy.State  `json:"before,omitzero"`
}

type Response struct {
	Error string `json:"error,omitempty"`
	Stale bool   `json:"stale,omitempty"`
}

func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

func appBundle(exe string) string {
	macOS := filepath.Dir(exe)
	contents := filepath.Dir(macOS)
	app := filepath.Dir(contents)
	if filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || filepath.Ext(app) != ".app" {
		return ""
	}
	return app
}

const (
	appID    = "app.capyvibe.proxygo"
	formerID = "com.example.proxygo"
)

var Label = sync.OnceValue(func() string {
	exe, _ := executable()
	return cmp.Or(clientinfo.BundleID(exe), appID) + ".helper"
})

func formerLabel(label string) string {
	if rest, ok := strings.CutPrefix(label, appID); ok {
		return formerID + rest
	}
	return ""
}

func daemonPlist(label, tool string, uid int) string {
	str := func(s string) string { return "<string>" + html.EscapeString(s) + "</string>" }
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0"><dict>` +
		`<key>Label</key>` + str(label) +
		`<key>ProgramArguments</key><array>` + str(tool) + str(Arg) + str(label) + str(strconv.Itoa(uid)) + `</array>` +
		`<key>RunAtLoad</key><true/>` +
		`<key>KeepAlive</key><true/>` +
		`</dict></plist>`
}
