package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"proxygo/internal/flow"
)

var CharlesApp = func() string {
	home, _ := os.UserHomeDir()
	for _, p := range []string{"/Applications/Charles.app", filepath.Join(home, "Applications", "Charles.app")} {
		if _, err := os.Stat(filepath.Join(p, "Contents", "MacOS", "Charles")); err == nil {
			return p
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "mdfind", "kMDItemCFBundleIdentifier == 'com.xk72.Charles'").Output()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.HasSuffix(line, ".app") {
			return line
		}
	}
	return ""
}

var ErrNoCharles = errors.New("opening a Charles session needs Charles Proxy, which converts it: install Charles, or export the session from Charles as JSON (.chlsj) or HAR")

func ReadCharlesSession(path string) ([]*flow.Flow, error) {
	app := CharlesApp()
	if app == "" {
		return nil, ErrNoCharles
	}
	dir, err := os.MkdirTemp("", "proxygo-charles-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	har := filepath.Join(dir, "session.har")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(app, "Contents", "MacOS", "Charles"), "convert", path, har) // #nosec G204 -- Charles's own converter, given the file the user imports.
	out, err := cmd.CombinedOutput()
	if _, statErr := os.Stat(har); err != nil || statErr != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" && err != nil {
			msg = err.Error()
		}
		return nil, fmt.Errorf("Charles could not convert %s: %s", filepath.Base(path), msg) //nolint:staticcheck // Charles is a proper name and starts the message.
	}
	flows, err := ReadHAR(har)
	for _, f := range flows {
		f.Client = flow.Client{Name: "Charles", PID: -1}
	}
	return flows, err
}
