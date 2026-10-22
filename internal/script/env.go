package script

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (e *Engine) SetAllowEnv(on bool) {
	e.mu.Lock()
	e.allowEnv = on
	e.mu.Unlock()
}

func (e *Engine) environment() (map[string]string, bool) {
	e.mu.Lock()
	allowed, env := e.allowEnv, e.env
	e.mu.Unlock()
	if !allowed {
		return nil, false
	}
	if env == nil {
		env = e.ReloadEnv()
	}
	return env, true
}

func (e *Engine) ReloadEnv() map[string]string {
	env := loadEnv()
	e.mu.Lock()
	e.env = env
	e.mu.Unlock()
	return env
}

const envMarker = "\x00PROXYGO_ENV\x00"

var loadEnv = func() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-l", "-i", "-c", `printf '\0PROXYGO_ENV\0'; env -0`) // #nosec G204 -- the user's login shell, running a fixed command.
	cmd.Stdin = nil
	b, err := cmd.Output()
	if err != nil && len(b) == 0 {
		return out
	}
	i := bytes.Index(b, []byte(envMarker))
	if i < 0 {
		return out
	}
	for kv := range strings.SplitSeq(string(b[i+len(envMarker):]), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			out[k] = v
		}
	}
	return out
}
