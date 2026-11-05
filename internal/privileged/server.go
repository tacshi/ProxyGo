package privileged

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxygo/internal/cli"
	"proxygo/internal/systemproxy"
)

const cliLink = "/usr/local/bin/" + cli.Name

type peer struct {
	uid    int
	pid    int
	cdhash []byte
	path   string
}

type server struct {
	label   string
	uid     int
	cdhash  []byte
	mu      sync.Mutex
	watched *appWatch
	saved   *systemproxy.Saved
	path    string
	every   time.Duration
	sys     system
}

type system struct {
	alive   func(int) bool
	status  func() systemproxy.State
	read    func() (systemproxy.Snapshot, error)
	enable  func(systemproxy.Config) error
	disable func() error
	restore func(systemproxy.Snapshot) error
}

var realSystem = system{
	alive:   processAlive,
	status:  systemproxy.Status,
	read:    systemproxy.Read,
	enable:  systemproxy.Enable,
	disable: systemproxy.Disable,
	restore: systemproxy.Restore,
}

type appWatch struct {
	pid int
	cfg systemproxy.Config
}

func Serve(args []string) int {
	if len(args) != 2 {
		log.Printf("usage: %s <label> <uid>", Arg)
		return 2
	}
	uid, err := strconv.Atoi(args[1])
	if err != nil {
		log.Printf("bad uid %q", args[1])
		return 2
	}
	self, err := ownCDHash()
	if err != nil {
		log.Print(err)
		return 1
	}
	s := &server{label: args[0], uid: uid, cdhash: self, path: statePath(args[0]), sys: realSystem}
	if saved, ok := systemproxy.Load(s.path); ok {
		s.saved = &saved
	}
	path := socketPath(s.label)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Print(err)
		return 1
	}
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- the app connects as the logged-in user, and the helper checks its code signature.
		log.Print(err)
		return 1
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			return 1
		}
		go s.serve(c.(*net.UnixConn))
	}
}

func (s *server) serve(c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	enc := json.NewEncoder(c)
	p, err := peerOf(c)
	if err != nil || p.uid != s.uid || !bytes.Equal(p.cdhash, s.cdhash) {
		_ = enc.Encode(Response{Stale: true, Error: errStale.Error()})
		return
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(c, 1<<20)).Decode(&req); err != nil {
		_ = enc.Encode(Response{Error: "bad request: " + err.Error()})
		return
	}
	s.mu.Lock()
	err = s.handle(req, p)
	s.mu.Unlock()
	var resp Response
	if err != nil {
		resp.Error = err.Error()
	}
	_ = enc.Encode(resp)
	if req.Op == "uninstall" && err == nil {
		_ = c.Close()
		_ = exec.Command("/bin/launchctl", "bootout", "system/"+s.label).Run() // #nosec G204 -- launchctl, given the helper's own label.
		os.Exit(0)
	}
}

func (s *server) handle(req Request, p peer) error {
	switch req.Op {
	case "ping":
		return nil
	case "enable":
		cfg := req.Config
		if !loopback(cfg.Host) || cfg.Port < 1 || cfg.Port > 65535 || cfg.SOCKSPort < 0 || cfg.SOCKSPort > 65535 {
			return errors.New("ProxyGo's helper points macOS only at a proxy on this Mac")
		}
		if err := s.remember(cfg); err != nil {
			return err
		}
		if err := s.sys.enable(cfg); err != nil {
			return err
		}
		s.watch(p.pid, cfg)
		return nil
	case "disable":
		s.watched = nil
		if err := s.sys.disable(); err != nil {
			return err
		}
		s.forget()
		return nil
	case "restore":
		s.watched = nil
		return s.giveBack()
	case "link-cli":
		return linkCLI(p.path)
	case "uninstall":
		if old := formerLabel(s.label); old != "" {
			_ = exec.Command("/bin/launchctl", "bootout", "system/"+old).Run() // #nosec G204 -- launchctl, given the label of the helper an older ProxyGo installed.
			if err := removeHelper(old); err != nil {
				return err
			}
		}
		return removeHelper(s.label)
	}
	return fmt.Errorf("unknown request %q", req.Op)
}

func (s *server) remember(cfg systemproxy.Config) error {
	cur := s.sys.status()
	ours := cur.PointsAt(cfg.Host, cfg.Port)
	var before systemproxy.Snapshot
	if s.saved != nil && (ours || cur.PointsAt(s.saved.Host, s.saved.Port)) {
		before = s.saved.Before
	} else {
		read, err := s.sys.read()
		if err != nil {
			return err
		}
		before = read
		if ours {
			before = read.Without(cfg)
		}
	}
	saved := systemproxy.Saved{Before: before, Host: cfg.Host, Port: cfg.Port}
	if err := systemproxy.Save(s.path, saved); err != nil {
		return fmt.Errorf("saving the macOS proxy settings: %w", err)
	}
	s.saved = &saved
	return nil
}

func (s *server) giveBack() error {
	var before systemproxy.Snapshot
	if s.saved != nil {
		before = s.saved.Before
	}
	if err := s.sys.restore(before); err != nil {
		return err
	}
	s.forget()
	return nil
}

func (s *server) forget() {
	s.saved = nil
	systemproxy.Forget(s.path)
}

func removeHelper(label string) error {
	for _, path := range []string{plistPath(label), toolPath(label), socketPath(label), statePath(label)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return os.RemoveAll(bundlePath(label))
}

func (s *server) watch(pid int, cfg systemproxy.Config) {
	if pid <= 0 {
		return
	}
	w := &appWatch{pid: pid, cfg: cfg}
	s.watched = w
	every := cmp.Or(s.every, time.Second)
	go func() {
		for {
			time.Sleep(every)
			s.mu.Lock()
			if s.watched != w {
				s.mu.Unlock()
				return
			}
			if s.sys.alive(pid) {
				s.mu.Unlock()
				continue
			}
			s.watched = nil
			if s.sys.status().PointsAt(cfg.Host, cfg.Port) {
				if err := s.giveBack(); err != nil {
					log.Printf("giving macOS its proxy back: %v", err)
				}
			}
			s.mu.Unlock()
			return
		}
	}()
}

func loopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func linkCLI(target string) error {
	if !strings.Contains(target, ".app/Contents/MacOS/") {
		return errors.New("install the command-line tool from ProxyGo.app")
	}
	if fi, err := os.Lstat(cliLink); err == nil && fi.Mode()&fs.ModeSymlink == 0 {
		return fmt.Errorf("%s is a file, not a link: remove it first", cliLink)
	}
	if err := os.MkdirAll(filepath.Dir(cliLink), 0o755); err != nil { // #nosec G301 -- /usr/local/bin, which every user's shell searches.
		return err
	}
	tmp := cliLink + ".proxygo-new"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, cliLink); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
