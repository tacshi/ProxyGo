package privileged

import (
	"bytes"
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
	cdhash []byte
	path   string
}

type server struct {
	label  string
	uid    int
	cdhash []byte
	mu     sync.Mutex
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
	s := &server{label: args[0], uid: uid, cdhash: self}
	path := socketPath(s.label)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Print(err)
		return 1
	}
	if err := os.Chmod(path, 0o666); err != nil {
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
	defer c.Close()
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
		c.Close()
		_ = exec.Command("/bin/launchctl", "bootout", "system/"+s.label).Run()
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
		return systemproxy.Enable(cfg)
	case "disable":
		return systemproxy.Disable()
	case "restore":
		return systemproxy.Restore(req.State)
	case "link-cli":
		return linkCLI(p.path)
	case "uninstall":
		for _, path := range []string{plistPath(s.label), toolPath(s.label), socketPath(s.label)} {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unknown request %q", req.Op)
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
	if err := os.MkdirAll(filepath.Dir(cliLink), 0o755); err != nil {
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
