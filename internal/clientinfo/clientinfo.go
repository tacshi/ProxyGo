package clientinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Info struct {
	PID      int
	Name     string
	Path     string
	BundleID string
}

type Lookup struct {
	mu     sync.RWMutex
	byPort map[int]Info
	byPID  map[int]Info
	stop   chan struct{}
	once   sync.Once
}

func New(interval time.Duration) *Lookup {
	l := &Lookup{
		byPort: map[int]Info{},
		byPID:  map[int]Info{},
		stop:   make(chan struct{}),
	}
	if interval <= 0 {
		interval = 1500 * time.Millisecond
	}
	go l.loop(interval)
	return l
}

func (l *Lookup) Close() {
	l.once.Do(func() { close(l.stop) })
}

func (l *Lookup) loop(interval time.Duration) {
	l.refresh()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.refresh()
		}
	}
}

func (l *Lookup) ForPort(port int) Info {
	l.mu.RLock()
	info, ok := l.byPort[port]
	l.mu.RUnlock()
	if ok {
		return info
	}
	if info, ok := lookupPort(port); ok {
		l.mu.Lock()
		l.byPort[port] = info
		l.mu.Unlock()
		return info
	}
	return systemInfo()
}

func systemInfo() Info {
	return Info{PID: -1, Name: "System"}
}

func (l *Lookup) refresh() {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-FpcPn").Output()
	if err != nil && len(out) == 0 {
		return
	}
	ports, pids := parseLsof(out)
	infos := map[int]Info{}
	for pid := range pids {
		infos[pid] = describe(pid)
	}
	l.mu.Lock()
	l.byPort = portsWithInfo(ports, infos)
	l.byPID = infos
	l.mu.Unlock()
}

func lookupPort(port int) (Info, bool) {
	out, err := exec.Command("lsof", "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:ESTABLISHED", "-FpcPn").Output()
	if err != nil && len(out) == 0 {
		return Info{}, false
	}
	ports, _ := parseLsof(out)
	if ports[port] == 0 {
		return Info{}, false
	}
	return describe(ports[port]), true
}

func portsWithInfo(ports map[int]int, infos map[int]Info) map[int]Info {
	out := make(map[int]Info, len(ports))
	for port, pid := range ports {
		info, ok := infos[pid]
		if !ok {
			info = describe(pid)
		}
		out[port] = info
	}
	return out
}

func parseLsof(out []byte) (map[int]int, map[int]bool) {
	ports := map[int]int{}
	pids := map[int]bool{}
	pid := 0
	for line := range strings.SplitSeq(string(out), "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
			if pid > 0 {
				pids[pid] = true
			}
		case 'n':
			if pid <= 0 {
				continue
			}
			local, _, _ := strings.Cut(line[1:], "->")
			if port := endpointPort(local); port > 0 {
				ports[port] = pid
			}
		}
	}
	return ports, pids
}

func endpointPort(endpoint string) int {
	_, port, ok := strings.CutLast(endpoint, ":")
	if !ok {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

func describe(pid int) Info {
	if pid <= 0 {
		return systemInfo()
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	path := ""
	if err == nil {
		path = strings.TrimSpace(string(out))
	}
	if !filepath.IsAbs(path) {
		if full := executablePath(pid); filepath.IsAbs(full) {
			path = full
		}
	}
	name := appName(path)
	if name == "" {
		name = filepath.Base(path)
	}
	if name == "" {
		name = "Process " + strconv.Itoa(pid)
	}
	return Info{PID: pid, Name: name, Path: path, BundleID: BundleID(path)}
}

var bundleIDs sync.Map

func BundleID(path string) string {
	bundle := BundlePath(path)
	if bundle == "" {
		return ""
	}
	if v, ok := bundleIDs.Load(bundle); ok {
		return v.(string)
	}
	id := ""
	out, err := exec.Command("plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(bundle, "Contents", "Info.plist")).Output()
	if err == nil {
		id = strings.TrimSpace(string(out))
	}
	bundleIDs.Store(bundle, id)
	return id
}

func appName(path string) string {
	if path == "" {
		return ""
	}
	parts := strings.Split(path, string(os.PathSeparator))
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasSuffix(parts[i], ".app") {
			return strings.TrimSuffix(parts[i], ".app")
		}
	}
	return ""
}

func BundlePath(path string) string {
	if i := strings.Index(path, ".app/"); i >= 0 {
		return path[:i+4]
	}
	if strings.HasSuffix(path, ".app") {
		return path
	}
	return ""
}
