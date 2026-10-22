package app

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxygo/internal/flow"
	"proxygo/locales"
)

func formatSize(n int) string {
	switch {
	case n <= 0:
		return "–"
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(1024*1024*1024))
}

func formatBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	return formatSize(int(n))
}

func formatRate(bytesPerSecond int64) string {
	if bytesPerSecond <= 0 {
		return "0 B/s"
	}
	return formatSize(int(bytesPerSecond)) + "/s"
}

func formatDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "–"
	case d < time.Millisecond:
		return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000)
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.2f s", d.Seconds())
	}
	d = d.Round(time.Second)
	big, small, bigUnit, smallUnit := d/time.Minute, d%time.Minute/time.Second, "min", "s"
	if d >= time.Hour {
		d = d.Round(time.Minute)
		big, small, bigUnit, smallUnit = d/time.Hour, d%time.Hour/time.Minute, "h", "min"
	}
	if small == 0 {
		return fmt.Sprintf("%d %s", big, bigUnit)
	}
	return fmt.Sprintf("%d %s %d %s", big, bigUnit, small, smallUnit)
}

func flowDuration(f *flow.Flow) string {
	if f == nil || f.IsActive() {
		return "–"
	}
	return formatDuration(f.Duration())
}

func flowTime(f *flow.Flow) string {
	t := f.RequestTime()
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("15:04:05.000")
}

func displayURL(f *flow.Flow) string {
	if f.IsTunnel() {
		return strings.TrimSuffix(f.URL(), "/")
	}
	return f.URL()
}

func clientName(f *flow.Flow) string {
	if f != nil && f.Client.Name != "" {
		return f.Client.Name
	}
	return "System"
}

func statusLabel(f *flow.Flow) string {
	switch {
	case f == nil:
		return ""
	case paused(f) != "":
		return locales.StatusPaused()
	case f.IsActive():
		return locales.StatusActive()
	case f.IsIncomplete():
		return "–"
	case f.IsError():
		return "999"
	}
	return fmt.Sprint(f.StatusCode())
}

func paused(f *flow.Flow) string {
	m, _ := f.ToolMetadata.(map[string]any)
	s, _ := m["paused"].(string)
	return s
}

func tools(f *flow.Flow) []string {
	m, _ := f.ToolMetadata.(map[string]any)
	var out []string
	for _, t := range []struct{ key, name string }{
		{"breakpoint", "Breakpoint"}, {"mapLocal", "Map Local"}, {"mapRemote", "Map Remote"},
		{"breakpointResponse", "Breakpoint Answer"},
		{"script", "Script"}, {"mockAPI", "Mock API"}, {"block", "Blocked"}, {"blockedApp", "Blocked App"}, {"network", "Network Conditions"},
		{"dns", "DNS Spoofing"}, {"socks", "SOCKS"},
	} {
		if m[t.key] != nil {
			out = append(out, t.name)
		}
	}
	if m["breakpointResponse"] != nil {
		out = slices.DeleteFunc(out, func(s string) bool { return s == "Breakpoint" })
	}
	return out
}

func toolIcon(name string) string {
	switch name {
	case "Breakpoint", "Breakpoint Answer":
		return "bug"
	case "Map Local":
		return "folder"
	case "Map Remote":
		return "map"
	case "Script", "Mock API":
		return "script"
	case "Blocked", "Blocked App":
		return "block"
	case "Network Conditions":
		return "speed"
	case "DNS Spoofing":
		return "dns"
	}
	return "pencil"
}

var primaryIP = sync.OnceValue(func() string {
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		defer func() { _ = conn.Close() }()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
			return addr.IP.String()
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				return n.IP.String()
			}
		}
	}
	return "127.0.0.1"
})

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func headerLines(h flow.Header) string {
	var b strings.Builder
	for _, e := range h.Entries {
		if e.Enabled && !strings.HasPrefix(e.Key.Name, ":") {
			b.WriteString(e.Key.Name + ": " + e.Value + "\n")
		}
	}
	return b.String()
}

func parseHeaderLines(s string) flow.Header {
	var h flow.Header
	for line := range strings.SplitSeq(s, "\n") {
		name, value, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		h.Add(name, strings.TrimSpace(value))
	}
	return h
}

func residentMemory() int64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output() // #nosec G204 -- ps, asked about this process.
	if err != nil {
		return 0
	}
	kb, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0
	}
	return kb << 10
}
