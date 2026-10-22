package pac

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

const (
	refresh  = 5 * time.Minute
	cacheFor = 30 * time.Second
	runLimit = time.Second
)

type Resolver struct {
	URL    string
	Fetch  func(ctx context.Context, rawURL string) ([]byte, error)
	Lookup func(ctx context.Context, host string) ([]string, error)
	Now    func() time.Time

	mu      sync.Mutex
	vm      *goja.Runtime
	fn      goja.Callable
	loaded  time.Time
	loadErr error
	cache   map[string]cached
}

type cached struct {
	result string
	at     time.Time
}

func (r *Resolver) FindProxy(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if u.Scheme == "https" || u.Scheme == "wss" {
		rawURL = u.Scheme + "://" + u.Host + "/"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	key := rawURL
	if c, ok := r.cache[key]; ok && now.Sub(c.at) < cacheFor {
		return c.result, nil
	}
	if err := r.loadLocked(ctx, now); err != nil {
		return "", err
	}
	timer := time.AfterFunc(runLimit, func() { r.vm.Interrupt("the PAC script ran too long") })
	v, err := r.fn(goja.Undefined(), r.vm.ToValue(rawURL), r.vm.ToValue(host))
	timer.Stop()
	r.vm.ClearInterrupt()
	if err != nil {
		return "", fmt.Errorf("FindProxyForURL: %w", err)
	}
	result := ""
	if v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
		result = v.String()
	}
	if r.cache == nil || len(r.cache) > 4096 {
		r.cache = map[string]cached{}
	}
	r.cache[key] = cached{result: result, at: now}
	return result, nil
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) loadLocked(ctx context.Context, now time.Time) error {
	if r.vm != nil && now.Sub(r.loaded) < refresh {
		return nil
	}
	if r.vm == nil && r.loadErr != nil && now.Sub(r.loaded) < 30*time.Second {
		return r.loadErr
	}
	r.loaded = now
	src, err := r.fetch(ctx)
	if err != nil {
		if r.vm != nil {
			return nil
		}
		r.loadErr = fmt.Errorf("PAC %s: %w", r.URL, err)
		return r.loadErr
	}
	vm := goja.New()
	r.install(vm)
	timer := time.AfterFunc(runLimit, func() { vm.Interrupt("the PAC script ran too long") })
	_, err = vm.RunScript(r.URL, string(src))
	timer.Stop()
	if err == nil {
		fn, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
		if !ok {
			err = errors.New("the script has no FindProxyForURL function")
		} else {
			r.vm, r.fn, r.loadErr = vm, fn, nil
			clear(r.cache)
			return nil
		}
	}
	if r.vm != nil {
		return nil
	}
	r.loadErr = fmt.Errorf("PAC %s: %w", r.URL, err)
	return r.loadErr
}

func (r *Resolver) fetch(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if r.Fetch != nil {
		return r.Fetch(ctx, r.URL)
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "file" {
		return os.ReadFile(u.Path)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported PAC URL scheme %q", u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func (r *Resolver) resolve(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var addrs []string
	if r.Lookup != nil {
		addrs, _ = r.Lookup(ctx, host)
	} else {
		addrs, _ = net.DefaultResolver.LookupHost(ctx, host)
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

func (r *Resolver) install(vm *goja.Runtime) {
	set := func(name string, fn any) { _ = vm.Set(name, fn) }
	set("isPlainHostName", func(host string) bool { return !strings.Contains(host, ".") })
	set("dnsDomainIs", func(host, domain string) bool {
		return strings.HasSuffix(strings.ToLower(host), strings.ToLower(domain))
	})
	set("localHostOrDomainIs", func(host, hostdom string) bool {
		host, hostdom = strings.ToLower(host), strings.ToLower(hostdom)
		if host == hostdom {
			return true
		}
		return !strings.Contains(host, ".") && strings.HasPrefix(hostdom, host+".")
	})
	set("isResolvable", func(host string) bool { return r.resolve(host) != "" })
	set("isInNet", func(host, pattern, mask string) bool {
		ip := net.ParseIP(r.resolve(host)).To4()
		p, m := net.ParseIP(pattern).To4(), net.ParseIP(mask).To4()
		if ip == nil || p == nil || m == nil {
			return false
		}
		for i := range 4 {
			if ip[i]&m[i] != p[i]&m[i] {
				return false
			}
		}
		return true
	})
	set("dnsResolve", func(host string) any {
		if ip := r.resolve(host); ip != "" {
			return ip
		}
		return nil
	})
	set("myIpAddress", func() string { return myIP() })
	set("dnsDomainLevels", func(host string) int { return strings.Count(host, ".") })
	set("shExpMatch", func(s, pattern string) bool { return shExpMatch(s, pattern) })
	set("convert_addr", func(ip string) int64 {
		v := net.ParseIP(ip).To4()
		if v == nil {
			return 0
		}
		return int64(v[0])<<24 | int64(v[1])<<16 | int64(v[2])<<8 | int64(v[3])
	})
	set("weekdayRange", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(weekdayRange(r.now(), args(call)))
	})
	set("dateRange", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(dateRange(r.now(), args(call)))
	})
	set("timeRange", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(timeRange(r.now(), args(call)))
	})
	set("alert", func(goja.FunctionCall) goja.Value { return goja.Undefined() })
}

func args(call goja.FunctionCall) []string {
	out := make([]string, len(call.Arguments))
	for i, a := range call.Arguments {
		out[i] = a.String()
	}
	return out
}

var shExpCache sync.Map

func shExpMatch(s, pattern string) bool {
	re, ok := shExpCache.Load(pattern)
	if !ok {
		var b strings.Builder
		b.WriteString("^")
		for _, c := range pattern {
			switch c {
			case '*':
				b.WriteString(".*")
			case '?':
				b.WriteString(".")
			default:
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		b.WriteString("$")
		compiled, err := regexp.Compile(b.String())
		if err != nil {
			return false
		}
		re, _ = shExpCache.LoadOrStore(pattern, compiled)
	}
	return re.(*regexp.Regexp).MatchString(s)
}

var myIP = func() string {
	c, err := net.Dial("udp4", "198.51.100.1:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func gmt(now time.Time, a []string) (time.Time, []string) {
	if len(a) > 0 && strings.EqualFold(a[len(a)-1], "GMT") {
		return now.UTC(), a[:len(a)-1]
	}
	return now, a
}

var weekdays = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}

func weekdayRange(now time.Time, a []string) bool {
	now, a = gmt(now, a)
	idx := func(s string) int {
		for i, w := range weekdays {
			if strings.EqualFold(w, s) {
				return i
			}
		}
		return -1
	}
	day := int(now.Weekday())
	switch len(a) {
	case 1:
		return idx(a[0]) == day
	case 2:
		lo, hi := idx(a[0]), idx(a[1])
		if lo < 0 || hi < 0 {
			return false
		}
		if lo <= hi {
			return day >= lo && day <= hi
		}
		return day >= lo || day <= hi
	}
	return false
}

var months = []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}

func dateRange(now time.Time, a []string) bool {
	now, a = gmt(now, a)
	type part struct{ day, month, year int }
	parse := func(s string) (kind byte, v int) {
		for i, m := range months {
			if strings.EqualFold(m, s) {
				return 'm', i + 1
			}
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, 0
		}
		if n > 31 {
			return 'y', n
		}
		return 'd', n
	}
	if len(a) == 0 || len(a)%2 == 1 && len(a) != 1 {
		return false
	}
	half := len(a) / 2
	if len(a) == 1 {
		kind, v := parse(a[0])
		switch kind {
		case 'd':
			return now.Day() == v
		case 'm':
			return int(now.Month()) == v
		case 'y':
			return now.Year() == v
		}
		return false
	}
	var lo, hi part
	fill := func(p *part, vals []string) {
		for _, s := range vals {
			switch kind, v := parse(s); kind {
			case 'd':
				p.day = v
			case 'm':
				p.month = v
			case 'y':
				p.year = v
			}
		}
	}
	fill(&lo, a[:half])
	fill(&hi, a[half:])
	key := func(p part) int { return p.year*10000 + p.month*100 + p.day }
	cur := part{}
	if lo.year != 0 {
		cur.year = now.Year()
	}
	if lo.month != 0 {
		cur.month = int(now.Month())
	}
	if lo.day != 0 {
		cur.day = now.Day()
	}
	l, h, c := key(lo), key(hi), key(cur)
	if l <= h {
		return c >= l && c <= h
	}
	return c >= l || c <= h
}

func timeRange(now time.Time, a []string) bool {
	now, a = gmt(now, a)
	n := make([]int, len(a))
	for i, s := range a {
		v, err := strconv.Atoi(s)
		if err != nil {
			return false
		}
		n[i] = v
	}
	sec := now.Hour()*3600 + now.Minute()*60 + now.Second()
	var lo, hi int
	switch len(n) {
	case 1:
		return now.Hour() == n[0]
	case 2:
		lo, hi = n[0]*3600, n[1]*3600+3599
	case 4:
		lo, hi = n[0]*3600+n[1]*60, n[2]*3600+n[3]*60+59
	case 6:
		lo, hi = n[0]*3600+n[1]*60+n[2], n[3]*3600+n[4]*60+n[5]
	default:
		return false
	}
	if lo <= hi {
		return sec >= lo && sec <= hi
	}
	return sec >= lo || sec <= hi
}

func Proxies(result string) []*url.URL {
	var out []*url.URL
	for part := range strings.SplitSeq(result, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		scheme := ""
		switch strings.ToUpper(fields[0]) {
		case "DIRECT":
			out = append(out, nil)
			continue
		case "PROXY", "HTTP":
			scheme = "http"
		case "HTTPS":
			scheme = "https"
		case "SOCKS", "SOCKS5":
			scheme = "socks5"
		default:
			continue
		}
		if len(fields) < 2 {
			continue
		}
		u, err := url.Parse(scheme + "://" + fields[1])
		if err != nil || u.Host == "" {
			continue
		}
		out = append(out, u)
	}
	return out
}
