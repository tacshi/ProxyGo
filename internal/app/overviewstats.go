package app

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/store"
)

type overviewBucket struct {
	ok, failed, active int
	up, down           int64
}

type overviewStats struct {
	version uint64
	total   int

	ok, redirect, client, server, failed, active int

	durations []time.Duration
	codes     map[int]int
	reasons   map[string]int

	domains, apps, kinds map[string]int
	domainFails          map[string]int
	appFails             map[string]int
	domainBytes          map[string]int64
	appBytes             map[string]int64
	kindBytes            map[string]int64

	decrypted, tunnels int
	tunnelHosts        map[string]int

	first, last time.Time
	step        time.Duration
	buckets     []overviewBucket

	up, down    int64
	slow, large []*flow.Flow
}

func (s *overviewStats) errors() int { return s.client + s.server + s.failed }

func (s *overviewStats) percentile(q float64) time.Duration {
	if len(s.durations) == 0 {
		return 0
	}
	i := int(q*float64(len(s.durations))+0.5) - 1
	return s.durations[min(max(i, 0), len(s.durations)-1)]
}

func (s *overviewStats) https() int { return s.decrypted + s.tunnels }

func (s *overviewStats) span() time.Duration { return s.last.Sub(s.first) }

func (s *overviewStats) peakRequests() (int, time.Duration) {
	peak := 0
	for _, b := range s.buckets {
		peak = max(peak, b.ok+b.failed+b.active)
	}
	return peak, s.step
}

func (s *overviewStats) peakRate() int64 {
	var peak int64
	for _, b := range s.buckets {
		peak = max(peak, b.down, b.up)
	}
	return int64(float64(peak) / s.step.Seconds())
}

var bucketSteps = []time.Duration{
	100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond,
	time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second, 30 * time.Second,
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
}

func bucketStep(span time.Duration, most int) time.Duration {
	for _, s := range bucketSteps {
		if span/s < time.Duration(most) {
			return s
		}
	}
	return bucketSteps[len(bucketSteps)-1] * (span/bucketSteps[len(bucketSteps)-1]/time.Duration(most) + 1)
}

func isFlowError(f *flow.Flow) bool {
	return f.IsError() || f.StatusCode() >= 400
}

func errorReason(f *flow.Flow) string {
	if f.IsError() {
		return cmp.Or(f.ErrorText(), "Connection error")
	}
	code := f.StatusCode()
	if t := http.StatusText(code); t != "" {
		return fmt.Sprintf("%d %s", code, t)
	}
	return fmt.Sprint(code)
}

func flowEnd(f *flow.Flow) time.Time {
	t := f.Timing.ResponseEndedAt
	if t == nil {
		t = f.Timing.ResponseStartedAt
	}
	if t == nil {
		return f.RequestTime()
	}
	return time.Unix(0, int64(*t*1e9))
}

func computeOverview(flows []*flow.Flow) *overviewStats {
	s := &overviewStats{
		total: len(flows), codes: map[int]int{}, reasons: map[string]int{},
		domains: map[string]int{}, apps: map[string]int{}, kinds: map[string]int{},
		domainFails: map[string]int{}, appFails: map[string]int{},
		domainBytes: map[string]int64{}, appBytes: map[string]int64{}, kindBytes: map[string]int64{},
		tunnelHosts: map[string]int{},
	}
	for _, f := range flows {
		code := f.StatusCode()
		switch {
		case f.IsActive():
			s.active++
		case f.IsError():
			s.failed++
		case code >= 500:
			s.server++
		case code >= 400:
			s.client++
		case code >= 300:
			s.redirect++
		default:
			s.ok++
		}
		if code > 0 {
			s.codes[code]++
		}
		up, down := int64(f.RequestSize()), int64(f.ResponseSize())
		s.up += up
		s.down += down
		host, app := f.Host(), cmp.Or(f.Client.Name, "System")
		kind := f.ContentCategory()
		if f.IsTunnel() {
			kind = "Encrypted"
		}
		if host != "" {
			s.domains[host]++
			s.domainBytes[host] += up + down
		}
		s.apps[app]++
		s.appBytes[app] += up + down
		s.kinds[kind]++
		s.kindBytes[kind] += down
		if isFlowError(f) {
			s.reasons[errorReason(f)]++
			if host != "" {
				s.domainFails[host]++
			}
			s.appFails[app]++
		}
		switch {
		case f.IsTunnel():
			s.tunnels++
			if host != "" {
				s.tunnelHosts[host]++
			}
		case f.IsHTTPS():
			s.decrypted++
		}
		if !f.IsActive() && !f.IsTunnel() && !f.IsError() {
			if d := f.Duration(); d > 0 {
				s.durations = append(s.durations, d)
			}
		}
		if t := f.RequestTime(); !t.IsZero() {
			if s.first.IsZero() || t.Before(s.first) {
				s.first = t
			}
			if t.After(s.last) {
				s.last = t
			}
		}
	}
	slices.Sort(s.durations)
	s.slow = slowest(flows)
	s.slow = s.slow[:min(len(s.slow), 10)]
	s.large = largest(flows)
	s.large = s.large[:min(len(s.large), 10)]
	if s.first.IsZero() {
		return s
	}
	s.step = bucketStep(s.span(), 60)
	start := s.first.Truncate(s.step)
	s.first = start
	s.buckets = make([]overviewBucket, int(s.last.Sub(start)/s.step)+1)
	at := func(t time.Time) *overviewBucket {
		i := int(t.Sub(start) / s.step)
		return &s.buckets[min(max(i, 0), len(s.buckets)-1)]
	}
	for _, f := range flows {
		t := f.RequestTime()
		if t.IsZero() {
			continue
		}
		b := at(t)
		switch {
		case f.IsActive():
			b.active++
		case isFlowError(f):
			b.failed++
		default:
			b.ok++
		}
		b.up += int64(f.RequestSize())
		at(flowEnd(f)).down += int64(f.ResponseSize())
	}
	return s
}

func (a *App) overviewStats() *overviewStats {
	if a.ov == nil || a.ov.version != a.version {
		a.ov = computeOverview(a.flows)
		a.ov.version = a.version
	}
	return a.ov
}

func (s *overviewStats) markdown() string {
	var b strings.Builder
	pct := func(n, of int) string { return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(max(of, 1))) }
	fmt.Fprintf(&b, "# ProxyGo Overview\n\n")
	if !s.first.IsZero() {
		fmt.Fprintf(&b, "%s – %s (%s)\n\n", s.first.Local().Format("2006-01-02 15:04:05"), s.last.Local().Format("15:04:05"), formatDuration(s.span()))
	}
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Requests | %d |\n", s.total)
	fmt.Fprintf(&b, "| Errors | %d (%s) |\n", s.errors(), pct(s.errors(), s.total))
	fmt.Fprintf(&b, "| Median time | %s |\n", formatDuration(s.percentile(0.5)))
	fmt.Fprintf(&b, "| P95 time | %s |\n", formatDuration(s.percentile(0.95)))
	fmt.Fprintf(&b, "| Uploaded | %s |\n", formatBytes(s.up))
	fmt.Fprintf(&b, "| Downloaded | %s |\n", formatBytes(s.down))
	if s.https() > 0 {
		fmt.Fprintf(&b, "| HTTPS decrypted | %s (%d of %d) |\n", pct(s.decrypted, s.https()), s.decrypted, s.https())
	}
	fmt.Fprintf(&b, "| Apps | %d |\n| Domains | %d |\n", len(s.apps), len(s.domains))
	fmt.Fprintf(&b, "\n## Status\n\n| Status | Requests |\n|---|---|\n")
	for _, r := range []struct {
		label string
		n     int
	}{{"2xx", s.ok}, {"3xx", s.redirect}, {"4xx", s.client}, {"5xx", s.server}, {"Failed", s.failed}, {"Active", s.active}} {
		if r.n > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", r.label, r.n)
		}
	}
	table := func(title, col string, counts map[string]int, limit int) {
		if len(counts) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n## %s\n\n| %s | Requests |\n|---|---|\n", title, col)
		for i, k := range store.ByCount(counts) {
			if i >= limit {
				break
			}
			fmt.Fprintf(&b, "| %s | %d |\n", strings.ReplaceAll(k, "|", "\\|"), counts[k])
		}
	}
	table("Top Domains", "Domain", s.domains, 10)
	table("Top Apps", "App", s.apps, 10)
	table("Content Types", "Type", s.kinds, 20)
	table("Errors", "Reason", s.reasons, 10)
	if slow := s.slow; len(slow) > 0 {
		fmt.Fprintf(&b, "\n## Slowest Requests\n\n| Duration | Method | URL |\n|---|---|---|\n")
		for _, f := range slow {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", flowDuration(f), f.MethodName(), strings.ReplaceAll(f.URL(), "|", "%7C"))
		}
	}
	return b.String()
}

func finished(flows []*flow.Flow) []*flow.Flow {
	return slices.DeleteFunc(slices.Clone(flows), func(f *flow.Flow) bool { return f.IsActive() || f.IsTunnel() || f.IsError() })
}

func slowest(flows []*flow.Flow) []*flow.Flow {
	out := finished(flows)
	slices.SortStableFunc(out, func(x, y *flow.Flow) int { return cmp.Compare(y.Duration(), x.Duration()) })
	return out
}

func largest(flows []*flow.Flow) []*flow.Flow {
	out := slices.DeleteFunc(finished(flows), func(f *flow.Flow) bool { return f.ResponseBodySize() <= 0 })
	slices.SortStableFunc(out, func(x, y *flow.Flow) int { return cmp.Compare(y.ResponseBodySize(), x.ResponseBodySize()) })
	return out
}
