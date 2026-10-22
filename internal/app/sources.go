package app

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"proxygo/internal/flow"
)

type source struct {
	app  string
	host string
	path string
}

func (s source) id() string {
	switch {
	case s.host == "":
		return "app:" + s.app
	case s.app == "" && s.path == "":
		return "domain:" + s.host
	}
	return "src:" + s.app + "\x1f" + s.host + "\x1f" + s.path
}

func parseSource(id string) (source, bool) {
	if app, ok := strings.CutPrefix(id, "app:"); ok {
		return source{app: app}, true
	}
	if host, ok := strings.CutPrefix(id, "domain:"); ok {
		return source{host: host}, true
	}
	rest, ok := strings.CutPrefix(id, "src:")
	if !ok {
		return source{}, false
	}
	parts := strings.SplitN(rest, "\x1f", 3)
	if len(parts) != 3 || parts[1] == "" {
		return source{}, false
	}
	return source{app: parts[0], host: parts[1], path: parts[2]}, true
}

func (s source) label() string {
	switch {
	case s.host == "":
		return s.app
	case s.path == "":
		return s.host
	}
	return s.path[strings.LastIndexByte(s.path, '/'):]
}

func (s source) parent() (source, bool) {
	switch {
	case s.host == "":
		return source{}, false
	case s.path == "":
		if s.app == "" {
			return source{}, false
		}
		return source{app: s.app}, true
	}
	if i := strings.LastIndexByte(s.path, '/'); i > 0 {
		return source{app: s.app, host: s.host, path: s.path[:i]}, true
	}
	return source{app: s.app, host: s.host}, true
}

func (s source) match(f *flow.Flow) bool {
	if s.app != "" && clientName(f) != s.app {
		return false
	}
	if s.host != "" && !strings.EqualFold(f.Host(), s.host) {
		return false
	}
	return s.path == "" || underPath(flowPath(f), s.path)
}

func (s source) pattern() string {
	if s.path == "" {
		return s.host + "/*"
	}
	return s.host + s.path + "/*"
}

func flowPath(f *flow.Flow) string {
	if f.IsTunnel() {
		return "/"
	}
	p, _, _ := strings.Cut(f.URLPath(), "?")
	return p
}

func underPath(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

func segments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

type sourceChild struct {
	source
	count int
}

type sourceTree struct {
	flows    []*flow.Flow
	apps     map[string]int
	devices  map[string]int
	domains  map[string]int
	appHosts map[string]map[string]int
	appPaths map[string]string
	hasPaths map[source]bool
	memo     map[source][]sourceChild
}

func buildSources(flows []*flow.Flow) *sourceTree {
	t := &sourceTree{
		flows:    flows,
		apps:     map[string]int{},
		devices:  map[string]int{},
		domains:  map[string]int{},
		appHosts: map[string]map[string]int{},
		appPaths: map[string]string{},
		hasPaths: map[source]bool{},
		memo:     map[source][]sourceChild{},
	}
	for _, f := range flows {
		app, host := clientName(f), f.Host()
		if remoteIP(f) != "" {
			t.devices[app]++
		} else {
			t.apps[app]++
			if t.appPaths[app] == "" {
				t.appPaths[app] = f.Client.Path
			}
		}
		if host == "" {
			continue
		}
		t.domains[host]++
		if t.appHosts[app] == nil {
			t.appHosts[app] = map[string]int{}
		}
		t.appHosts[app][host]++
		if len(segments(flowPath(f))) > 0 {
			t.hasPaths[source{host: host}] = true
			t.hasPaths[source{app: app, host: host}] = true
		}
	}
	return t
}

func (t *sourceTree) expandable(s source) bool {
	switch {
	case s.host == "":
		return len(t.appHosts[s.app]) > 0
	case s.path == "":
		return t.hasPaths[s]
	}
	return len(t.children(s)) > 0
}

func (t *sourceTree) children(s source) []sourceChild {
	if out, ok := t.memo[s]; ok {
		return out
	}
	counts := map[string]int{}
	if s.host == "" {
		maps.Copy(counts, t.appHosts[s.app])
	} else {
		depth := len(segments(s.path))
		for _, f := range t.flows {
			if !s.match(f) {
				continue
			}
			if segs := segments(flowPath(f)); len(segs) > depth {
				counts["/"+strings.Join(segs[:depth+1], "/")]++
			}
		}
	}
	out := make([]sourceChild, 0, len(counts))
	for key, n := range counts {
		c := sourceChild{source: source{app: s.app, host: s.host, path: key}, count: n}
		if s.host == "" {
			c.source = source{app: s.app, host: key}
		}
		out = append(out, c)
	}
	slices.SortFunc(out, func(x, y sourceChild) int {
		return cmp.Or(cmp.Compare(y.count, x.count), strings.Compare(x.label(), y.label()))
	})
	t.memo[s] = out
	return out
}
