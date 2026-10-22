package settings

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"

	"proxygo/internal/store"
)

const (
	AppearanceSystem = ""
	AppearanceLight  = "light"
	AppearanceDark   = "dark"
)

type HeaderColumn struct {
	Name     string `json:"name"`
	Response bool   `json:"response,omitzero"`
}

func (h HeaderColumn) ID() string {
	side := "req"
	if h.Response {
		side = "res"
	}
	return "header:" + side + ":" + h.Name
}

type Settings struct {
	Port                int    `json:"port"`
	Appearance          string `json:"appearance,omitempty"`
	OverrideSystemProxy bool   `json:"override_system_proxy,omitzero"`
	StartPaused         bool   `json:"start_paused,omitzero"`
	MaxFlows            int    `json:"max_flows"`
	AutoSelect          bool   `json:"auto_select"`
	StayOnTop           bool   `json:"stay_on_top,omitzero"`
	OpenLastSession     bool   `json:"open_last_session"`

	AppIcon string `json:"app_icon,omitempty"`

	ShowSidebar     bool    `json:"show_sidebar"`
	ShowDetail      bool    `json:"show_detail"`
	DetailRight     bool    `json:"detail_right,omitzero"`
	SidebarWidth    float32 `json:"sidebar_width"`
	TableHeight     float32 `json:"table_height"`
	TableShare      float32 `json:"table_share,omitzero"`
	TableWidthShare float32 `json:"table_width_share,omitzero"`
	TableWidth      float32 `json:"table_width"`
	DetailPercent   float32 `json:"detail_percent"`
	StackedDetail   bool    `json:"stacked_detail,omitzero"`

	HiddenColumns []string           `json:"hidden_columns,omitempty"`
	HeaderColumns []HeaderColumn     `json:"header_columns,omitempty"`
	Columns       []Column           `json:"columns,omitempty"`
	ColumnWidths  map[string]float32 `json:"column_widths,omitempty"`
	ColumnOrder   []string           `json:"column_order,omitempty"`

	FilterPresets []store.Preset `json:"filter_presets,omitempty"`
	MemoryLimitMB int            `json:"memory_limit_mb,omitzero"`

	ListenLocalhost bool `json:"listen_localhost,omitzero"`
	ListenIPv4Only  bool `json:"listen_ipv4_only,omitzero"`

	MCP            bool `json:"mcp,omitzero"`
	MCPHTTP        bool `json:"mcp_http,omitzero"`
	MCPShowSecrets bool `json:"mcp_show_secrets,omitzero"`

	DiffTool string `json:"diff_tool,omitempty"`

	DeviceNames     map[string]string `json:"device_names,omitempty"`
	HideMenuBarIcon bool              `json:"hide_menu_bar_icon,omitzero"`

	Pinned         []string `json:"pinned,omitempty"`
	RecentSessions []string `json:"recent_sessions,omitempty"`
	CodeLanguage   string   `json:"code_language,omitempty"`
}

var DefaultHiddenColumns = []string{"code", "protocol", "host", "path", "contentType", "serverIP"}

func Defaults() Settings {
	return Settings{
		Port:            9090,
		MaxFlows:        50000,
		AutoSelect:      false,
		OpenLastSession: true,
		ShowSidebar:     true,
		ShowDetail:      true,
		SidebarWidth:    260,
		TableHeight:     460,
		TableWidth:      720,
		DetailPercent:   50,
		HiddenColumns:   slices.Clone(DefaultHiddenColumns),
	}
}

type Store struct {
	mu   sync.Mutex
	path string
	s    Settings
}

func Open(path string) *Store {
	st := &Store{path: path, s: Defaults()}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &st.s)
	}
	st.s.normalize()
	return st
}

func (s *Settings) normalize() {
	for _, h := range s.HeaderColumns {
		c := Column{Name: h.Name, Response: h.Response, Source: SourceHeader, Key: h.Name}
		if !slices.ContainsFunc(s.Columns, func(x Column) bool { return x.ID() == c.ID() }) {
			s.Columns = append(s.Columns, c)
		}
	}
	s.HeaderColumns = nil
	if s.MemoryLimitMB < 0 {
		s.MemoryLimitMB = 0
	}
	d := Defaults()
	if s.Port <= 0 || s.Port > 65535 {
		s.Port = d.Port
	}
	if s.MaxFlows <= 0 {
		s.MaxFlows = d.MaxFlows
	}
	if s.SidebarWidth < 160 {
		s.SidebarWidth = d.SidebarWidth
	}
	if s.TableHeight < 120 {
		s.TableHeight = d.TableHeight
	}
	if s.TableWidth < 300 {
		s.TableWidth = d.TableWidth
	}
	if s.TableShare < 0.1 || s.TableShare > 0.9 {
		s.TableShare = 0
	}
	if s.TableWidthShare < 0.1 || s.TableWidthShare > 0.9 {
		s.TableWidthShare = 0
	}
	if s.DetailPercent < 15 || s.DetailPercent > 85 {
		s.DetailPercent = d.DetailPercent
	}
}

func (st *Store) Get() Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	c := st.s
	c.HiddenColumns = slices.Clone(c.HiddenColumns)
	c.Columns = slices.Clone(c.Columns)
	c.FilterPresets = slices.Clone(c.FilterPresets)
	c.ColumnOrder = slices.Clone(c.ColumnOrder)
	c.Pinned = slices.Clone(c.Pinned)
	c.RecentSessions = slices.Clone(c.RecentSessions)
	c.ColumnWidths = maps.Clone(c.ColumnWidths)
	c.DeviceNames = maps.Clone(c.DeviceNames)
	return c
}

func (st *Store) Update(fn func(*Settings)) error {
	st.mu.Lock()
	fn(&st.s)
	st.s.normalize()
	b, err := json.Marshal(st.s, jsontext.WithIndent("  "))
	path := st.path
	st.mu.Unlock()
	if err != nil || path == "" {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Settings) AddRecent(path string) {
	s.RecentSessions = slices.DeleteFunc(s.RecentSessions, func(p string) bool { return p == path })
	s.RecentSessions = append([]string{path}, s.RecentSessions...)
	if len(s.RecentSessions) > 10 {
		s.RecentSessions = s.RecentSessions[:10]
	}
}

func (s *Settings) RemoveRecent(path string) {
	s.RecentSessions = slices.DeleteFunc(s.RecentSessions, func(p string) bool { return p == path })
}

func (s *Settings) TogglePin(key string) bool {
	if i := slices.Index(s.Pinned, key); i >= 0 {
		s.Pinned = slices.Delete(s.Pinned, i, i+1)
		return false
	}
	s.Pinned = append(s.Pinned, key)
	return true
}

func (s *Settings) ListenAddr(port int) (addr, network string) {
	host, network := "", "tcp"
	if s.ListenIPv4Only {
		network = "tcp4"
	}
	if s.ListenLocalhost {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), network
}
