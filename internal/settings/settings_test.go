package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	st := Open(path)
	if st.Get().Port != 9090 || !st.Get().ShowSidebar {
		t.Fatalf("defaults %+v", st.Get())
	}
	err := st.Update(func(s *Settings) {
		s.Port = 8888
		s.Appearance = AppearanceDark
		s.TogglePin("host:api.dev")
		s.HeaderColumns = append(s.HeaderColumns, HeaderColumn{Name: "X-Request-Id", Response: true})
		for i := range 12 {
			s.AddRecent(filepath.Join("/tmp", string(rune('a'+i))))
		}
		s.AddRecent("/tmp/c")
		s.SidebarWidth = 5
	})
	if err != nil {
		t.Fatal(err)
	}
	again := Open(path).Get()
	if again.Port != 8888 || again.Appearance != "dark" || len(again.Pinned) != 1 || again.SidebarWidth != 260 {
		t.Fatalf("%+v", again)
	}
	if len(again.RecentSessions) != 10 || again.RecentSessions[0] != "/tmp/c" {
		t.Fatalf("recent %v", again.RecentSessions)
	}
	if len(again.HeaderColumns) != 0 || len(again.Columns) != 1 || again.Columns[0].ID() != "header:res:X-Request-Id" || again.Columns[0].Source != SourceHeader {
		t.Fatalf("%+v %+v", again.HeaderColumns, again.Columns)
	}
	if addr, network := again.ListenAddr(9090); addr != ":9090" || network != "tcp" {
		t.Errorf("listen %s %s", addr, network)
	}
	again.ListenLocalhost, again.ListenIPv4Only = true, true
	if addr, network := again.ListenAddr(9090); addr != "127.0.0.1:9090" || network != "tcp4" {
		t.Errorf("listen %s %s", addr, network)
	}
	s := again
	if s.TogglePin("host:api.dev") || len(s.Pinned) != 0 {
		t.Fatal("unpin")
	}
	_ = os.WriteFile(path, []byte("{broken"), 0o600)
	if Open(path).Get().Port != 9090 {
		t.Fatal("broken file not ignored")
	}
}
