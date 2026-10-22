package session

import (
	"archive/zip"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxygo/internal/flow"
)

func sampleFlows() []*flow.Flow {
	start, end := 1700000000.5, 1700000000.75
	a := flow.New("AAAA0001")
	a.Timing = flow.Timing{RequestStartedAt: &start, ResponseEndedAt: &end}
	a.Client = flow.Client{Name: "Safari", Path: "/Applications/Safari.app"}
	a.Request = &flow.Request{
		Scheme: "https", Host: "api.dev", Port: 443, IsSSL: true, Version: flow.Version{Major: 2},
		FullPath: "https://api.dev/users?page=2", URI: "/users?page=2", Method: flow.Method{Name: "POST"},
		Header:   flow.NewHeader(http.Header{"Host": {"api.dev"}, "Content-Type": {"application/json"}, "Cookie": {"s=1"}}),
		BodyData: flow.Blob(`{"name":"a"}`),
	}
	a.Response = &flow.Response{
		Status: &flow.Status{Code: 201, Phrase: "Created"}, Version: flow.Version{Major: 2},
		Header:   flow.NewHeader(http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"t=2"}}),
		BodyData: flow.Blob(`{"id":1}`),
	}
	a.Comment, a.Highlight, a.Saved = "first", "green", true

	s2, e2 := 1700000001.0, 1700000001.1
	b := flow.New("BBBB0002")
	b.Timing = flow.Timing{RequestStartedAt: &s2, ResponseEndedAt: &e2}
	b.Request = &flow.Request{Scheme: "http", Host: "img.dev", Port: 80, FullPath: "http://img.dev/a.png", URI: "/a.png", Method: flow.Method{Name: "GET"}}
	b.Response = &flow.Response{Status: &flow.Status{Code: 200}, Header: flow.NewHeader(http.Header{"Content-Type": {"image/png"}}), BodyData: flow.Blob{0x89, 'P', 'N', 'G', 0, 1, 2}}

	e := flow.New("CCCC0003")
	e.Timing = flow.Timing{RequestStartedAt: new(1700000002.0)}
	e.Request = &flow.Request{Scheme: "https", Host: "down.dev", Port: 443, FullPath: "https://down.dev/", URI: "/", Method: flow.Method{Name: "GET"}}
	e.Response = &flow.Response{Status: &flow.Status{Code: 999, Phrase: "Error"}, Error: flow.ResponseError{"couldNotConnectToServer": map[string]any{"message": "refused"}}}
	return []*flow.Flow{b, a, e}
}

func TestBundleRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.proxygosession")
	if err := Write(path, sampleFlows(), map[string]string{"/Applications/Safari.app": "iVBOR"}); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	zr.Close()
	for _, n := range []string{"SharedFlowStorage", "SourceListData", "AppIconStorage", "Overview"} {
		if !names[n] {
			t.Fatalf("missing %s", n)
		}
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Flows) != 3 || b.Icons["/Applications/Safari.app"] != "iVBOR" {
		t.Fatalf("%d flows, icons %v", len(b.Flows), b.Icons)
	}
	a := b.Flows[0]
	if a.UniqueID != "AAAA0001" || a.ID != "1" {
		t.Fatalf("not sorted by start: %s %s", a.UniqueID, a.ID)
	}
	if string(a.Request.BodyData) != `{"name":"a"}` || a.StatusCode() != 201 {
		t.Fatal("bodies or status lost")
	}
	if a.Comment != "first" || a.Highlight != "green" || !a.Saved || a.HTTPVersionLabel() != "h2" {
		t.Fatalf("user fields %+v", a)
	}
	if !b.Flows[2].IsError() || b.Flows[2].ErrorText() != "refused" {
		t.Fatal("error flow")
	}
	if string(b.Flows[1].Response.BodyData) != "\x89PNG\x00\x01\x02" {
		t.Fatal("binary body")
	}
}

func TestHARRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.har")
	if err := WriteHAR(path, sampleFlows()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["log"].(map[string]any)["entries"].([]any)
	if len(entries) != 3 {
		t.Fatalf("%d entries", len(entries))
	}
	flows, err := ReadHAR(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 3 {
		t.Fatalf("%d flows", len(flows))
	}
	a := flows[0]
	if a.URL() != "https://api.dev/users?page=2" || a.MethodName() != "POST" || a.StatusCode() != 201 {
		t.Fatalf("flow %s %s %d", a.MethodName(), a.URL(), a.StatusCode())
	}
	if string(a.Request.BodyData) != `{"name":"a"}` || string(a.Response.BodyData) != `{"id":1}` || a.Comment != "first" {
		t.Fatal("HAR bodies")
	}
	if a.HTTPVersionLabel() != "h2" || a.Duration().Milliseconds() != 250 {
		t.Fatalf("version %s duration %v", a.HTTPVersionLabel(), a.Duration())
	}
	if string(flows[1].Response.BodyData) != "\x89PNG\x00\x01\x02" {
		t.Fatal("base64 body")
	}
	if !flows[2].IsError() {
		t.Fatal("HAR error entry")
	}
	if _, err := ReadHAR(filepath.Join(t.TempDir(), "missing.har")); err == nil {
		t.Fatal("missing file read")
	}
}

func TestCSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.csv")
	flows := sampleFlows()
	for i, f := range flows {
		f.ID = string(rune('1' + i))
	}
	flows[0].Timing.RequestStartedAt, flows[0].Timing.ResponseEndedAt = new(10.0), new(10.00025)
	if err := WriteCSV(path, flows); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rows[0][1] != "URL" || rows[2][1] != "https://api.dev/users?page=2" || rows[2][4] != "201 Created" {
		t.Fatalf("rows %v", rows)
	}
	if rows[0][7] != "Duration (ms)" || rows[1][7] != "0.25" {
		t.Fatalf("duration %q", rows[1][7])
	}
}

func TestCharles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.chlsj")
	doc := `[{"status":"COMPLETE","method":"GET","protocolVersion":"HTTP/1.1","scheme":"https","host":"api.dev","actualPort":443,
	"path":"/v1","query":"a=1","remoteAddress":"api.dev/1.2.3.4","notes":"hi",
	"times":{"start":"2024-01-02T03:04:05.000Z","responseBegin":"2024-01-02T03:04:05.100Z","end":"2024-01-02T03:04:05.200Z"},
	"request":{"header":{"headers":[{"name":"Accept","value":"*/*"}]}},
	"response":{"status":200,"header":{"headers":[{"name":"Content-Type","value":"text/plain"}]},"body":{"text":"aGVsbG8=","encoded":true}}},
	{"status":"FAILED","method":"GET","scheme":"http","host":"down.dev","path":"/","errorMessage":"refused"}]`
	os.WriteFile(path, []byte(doc), 0o644)
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Flows) != 2 {
		t.Fatalf("%d flows", len(b.Flows))
	}
	var ok *flow.Flow
	for _, f := range b.Flows {
		if f.Host() == "api.dev" {
			ok = f
		}
	}
	if ok == nil || ok.URL() != "https://api.dev/v1?a=1" || string(ok.Response.BodyData) != "hello" || ok.Comment != "hi" || ok.Duration().Milliseconds() != 200 {
		t.Fatalf("charles flow %+v", ok)
	}
}

func TestSavedSessions(t *testing.T) {
	dir, _ := os.UserConfigDir()
	matches, _ := filepath.Glob(filepath.Join(dir, "ProxyGo", "*"+Ext))
	if len(matches) == 0 {
		t.Skip("no saved sessions")
	}
	for _, m := range matches {
		b, err := Read(m)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		out := filepath.Join(t.TempDir(), "again.proxygosession")
		if err := Write(out, b.Flows, b.Icons); err != nil {
			t.Fatal(err)
		}
		again, err := Read(out)
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Flows) != len(b.Flows) {
			t.Fatalf("%s: %d flows became %d", m, len(b.Flows), len(again.Flows))
		}
		for i := range b.Flows {
			x, _ := json.Marshal(b.Flows[i])
			y, _ := json.Marshal(again.Flows[i])
			if strings.Compare(string(x), string(y)) != 0 {
				t.Fatalf("%s: flow %d changed", m, i)
			}
		}
	}
}

func TestUnfinishedFlowsReadBackIncomplete(t *testing.T) {
	flows := sampleFlows()
	open := flows[2].Clone()
	open.UniqueID, open.Response = "OPEN0001", nil
	path := filepath.Join(t.TempDir(), "s.proxygosession")
	if err := Write(path, append(flows, open), nil); err != nil {
		t.Fatal(err)
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range b.Flows {
		if f.IsActive() {
			t.Fatalf("%s is active after reading", f.UniqueID)
		}
		if f.IsIncomplete() != (f.UniqueID == "OPEN0001") {
			t.Fatalf("%s: incomplete %v", f.UniqueID, f.IsIncomplete())
		}
	}
}

func TestHARWebSocketMessages(t *testing.T) {
	f := flow.New("WS000001")
	f.Request = &flow.Request{Scheme: "ws", Host: "chat.dev", Port: 80, FullPath: "ws://chat.dev/socket", URI: "/socket", Method: flow.Method{Name: "GET"},
		Header: flow.NewHeader(http.Header{"Upgrade": {"websocket"}})}
	f.Response = &flow.Response{Status: &flow.Status{Code: 101, Phrase: "Switching Protocols"}, Header: flow.NewHeader(http.Header{"Upgrade": {"websocket"}})}
	f.WebSocketMessageStorage = &flow.WebSocketStorage{Messages: []flow.WebSocketMessage{
		{From: "client", Type: "text", Data: "hi", Time: 1},
		{From: "server", Type: "binary", RawData: []byte{0, 1, 2}, Time: 2},
	}}
	path := filepath.Join(t.TempDir(), "ws.har")
	if err := WriteHAR(path, []*flow.Flow{f}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"_webSocketMessages"`) || !strings.Contains(string(raw), `"type": "send"`) && !strings.Contains(string(raw), `"type":"send"`) {
		t.Fatalf("no WebSocket messages in %s", raw)
	}
	flows, err := ReadHAR(path)
	if err != nil || len(flows) != 1 {
		t.Fatalf("%v %d", err, len(flows))
	}
	got := flows[0].WebSocketMessageStorage
	if got == nil || len(got.Messages) != 2 || got.Messages[0].Data != "hi" || got.Messages[0].From != "client" ||
		got.Messages[1].Type != "binary" || string(got.Messages[1].RawData) != "\x00\x01\x02" {
		t.Fatalf("messages %+v", got)
	}
}
