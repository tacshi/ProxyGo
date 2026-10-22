package session

import (
	"path/filepath"
	"testing"

	"proxygo/internal/flow"
)

func TestSavedRoundTrip(t *testing.T) {
	f := flow.New("saved-flow")
	f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, Scheme: "http", Host: "example.com", Port: 80, FullPath: "http://example.com/"}
	f.Saved = true

	path := filepath.Join(t.TempDir(), "saved.proxygosession")
	if err := Write(path, []*flow.Flow{f}, nil); err != nil {
		t.Fatal(err)
	}
	b, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Flows) != 1 {
		t.Fatalf("got %d flows", len(b.Flows))
	}
	if !b.Flows[0].Saved {
		t.Fatal("Saved flag did not survive the session round trip")
	}
}
