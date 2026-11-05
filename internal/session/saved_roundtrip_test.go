package session

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
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

func TestRoundTripKeepsOrderOfSimultaneousFlows(t *testing.T) {
	start := 1_792_744_794.986548
	var flows []*flow.Flow
	var want []string
	for i := range 8 {
		f := flow.New(fmt.Sprintf("SAME-%02d", 7-i))
		f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, Scheme: "https", Host: "example.com", Port: 443, FullPath: fmt.Sprintf("https://example.com/%d", i)}
		f.Timing.RequestStartedAt = new(start)
		flows = append(flows, f)
		want = append(want, f.UniqueID)
	}
	early := flow.New("EARLY")
	early.Request = &flow.Request{Method: flow.Method{Name: "GET"}, Scheme: "https", Host: "example.com", Port: 443, FullPath: "https://example.com/early"}
	early.Timing.RequestStartedAt = new(start - 1)
	flows = append([]*flow.Flow{early}, flows...)
	want = append([]string{early.UniqueID}, want...)

	path := filepath.Join(t.TempDir(), "same.proxygosession")
	for round := range 20 {
		if err := Write(path, flows, nil); err != nil {
			t.Fatal(err)
		}
		b, err := Read(path)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for i, f := range b.Flows {
			got = append(got, f.UniqueID)
			if f.ID != strconv.Itoa(i+1) {
				t.Fatalf("round %d: flow %d has ID %s", round, i, f.ID)
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("round %d: flows that started together came back as %v, want %v", round, got, want)
		}
		flows = b.Flows
	}
}
