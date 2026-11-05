package control

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedPeer(t *testing.T) {
	for _, c := range []struct {
		peer, self int
		want       bool
	}{
		{501, 501, true},
		{0, 501, false},
		{502, 501, false},
		{501, 0, true},
	} {
		if got := trustedPeer(c.peer, c.self); got != c.want {
			t.Errorf("trustedPeer(%d, %d) = %v, want %v", c.peer, c.self, got, c.want)
		}
	}
}

func TestDialSocketChecksThePeer(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := DialSocket(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	uid, err := peerUID(c)
	if err != nil || uid != os.Geteuid() {
		t.Errorf("peerUID = %d, %v; want %d", uid, err, os.Geteuid())
	}
}
