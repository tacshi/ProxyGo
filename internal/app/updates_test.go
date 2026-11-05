package app

import (
	"net/url"
	"strconv"
	"testing"

	"proxygo/internal/proxy"
)

func TestUpdatesSkipOwnProxy(t *testing.T) {
	a, _ := testApp(t)
	s := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Rules: a.rules, Sink: a.store, Certs: a.certs})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	port := strconv.Itoa(s.Port())
	for raw, want := range map[string]bool{
		"http://127.0.0.1:" + port:   true,
		"http://localhost:" + port:   true,
		"http://[::1]:" + port:       true,
		"http://127.0.0.1:1":         false,
		"http://10.0.0.8:" + port:    false,
		"http://proxy.corp:" + port:  false,
		"socks5://127.0.0.1:" + port: true,
	} {
		u, _ := url.Parse(raw)
		if got := ownProxy(u, s); got != want {
			t.Errorf("ownProxy(%s) = %v, want %v", raw, got, want)
		}
	}
	if u, _ := url.Parse("http://127.0.0.1:" + port); ownProxy(u, nil) {
		t.Error("a proxy counts as ProxyGo's before ProxyGo serves")
	}
}
