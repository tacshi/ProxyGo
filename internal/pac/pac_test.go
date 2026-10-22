package pac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const script = `
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || dnsDomainIs(host, ".local")) return "DIRECT";
  if (shExpMatch(host, "*.corp.example.com")) return "PROXY corp-proxy:8080; DIRECT";
  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "SOCKS5 socks.example.com:1080";
  if (url.indexOf("/secret") >= 0) return "HTTPS leak:1";
  if (weekdayRange("SAT", "SUN") && timeRange(0, 23)) return "PROXY weekend:3128";
  return "PROXY default:3128; HTTPS secure:443; DIRECT";
}`

func resolver(src string) (*Resolver, *int) {
	fetches := 0
	r := &Resolver{
		URL: "http://wpad/proxy.pac",
		Fetch: func(context.Context, string) ([]byte, error) {
			fetches++
			return []byte(src), nil
		},
		Lookup: func(_ context.Context, host string) ([]string, error) {
			if host == "intranet.example.com" {
				return []string{"10.1.2.3"}, nil
			}
			return []string{"93.184.216.34"}, nil
		},
		Now: func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
	}
	return r, &fetches
}

func TestFindProxy(t *testing.T) {
	r, fetches := resolver(script)
	for rawURL, want := range map[string]string{
		"http://printer/":                        "DIRECT",
		"http://nas.local/x":                     "DIRECT",
		"https://a.corp.example.com/x":           "PROXY corp-proxy:8080; DIRECT",
		"http://intranet.example.com/":           "SOCKS5 socks.example.com:1080",
		"https://api.example.com/secret?token=1": "PROXY default:3128; HTTPS secure:443; DIRECT",
		"http://api.example.com/secret":          "HTTPS leak:1",
	} {
		got, err := r.FindProxy(context.Background(), rawURL)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", rawURL, got, err, want)
		}
	}
	if *fetches != 1 {
		t.Errorf("fetched %d times", *fetches)
	}
	proxies := Proxies("PROXY default:3128; HTTPS secure:443; SOCKS s:1080; SOCKS4 old:1; DIRECT")
	if len(proxies) != 4 || proxies[0].String() != "http://default:3128" || proxies[1].Scheme != "https" || proxies[2].Scheme != "socks5" || proxies[3] != nil {
		t.Errorf("Proxies: %v", proxies)
	}
}

func TestFindProxyFailures(t *testing.T) {
	r, _ := resolver("function FindProxyForURL(u, h) { while (true) {} }")
	start := time.Now()
	if _, err := r.FindProxy(context.Background(), "http://x/"); err == nil || time.Since(start) > 3*time.Second {
		t.Errorf("an endless script: %v after %v", err, time.Since(start))
	}
	if _, err := r.FindProxy(context.Background(), "http://x/"); err == nil {
		t.Error("the script still loops")
	}
	r, _ = resolver("var x = 1;")
	if _, err := r.FindProxy(context.Background(), "http://x/"); err == nil || !strings.Contains(err.Error(), "FindProxyForURL") {
		t.Errorf("no function: %v", err)
	}
	r, _ = resolver(script)
	r.Fetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("offline") }
	if _, err := r.FindProxy(context.Background(), "http://x/"); err == nil {
		t.Error("an unreachable script")
	}
}

func TestRanges(t *testing.T) {
	wed := time.Date(2026, 10, 21, 13, 30, 15, 0, time.UTC)
	for i, tc := range []struct {
		fn   func(time.Time, []string) bool
		args []string
		want bool
	}{
		{weekdayRange, []string{"WED"}, true},
		{weekdayRange, []string{"MON", "FRI"}, true},
		{weekdayRange, []string{"FRI", "MON"}, false},
		{weekdayRange, []string{"SAT", "SUN", "GMT"}, false},
		{dateRange, []string{"21"}, true},
		{dateRange, []string{"OCT"}, true},
		{dateRange, []string{"2026"}, true},
		{dateRange, []string{"1", "15"}, false},
		{dateRange, []string{"SEP", "NOV"}, true},
		{dateRange, []string{"NOV", "FEB"}, false},
		{dateRange, []string{"1", "OCT", "31", "DEC"}, true},
		{dateRange, []string{"1", "JAN", "2020", "31", "DEC", "2025"}, false},
		{timeRange, []string{"13"}, true},
		{timeRange, []string{"9", "17"}, true},
		{timeRange, []string{"22", "6"}, false},
		{timeRange, []string{"13", "0", "13", "30"}, true},
		{timeRange, []string{"13", "30", "16", "13", "30", "14"}, false},
	} {
		if got := tc.fn(wed, tc.args); got != tc.want {
			t.Errorf("case %d (%v) = %v", i, tc.args, got)
		}
	}
}
