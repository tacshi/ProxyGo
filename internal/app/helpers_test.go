package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"proxygo/internal/certs"
	"proxygo/internal/flow"
	"proxygo/internal/store"
)

type storeCondition = store.Condition

func TestMain(m *testing.M) {
	certs.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch cmd := name + " " + strings.Join(args, " "); {
		case strings.HasPrefix(cmd, "xcrun simctl list"):
			return []byte(`{"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-26-0":[{"udid":"SIM-1","name":"iPhone 17 Pro","state":"Booted"}]}}`), nil
		case strings.HasPrefix(cmd, "adb devices"):
			return []byte("List of devices attached\nemulator-5554 device product:sdk model:Pixel_9 device:emu\n"), nil
		}
		return nil, errors.New("not run in tests")
	}
	os.Exit(m.Run())
}

func newEcho(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.RequestURI(), b)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func inspectorFixtures() []*flow.Flow {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	jwt := enc(`{"alg":"RS256","typ":"JWT"}`) + "." + enc(`{"sub":"ada","exp":1700000000,"iat":1699996400,"scope":"read write"}`) + "." + enc("signature")
	start := 1_700_000_100.0
	k := flow.New("K1")
	k.IsSSL = true
	k.Client = flow.Client{Name: "Safari", PID: 42}
	k.Timing = flow.Timing{RequestStartedAt: new(start), ResponseEndedAt: new(start + 0.2)}
	k.Request = &flow.Request{Scheme: "https", Host: "auth.example.com", Port: 443, FullPath: "https://auth.example.com/me", URI: "/me", Method: flow.Method{Name: "GET"},
		Version: flow.Version{Major: 2}, Header: flow.NewHeader(http.Header{"Authorization": {"Bearer " + jwt}})}
	k.Response = &flow.Response{Status: &flow.Status{Code: 200, Phrase: "OK"}, Header: flow.NewHeader(http.Header{"Content-Type": {"application/json"}}), BodyData: flow.Blob(`{"ok":true}`)}
	k.TLS = &flow.TLSDetails{
		Client: &flow.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2", ServerName: "auth.example.com", Offered: []string{"h2", "http/1.1"}},
		Server: &flow.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_256_GCM_SHA384", ALPN: "h2", ServerName: "auth.example.com", Certificates: []flow.TLSCertificate{
			{Subject: "CN=auth.example.com", Issuer: "CN=Example Issuing CA,O=Example", DNSNames: []string{"auth.example.com", "*.example.com"}, NotBefore: time.Unix(1690000000, 0), NotAfter: time.Unix(1990000000, 0), SHA256: "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12"},
			{Subject: "CN=Example Issuing CA,O=Example", Issuer: "CN=Example Root,O=Example", NotBefore: time.Unix(1600000000, 0), NotAfter: time.Unix(2000000000, 0), SHA256: "00FF"},
		}},
	}
	l := flow.New("L2")
	l.Timing = flow.Timing{RequestStartedAt: new(start + 1), ResponseEndedAt: new(start + 3)}
	l.Request = &flow.Request{Scheme: "https", Host: "stream.example.com", Port: 443, FullPath: "https://stream.example.com/events", URI: "/events", Method: flow.Method{Name: "GET"}, Header: flow.NewHeader(http.Header{"Accept": {"text/event-stream"}})}
	l.Response = &flow.Response{Status: &flow.Status{Code: 200}, Header: flow.NewHeader(http.Header{"Content-Type": {"text/event-stream"}}),
		BodyData: flow.Blob(": ping\n\nevent: token\nid: 1\ndata: {\"delta\":\"Hel\"}\n\nevent: token\nid: 2\ndata: {\"delta\":\"lo\"}\n\nevent: done\ndata: [DONE]\nretry: 3000\n\n")}
	m := flow.New("M3")
	m.Timing = flow.Timing{RequestStartedAt: new(start + 4), ResponseEndedAt: new(start + 4.1)}
	m.Request = &flow.Request{Scheme: "https", Host: "rpc.example.com", Port: 443, FullPath: "https://rpc.example.com/state", URI: "/state", Method: flow.Method{Name: "GET"}}
	m.Response = &flow.Response{Status: &flow.Status{Code: 200}, Header: flow.NewHeader(http.Header{"Content-Type": {"application/msgpack"}}),
		BodyData: flow.Blob{0x82, 0xa4, 'n', 'a', 'm', 'e', 0xa3, 'A', 'd', 'a', 0xa4, 't', 'a', 'g', 's', 0x92, 0xa1, 'x', 0xa1, 'y'}}
	return []*flow.Flow{k, l, m}
}
