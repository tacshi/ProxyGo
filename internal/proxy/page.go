package proxy

import (
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
)

var certHosts = []string{"proxy.go", "proxygo.ssl", "cert.proxygo.io"}

func isCertHost(hostport string) bool {
	host, _ := splitHostPort(hostport, 80)
	host = strings.ToLower(host)
	for _, h := range certHosts {
		if host == h {
			return true
		}
	}
	return false
}

func (s *Server) servePage(w http.ResponseWriter, r *http.Request) {
	if s.opts.Certs == nil {
		http.Error(w, "ProxyGo has no certificate authority", http.StatusServiceUnavailable)
		return
	}
	pemBytes := s.opts.Certs.CertPEM()
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case "/ssl", "/ssl.pem", "/cert", "/cert.pem", "/proxygo-ca.pem":
		writeCert(w, "proxygo-ca.pem", pemBytes)
		return
	case "/ssl.der", "/ssl.crt", "/cert.crt", "/proxygo-ca.crt", "/cert.der":
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			http.Error(w, "bad certificate", http.StatusInternalServerError)
			return
		}
		writeCert(w, "proxygo-ca.crt", block.Bytes)
		return
	case "", "/index.html":
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, certPage, html.EscapeString(s.opts.Certs.CommonName()), s.Port())
}

func writeCert(w http.ResponseWriter, name string, b []byte) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

const certPage = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProxyGo Certificate</title>
<style>
:root{color-scheme:light dark;--fg:#1d1d1f;--muted:#6e6e73;--card:#f5f5f7;--accent:#2f7cf6}
@media (prefers-color-scheme:dark){:root{--fg:#f5f5f7;--muted:#a1a1a6;--card:#1c1c1e}}
body{font:16px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;color:var(--fg);max-width:640px;margin:0 auto;padding:32px 20px}
h1{font-size:28px;margin:0 0 4px}p{color:var(--muted);margin:4px 0 16px}
.card{background:var(--card);border-radius:14px;padding:16px 20px;margin:14px 0}
.card h2{font-size:17px;margin:0 0 6px}.card ol{margin:6px 0 0;padding-left:20px;color:var(--muted)}
a.button{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;padding:10px 18px;border-radius:10px;font-weight:600;margin:4px 8px 4px 0}
a.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent)}
code{font-size:13px}
</style></head><body>
<h1>ProxyGo</h1>
<p>Install the root certificate <code>%s</code> to inspect HTTPS traffic from this device.</p>
<a class="button" href="/ssl.pem">Download Certificate (PEM)</a>
<a class="button secondary" href="/ssl.crt">Download for Android (CRT)</a>
<div class="card"><h2>iPhone and iPad</h2><ol>
<li>Download the PEM certificate in Safari and allow the profile.</li>
<li>Settings › General › VPN &amp; Device Management: install the ProxyGo profile.</li>
<li>Settings › General › About › Certificate Trust Settings: turn on full trust for ProxyGo.</li>
</ol></div>
<div class="card"><h2>Android</h2><ol>
<li>Tap Download for Android (CRT) above.</li>
<li>Settings › Security › Encryption &amp; credentials › Install a certificate › CA certificate.</li>
<li>Apps targeting Android 7 or later trust user certificates only when their network security configuration allows it.</li>
</ol></div>
<div class="card"><h2>Proxy</h2><p>Set this device's Wi-Fi HTTP proxy to this Mac's address, port %d.</p></div>
</body></html>`
