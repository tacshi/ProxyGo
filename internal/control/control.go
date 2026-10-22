package control

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxygo/internal/certs"
	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/store"
)

type Host interface {
	Store() *store.Store
	Rules() *rules.Store
	Proxy() *proxy.Server
	Certs() *certs.Manager
	Version() string
	ProxyAddress() (host string, port int)
	Recording() bool
	SetRecording(on bool)
	SystemProxy() bool
	SetSystemProxy(on bool) error
	ClearSession()
	Selected() []*flow.Flow
	MCP() bool
	SetMCP(on bool) error
	Open(window string) error
	Export(path, format string, flows []*flow.Flow) error
}

type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func RunDir(dataDir string) string        { return filepath.Join(dataDir, "run") }
func SocketPath(dataDir string) string    { return filepath.Join(RunDir(dataDir), "control.sock") }
func MCPSocketPath(dataDir string) string { return filepath.Join(RunDir(dataDir), "mcp.sock") }

func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs its search bit; only this user gets it.
		return nil, err
	}
	if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
		_ = c.Close()
		return nil, fmt.Errorf("another ProxyGo is listening on %s", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

type Server struct {
	host Host
	path string
	ln   net.Listener
	wg   sync.WaitGroup
}

func Serve(host Host, path string) (*Server, error) {
	ln, err := Listen(path)
	if err != nil {
		return nil, err
	}
	s := &Server{host: host, path: path, ln: ln}
	s.wg.Go(s.accept)
	return s, nil
}

func (s *Server) Close() {
	_ = s.ln.Close()
	s.wg.Wait()
	_ = os.Remove(s.path)
}

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
	var req Request
	if err := json.NewDecoder(io.LimitReader(c, 16<<20)).Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(Response{Error: "bad request: " + err.Error()})
		return
	}
	result, err := Call(s.host, req.Method, req.Params)
	resp := Response{}
	if err != nil {
		resp.Error = err.Error()
	} else if result != nil {
		b, merr := json.Marshal(result)
		if merr != nil {
			resp.Error = merr.Error()
		} else {
			resp.Result = b
		}
	}
	_ = json.NewEncoder(c).Encode(resp)
}

func Dial(ctx context.Context, path, method string, params any) (json.RawMessage, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, ErrNotRunning
	}
	defer func() { _ = c.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(c).Encode(Request{Method: method, Params: raw}); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, fmt.Errorf("ProxyGo did not answer: %w", err)
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Result, nil
}

var ErrNotRunning = errors.New("ProxyGo is not running: open it, then try again")

func params[T any](raw json.RawMessage) (T, error) {
	var p T
	if len(raw) == 0 || string(raw) == "null" {
		return p, nil
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("bad parameters: %w", err)
	}
	return p, nil
}

type Status struct {
	Version       string `json:"version"`
	Recording     bool   `json:"recording"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	SocksPort     int    `json:"socksPort,omitempty"`
	SystemProxy   bool   `json:"systemProxy"`
	HTTPVersion   string `json:"httpVersionMode"`
	SSLProxying   bool   `json:"sslProxying"`
	MCP           bool   `json:"mcp"`
	Flows         int    `json:"flows"`
	CertTrusted   *bool  `json:"certificateTrusted,omitempty"`
	CertificateCN string `json:"certificate,omitempty"`
}

func StatusOf(h Host) Status {
	d := h.Rules().Current()
	host, port := h.ProxyAddress()
	st := Status{
		Version: h.Version(), Recording: h.Recording(), Host: host, Port: port, SocksPort: h.Proxy().SocksPort(),
		SystemProxy: h.SystemProxy(), HTTPVersion: d.HTTPVersionMode(), SSLProxying: d.SSL.Enabled,
		MCP: h.MCP(), Flows: h.Store().Len(),
	}
	if c := h.Certs(); c != nil {
		st.CertificateCN = c.CommonName()
	}
	return st
}

func Call(h Host, method string, raw json.RawMessage) (any, error) {
	type onOff struct {
		On bool `json:"on"`
	}
	switch method {
	case "status":
		return StatusOf(h), nil
	case "proxy.host":
		host, port := h.ProxyAddress()
		return map[string]any{"host": host, "port": port}, nil
	case "proxy.set":
		p, err := params[onOff](raw)
		if err != nil {
			return nil, err
		}
		return nil, h.SetSystemProxy(p.On)
	case "recording.set":
		p, err := params[onOff](raw)
		if err != nil {
			return nil, err
		}
		h.SetRecording(p.On)
		return nil, nil
	case "session.clear":
		h.ClearSession()
		return nil, nil
	case "session.export":
		p, err := params[struct {
			Path    string   `json:"path"`
			Format  string   `json:"format"`
			Domains []string `json:"domains"`
			Since   string   `json:"since"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(p.Path) {
			return nil, errors.New("the output path must be absolute")
		}
		flows := FilterExport(h.Store().Snapshot(), p.Domains, p.Since)
		if err := h.Export(p.Path, cmp.Or(p.Format, "proxygosession"), flows); err != nil {
			return nil, err
		}
		return map[string]any{"path": p.Path, "flows": len(flows)}, nil
	case "http.version":
		return map[string]string{"mode": h.Rules().Current().HTTPVersionMode()}, nil
	case "http.version.set":
		p, err := params[struct {
			Mode string `json:"mode"`
		}](raw)
		if err != nil {
			return nil, err
		}
		var setErr error
		h.Rules().Update(func(d *rules.Data) { setErr = d.SetHTTPVersionMode(p.Mode) })
		if setErr != nil {
			return nil, setErr
		}
		return map[string]string{"mode": h.Rules().Current().HTTPVersionMode()}, nil
	case "tool.set":
		p, err := params[struct {
			Tool string `json:"tool"`
			On   bool   `json:"on"`
		}](raw)
		if err != nil {
			return nil, err
		}
		return nil, SetTool(h.Rules(), p.Tool, p.On)
	case "tool.status":
		return ToolStatus(h.Rules().Current()), nil
	case "open":
		p, err := params[struct {
			Window string `json:"window"`
		}](raw)
		if err != nil {
			return nil, err
		}
		return nil, h.Open(p.Window)
	case "external.set":
		p, err := params[struct {
			On    bool    `json:"on"`
			HTTP  *string `json:"http"`
			HTTPS *string `json:"https"`
			PAC   *string `json:"pac"`
		}](raw)
		if err != nil {
			return nil, err
		}
		h.Rules().Update(func(d *rules.Data) {
			d.Upstream.Enabled = p.On
			if p.HTTP != nil {
				d.Upstream.HTTP = *p.HTTP
			}
			if p.HTTPS != nil {
				d.Upstream.HTTPS = *p.HTTPS
			}
			if p.PAC != nil {
				d.Upstream.PACURL = *p.PAC
			}
		})
		return h.Rules().Current().Upstream, nil
	case "rules.export":
		p, err := params[struct {
			Path        string `json:"path"`
			EnabledOnly bool   `json:"enabledOnly"`
		}](raw)
		if err != nil {
			return nil, err
		}
		return nil, ExportRules(h.Rules(), p.Path, p.EnabledOnly)
	case "rules.import":
		p, err := params[struct {
			Path     string `json:"path"`
			Override bool   `json:"override"`
		}](raw)
		if err != nil {
			return nil, err
		}
		return nil, ImportRules(h.Rules(), p.Path, p.Override)
	case "rules.list", "rules.get", "rules.create", "rules.update", "rules.delete", "rules.enable", "rules.disable":
		p, err := params[struct {
			Tool string          `json:"tool"`
			ID   string          `json:"id"`
			Rule json.RawMessage `json:"rule"`
		}](raw)
		if err != nil {
			return nil, err
		}
		return RuleCall(h.Rules(), strings.TrimPrefix(method, "rules."), p.Tool, p.ID, p.Rule)
	case "mcp.set":
		p, err := params[onOff](raw)
		if err != nil {
			return nil, err
		}
		return nil, h.SetMCP(p.On)
	case "cert.install-root":
		p, err := params[struct {
			Path     string `json:"path"`
			Password string `json:"password"`
		}](raw)
		if err != nil {
			return nil, err
		}
		c := h.Certs()
		if c == nil {
			return nil, errors.New("ProxyGo has no certificate authority")
		}
		data, err := os.ReadFile(p.Path)
		if err != nil {
			return nil, err
		}
		if err := c.ImportRootP12(data, p.Password); err != nil {
			return nil, err
		}
		return map[string]string{"certificate": c.CommonName(), "sha256": c.Fingerprint()}, nil
	case "cert.trust":
		c := h.Certs()
		if c == nil {
			return nil, errors.New("ProxyGo has no certificate authority")
		}
		if err := c.Install(); err != nil {
			return nil, err
		}
		return map[string]any{"certificate": c.CommonName(), "trusted": c.Trusted()}, nil
	case "cert.add", "cert.remove", "cert.replace":
		p, err := params[CertParams](raw)
		if err != nil {
			return nil, err
		}
		return CertCall(h, strings.TrimPrefix(method, "cert."), p)
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

func FilterExport(flows []*flow.Flow, domains []string, since string) []*flow.Flow {
	if since != "" {
		for i, f := range flows {
			if f.ID == since || f.UniqueID == since {
				flows = flows[i+1:]
				break
			}
		}
	}
	if len(domains) == 0 {
		return flows
	}
	var out []*flow.Flow
	for _, f := range flows {
		for _, d := range domains {
			if strings.EqualFold(f.Host(), d) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}
