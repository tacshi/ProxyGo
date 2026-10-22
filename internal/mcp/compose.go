package mcp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
	"proxygo/internal/script"
)

type draft struct {
	mu  sync.Mutex
	ID  string        `json:"compose_id"`
	Msg proxy.Message `json:"-"`
}

func (d *draft) view() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	headers := map[string]string{}
	for _, e := range d.Msg.Header.Entries {
		if e.Enabled {
			headers[e.Key.Name] = e.Value
		}
	}
	return map[string]any{"compose_id": d.ID, "method": d.Msg.Method, "url": d.Msg.URL, "headers": headers, "body": string(d.Msg.Body)}
}

func (s *Server) newDraft(m proxy.Message) *draft {
	d := &draft{ID: "compose-" + rules.NewID(), Msg: m}
	s.drafts.Store(d.ID, d)
	return d
}

func (s *Server) draft(id string) (*draft, error) {
	v, ok := s.drafts.Load(id)
	if !ok {
		return nil, errors.New("no compose draft with that ID")
	}
	return v.(*draft), nil
}

func headerOf(m map[string]string) flow.Header {
	var h flow.Header
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

func (s *Server) addComposeTools() {
	srv := s.srv
	mcp.AddTool(srv, change("create_compose_http", "Compose Request", "A request to send later with send_compose_http, kept in memory.", false), func(_ context.Context, _ *mcp.CallToolRequest, in composeInput) (*mcp.CallToolResult, any, error) {
		if _, err := httpURL(in.URL); err != nil {
			return nil, nil, err
		}
		d := s.newDraft(proxy.Message{Method: strings.ToUpper(cmp.Or(in.Method, http.MethodGet)), URL: in.URL, Header: headerOf(in.Headers), Body: []byte(in.Body)})
		return jsonText(d.view())
	})
	mcp.AddTool(srv, change("create_compose_http_from_flow", "Compose from Flow", "A request to send later, as a captured flow's, to edit with update_compose_http.", false), func(_ context.Context, _ *mcp.CallToolRequest, in flowInput) (*mcp.CallToolResult, any, error) {
		f, err := s.flow(in.FlowID)
		if err != nil {
			return nil, nil, err
		}
		if f.IsTunnel() {
			return nil, nil, errors.New("an encrypted tunnel has no request to compose: enable SSL Proxying for its host")
		}
		d := s.newDraft(proxy.MessageOf(f))
		v := d.view()
		if s.Redact() {
			h, _ := redactHeader(d.Msg.Header)
			hs := map[string]string{}
			for _, e := range h.Entries {
				hs[e.Key.Name] = e.Value
			}
			v["headers"] = hs
			v["note"] = "Credentials show redacted here; the draft keeps them and sends them."
		}
		return jsonText(v)
	})
	mcp.AddTool(srv, readOnly("get_compose_http", "Compose Draft", "A compose draft's request."), func(_ context.Context, _ *mcp.CallToolRequest, in composeIDInput) (*mcp.CallToolResult, any, error) {
		d, err := s.draft(in.ComposeID)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(d.view())
	})
	mcp.AddTool(srv, change("update_compose_http", "Edit Compose Draft", "Change a draft's method, URL, headers or body.", false), func(_ context.Context, _ *mcp.CallToolRequest, in updateComposeInput) (*mcp.CallToolResult, any, error) {
		d, err := s.draft(in.ComposeID)
		if err != nil {
			return nil, nil, err
		}
		if in.URL != "" {
			if _, err := httpURL(in.URL); err != nil {
				return nil, nil, err
			}
		}
		d.mu.Lock()
		if in.Method != "" {
			d.Msg.Method = strings.ToUpper(in.Method)
		}
		if in.URL != "" {
			d.Msg.URL = in.URL
		}
		for k, v := range in.Headers {
			if v == "" {
				d.Msg.Header.Del(k)
			} else {
				d.Msg.Header.Set(k, v)
			}
		}
		if in.Body != nil {
			d.Msg.Body = []byte(*in.Body)
		}
		d.mu.Unlock()
		return jsonText(d.view())
	})
	mcp.AddTool(srv, change("delete_compose_http", "Delete Compose Draft", "Forget a draft.", false), func(_ context.Context, _ *mcp.CallToolRequest, in composeIDInput) (*mcp.CallToolResult, any, error) {
		s.drafts.Delete(in.ComposeID)
		return text("Deleted %s", in.ComposeID)
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "send_compose_http", Description: "Send a draft through ProxyGo, its tools applying, and return the flow it made. It reaches the network.",
		Annotations: &mcp.ToolAnnotations{Title: "Send Compose Draft", DestructiveHint: new(false), OpenWorldHint: new(true)}},
		func(ctx context.Context, _ *mcp.CallToolRequest, in sendComposeInput) (*mcp.CallToolResult, any, error) {
			d, err := s.draft(in.ComposeID)
			if err != nil {
				return nil, nil, err
			}
			d.mu.Lock()
			msg := d.Msg
			msg.Header = d.Msg.Header.Clone()
			d.mu.Unlock()
			timeout := time.Duration(clamp(in.TimeoutSeconds, 60, 600)) * time.Second
			f, err := s.host.Proxy().ReplayWith(ctx, msg, proxy.ReplayOptions{Timeout: timeout, FollowRedirects: in.FollowRedirects})
			if err != nil {
				return nil, nil, err
			}
			return jsonText(s.detail(f, 64<<10, false))
		})
}

func httpURL(raw string) (string, error) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", errors.New("the URL must start with http:// or https://")
	}
	return raw, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func filepathStat(p string) (os.FileInfo, error) { return os.Stat(p) }

func scriptCheck(name, src string) error { return script.Check(name, src) }

func (s *Server) addResources() {
	s.srv.AddResource(&mcp.Resource{Name: "scripting", Title: "ProxyGo Scripting", URI: "proxygo://docs/scripting", MIMEType: "text/markdown",
		Description: "How ProxyGo's scripts change requests and responses: the handlers, their objects, the globals and the addons."},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "proxygo://docs/scripting", MIMEType: "text/markdown", Text: script.Reference()}}}, nil
		})
}
