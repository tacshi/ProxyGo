package session

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/csv"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"proxygo/internal/flow"
)

func WriteCSV(path string, flows []*flow.Flow) error {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"ID", "URL", "Client", "Method", "Status", "Code", "Start Time", "Duration (ms)", "Request Size", "Response Size", "Content Type", "SSL", "Comment"})
	for _, f := range flows {
		if f == nil || f.Request == nil {
			continue
		}
		start := ""
		if t := f.RequestTime(); !t.IsZero() {
			start = t.Format(time.RFC3339Nano)
		}
		_ = w.Write([]string{
			f.ID, f.URL(), f.Client.Name, f.MethodName(), f.StatusLine(), strconv.Itoa(f.StatusCode()),
			start, strconv.FormatFloat(float64(f.Duration().Round(time.Microsecond).Microseconds())/1000, 'f', -1, 64),
			strconv.Itoa(f.RequestSize()), strconv.Itoa(f.ResponseSize()),
			f.ContentType(), strconv.FormatBool(f.IsHTTPS()), f.Comment,
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return writeAtomic(path, buf.Bytes())
}

type (
	charlesHeader struct {
		FirstLine string `json:"firstLine"`
		Headers   []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
	}
	charlesBody struct {
		Text     string `json:"text"`
		Encoded  bool   `json:"encoded"`
		Encoding string `json:"encoding"`
	}
	charlesPart struct {
		Status   int            `json:"status"`
		MimeType string         `json:"mimeType"`
		Header   *charlesHeader `json:"header"`
		Body     *charlesBody   `json:"body"`
	}
	charlesEntry struct {
		Status          string `json:"status"`
		Method          string `json:"method"`
		ProtocolVersion string `json:"protocolVersion"`
		Scheme          string `json:"scheme"`
		Host            string `json:"host"`
		Port            int    `json:"actualPort"`
		Path            string `json:"path"`
		Query           string `json:"query"`
		RemoteAddress   string `json:"remoteAddress"`
		ClientAddress   string `json:"clientAddress"`
		Notes           string `json:"notes"`
		Times           struct {
			Start         string `json:"start"`
			ResponseBegin string `json:"responseBegin"`
			End           string `json:"end"`
		} `json:"times"`
		Request  charlesPart `json:"request"`
		Response charlesPart `json:"response"`
		Error    string      `json:"errorMessage"`
	}
)

func ReadCharles(path string) ([]*flow.Flow, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the session file the user imports.
	if err != nil {
		return nil, err
	}
	var entries []charlesEntry
	if err := json.Unmarshal(data, &entries, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("not a Charles JSON session: %w", err)
	}
	flows := make([]*flow.Flow, 0, len(entries))
	for _, e := range entries {
		if e.Host == "" {
			continue
		}
		scheme := cmp.Or(strings.ToLower(e.Scheme), "http")
		port := e.Port
		if port == 0 {
			port = map[bool]int{true: 443, false: 80}[scheme == "https"]
		}
		host := e.Host
		if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
			host = host + ":" + strconv.Itoa(port)
		}
		u := url.URL{Scheme: scheme, Host: host, Path: cmp.Or(e.Path, "/"), RawQuery: e.Query}
		f := flow.New(flow.NewUniqueID())
		f.IsFromFile = true
		f.IsSSL = scheme == "https"
		f.Comment = e.Notes
		f.Client = flow.Client{Name: "Charles", PID: -1}
		f.Summary = flow.Summary{ServerIPAddress: hostOnly(e.RemoteAddress), ClientIPAddress: hostOnly(e.ClientAddress), ServerPort: port}
		if t, err := time.Parse(time.RFC3339Nano, e.Times.Start); err == nil {
			f.Timing.RequestStartedAt = new(float64(t.UnixNano()) / 1e9)
		}
		if t, err := time.Parse(time.RFC3339Nano, e.Times.ResponseBegin); err == nil {
			f.Timing.ResponseStartedAt = new(float64(t.UnixNano()) / 1e9)
		}
		if t, err := time.Parse(time.RFC3339Nano, e.Times.End); err == nil {
			f.Timing.ResponseEndedAt = new(float64(t.UnixNano()) / 1e9)
		}
		version := parseVersion(e.ProtocolVersion)
		f.Request = &flow.Request{
			Scheme: scheme, Port: port, IsSSL: f.IsSSL, Version: version, HTTPVersion: version.HTTPVersion(),
			FullPath: u.String(), URI: u.RequestURI(), Host: e.Host,
			Method: flow.Method{Name: strings.ToUpper(e.Method)}, Header: charlesHeaders(e.Request.Header),
			BodyData: charlesBytes(e.Request.Body),
		}
		switch {
		case e.Error != "" || strings.EqualFold(e.Status, "FAILED"):
			f.Response = &flow.Response{Status: &flow.Status{Code: 999, Phrase: "Error"},
				Error: flow.ResponseError{"couldNotConnectToServer": map[string]any{"message": cmp.Or(e.Error, "Failed")}}}
		case e.Response.Status > 0:
			f.Response = &flow.Response{
				Status: &flow.Status{Code: e.Response.Status}, Version: version, HTTPVersion: version.HTTPVersion(),
				Header: charlesHeaders(e.Response.Header), BodyData: charlesBytes(e.Response.Body),
			}
			f.Response.Header.Del("Content-Encoding")
		}
		flows = append(flows, f)
	}
	sortFlows(flows)
	return flows, nil
}

func charlesHeaders(h *charlesHeader) flow.Header {
	var out flow.Header
	if h == nil {
		return out
	}
	for _, kv := range h.Headers {
		out.Add(kv.Name, kv.Value)
	}
	return out
}

func charlesBytes(b *charlesBody) []byte {
	if b == nil || b.Text == "" {
		return nil
	}
	if b.Encoded || strings.EqualFold(b.Encoding, "base64") {
		if raw, err := base64.StdEncoding.DecodeString(b.Text); err == nil {
			return raw
		}
	}
	return []byte(b.Text)
}

func hostOnly(addr string) string {
	if i := strings.LastIndexByte(addr, '/'); i >= 0 {
		addr = addr[i+1:]
	}
	return addr
}
