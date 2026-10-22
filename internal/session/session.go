package session

import (
	"archive/zip"
	"bytes"
	"cmp"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"proxygo/internal/flow"
)

var wire = jsonv1.DefaultOptionsV1()

type Bundle struct {
	Flows []*flow.Flow
	Icons map[string]string
}

const Ext = ".proxygosession"

var Extensions = []string{"proxygosession", "har", "chlsj", "chls", "chlsx", "proxymansessionv2"}

func Open(path string) (*Bundle, error) {
	var b *Bundle
	var err error
	switch strings.ToLower(filepath.Ext(path)) {
	case ".har":
		var flows []*flow.Flow
		flows, err = ReadHAR(path)
		b = &Bundle{Flows: flows, Icons: map[string]string{}}
	case ".chlsj":
		var flows []*flow.Flow
		flows, err = ReadCharles(path)
		b = &Bundle{Flows: flows, Icons: map[string]string{}}
	case ".chls", ".chlsx":
		var flows []*flow.Flow
		flows, err = ReadCharlesSession(path)
		b = &Bundle{Flows: flows, Icons: map[string]string{}}
	default:
		b, err = Read(path)
	}
	if b != nil {
		for _, f := range b.Flows {
			f.MarkIncomplete()
		}
	}
	return b, err
}

func Read(path string) (*Bundle, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("not a session file: %w", err)
	}
	defer zr.Close()

	b := &Bundle{Icons: map[string]string{}}
	for _, f := range zr.File {
		switch f.Name {
		case "SharedFlowStorage", "AppIconStorage":
		default:
			continue
		}
		data, err := readZipFile(f)
		if err != nil {
			return nil, err
		}
		switch f.Name {
		case "SharedFlowStorage":
			var stored map[string]*flow.Flow
			if err := json.Unmarshal(data, &stored, wire); err != nil {
				return nil, fmt.Errorf("SharedFlowStorage: %w", err)
			}
			for _, fl := range stored {
				if fl != nil && fl.Request != nil {
					b.Flows = append(b.Flows, fl)
				}
			}
		case "AppIconStorage":
			var icons map[string]struct {
				ImageWrapper struct {
					Image string `json:"image"`
				} `json:"imageWrapper"`
			}
			if json.Unmarshal(data, &icons, wire) == nil {
				for path, icon := range icons {
					if icon.ImageWrapper.Image != "" {
						b.Icons[path] = icon.ImageWrapper.Image
					}
				}
			}
		}
	}
	sortFlows(b.Flows)
	return b, nil
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 1<<30))
}

func sortFlows(flows []*flow.Flow) {
	slices.SortStableFunc(flows, func(a, b *flow.Flow) int { return cmp.Compare(startedAt(a), startedAt(b)) })
	for i, f := range flows {
		f.Index = i
		f.ID = strconv.Itoa(i + 1)
		f.Name = f.ID
	}
}

func startedAt(f *flow.Flow) float64 {
	if f != nil && f.Timing.RequestStartedAt != nil {
		return *f.Timing.RequestStartedAt
	}
	return 0
}

func Write(path string, flows []*flow.Flow, icons map[string]string) error {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(name string, v any) error {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return err
		}
		return json.MarshalWrite(w, v, wire)
	}
	shared := make(map[string]*flow.Flow, len(flows))
	for i, f := range flows {
		c := *f
		c.Index, c.ID = i, strconv.Itoa(i+1)
		c.Name = c.ID
		shared[c.UniqueID] = &c
	}
	if err := put("SharedFlowStorage", shared); err != nil {
		return err
	}
	if err := put("SourceListData", sourceList(flows)); err != nil {
		return err
	}
	iconDoc := map[string]any{}
	for path, png := range icons {
		iconDoc[path] = map[string]any{"imageWrapper": map[string]string{"image": png}}
	}
	if err := put("AppIconStorage", iconDoc); err != nil {
		return err
	}
	if err := put("Overview", overview(flows)); err != nil {
		return err
	}
	for i, f := range flows {
		if f.ConnectionRecord == nil || f.Request == nil {
			continue
		}
		trace := map[string]any{
			"id": f.ConnectionRecord.TraceID, "host": f.Host(), "resolvedHost": f.Host(),
			"port": f.Request.Port, "state": "completed", "ipv4": []string{}, "ipv6": []string{},
			"events": []any{}, "number": i, "truncated": false,
		}
		if err := put(fmt.Sprintf("ConnectionTraces/trace_%d", i), trace); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return writeAtomic(path, buf.Bytes())
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	_ = os.Chmod(tmp.Name(), 0o644)
	return os.Rename(tmp.Name(), path)
}

func sourceList(flows []*flow.Flow) any {
	pinID := newUUID()
	favorites := map[string]any{
		"type": "FavoritesGroup", "title": "Favorites",
		"folders": []any{map[string]any{
			"id": pinID, "title": "Pinned", "mode": "fixed", "type": "PinFolder",
			"flowBox": map[string]any{"flowIDs": []string{}, "id": pinID}, "treeNodes": []any{},
		}},
	}
	type app struct {
		path    string
		bundle  *string
		ids     []string
		domains map[string][]string
	}
	apps := map[string]*app{}
	domains := map[string][]string{}
	var all []string
	for _, f := range flows {
		name := f.Client.Name
		if name == "" {
			name = "System"
		}
		a := apps[name]
		if a == nil {
			a = &app{path: f.Client.Path, bundle: f.Client.BundleIdentifier, domains: map[string][]string{}}
			apps[name] = a
		}
		a.ids = append(a.ids, f.UniqueID)
		a.domains[f.Host()] = append(a.domains[f.Host()], f.UniqueID)
		domains[f.Host()] = append(domains[f.Host()], f.UniqueID)
		all = append(all, f.UniqueID)
	}
	domainNode := func(d string, ids []string) any {
		return map[string]any{
			"id": "Domain-" + d, "name": d, "isEnabled": true, "nodes": []any{}, "flowIDs": ids,
			"kind": map[string]any{"domain": []any{map[string]any{"url": d, "title": d, "path": "", "isPath": false, "paths": []any{}}}},
		}
	}
	var appNodes []any
	for _, name := range slices.Sorted(maps.Keys(apps)) {
		a := apps[name]
		var nodes []any
		for _, d := range slices.Sorted(maps.Keys(a.domains)) {
			nodes = append(nodes, domainNode(d, a.domains[d]))
		}
		appNodes = append(appNodes, map[string]any{
			"name": name, "id": "Client-" + name, "isEnabled": true, "nodes": nodes, "flowIDs": a.ids,
			"kind": map[string]any{"client": []any{map[string]any{"name": name, "path": a.path, "bundleIdentifier": a.bundle, "iconPath": nil}}},
		})
	}
	var domainNodes []any
	for _, d := range slices.Sorted(maps.Keys(domains)) {
		domainNodes = append(domainNodes, domainNode(d, domains[d]))
	}
	appsID, domainsID := newUUID(), newUUID()
	return map[string]any{"groups": []any{favorites, map[string]any{
		"type": "AllGroup", "title": "All", "folders": []any{
			map[string]any{"id": appsID, "title": "Apps", "mode": "createNewClients", "type": "AllAppFolder",
				"flowBox": map[string]any{"flowIDs": all, "id": appsID}, "treeNodes": appNodes},
			map[string]any{"id": domainsID, "title": "Domains", "mode": "createNewDomains", "type": "AllDomainFolder",
				"flowBox": map[string]any{"flowIDs": all, "id": domainsID}, "treeNodes": domainNodes},
		},
	}}}
}

func overview(flows []*flow.Flow) any {
	upload, download := 0, 0
	status := map[string]int{"success": 0, "redirect": 0, "clientError": 0, "serverError": 0, "failed": 0, "pending": 0}
	apps := map[string]bool{}
	decrypted, plain, encrypted := 0, 0, 0
	for _, f := range flows {
		upload += f.RequestSize()
		download += f.ResponseSize()
		apps[f.Client.Name] = true
		code := f.StatusCode()
		switch {
		case f.IsError():
			status["failed"]++
		case f.IsActive() || code == 0:
			status["pending"]++
		case code >= 500:
			status["serverError"]++
		case code >= 400:
			status["clientError"]++
		case code >= 300:
			status["redirect"]++
		default:
			status["success"]++
		}
		switch {
		case f.IsTunnel():
			encrypted++
		case f.IsSSL:
			decrypted++
		default:
			plain++
		}
	}
	started := 0.0
	if len(flows) > 0 {
		started = startedAt(flows[0])
	}
	return map[string]any{
		"appCount": len(apps), "uploadBytes": upload, "downloadBytes": download,
		"slowestRequests": []any{}, "largestResponses": []any{},
		"timeline": []any{}, "contentTypes": []any{}, "status": status,
		"generatedAt": float64(time.Now().Unix()), "startedAt": started,
		"version": 1, "security": map[string]any{"decrypted": decrypted, "http": plain, "encrypted": encrypted},
		"durationHistogram": []int{0, 0, 0, 0, 0}, "bucketInterval": 1, "topApps": []any{},
	}
}

func newUUID() string { return strings.ToUpper(uuid.New().String()) }

var Formats = []string{"proxygosession", "har", "csv", "raw", "postman", "openapi", "openapi-html"}

func Export(path, format string, flows []*flow.Flow, icons map[string]string) error {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	switch strings.ToLower(format) {
	case "proxygosession", "proxygo":
		return Write(path, flows, icons)
	case "har":
		return WriteHAR(path, flows)
	case "csv":
		return WriteCSV(path, flows)
	case "raw":
		return WriteRaw(path, flows)
	case "postman":
		return WritePostman(path, name, flows)
	case "openapi", "openapi-yaml", "swagger":
		return WriteOpenAPI(path, name, flows)
	case "openapi-html":
		return WriteOpenAPIHTML(path, name, flows)
	}
	return fmt.Errorf("unknown format %q: use %s", format, strings.Join(Formats, ", "))
}
