package app

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"
	"github.com/egoist/mygo/proxygoui/editor"

	"proxygo/internal/curl"
	"proxygo/internal/flow"
	"proxygo/internal/formdata"
	"proxygo/internal/proxy"
)

const (
	bodyText = iota
	bodyJSON
	bodyForm
	bodyMultipart
)

var bodyKinds = []string{"Text", "JSON", "Form", "Multipart"}

const maxFilePart = 64 << 20

type partRow struct {
	id          int
	on          bool
	name, value string
	file        bool
	fileName    string
	contentType string
	data        []byte
}

func (e *messageEditor) partRows(parts []formdata.Part) {
	e.parts = nil
	for _, p := range parts {
		e.addPart(partRow{on: p.Enabled, name: p.Name, value: string(p.Value), file: p.FileName != "", fileName: p.FileName, contentType: p.ContentType, data: p.Value})
	}
}

func (e *messageEditor) addPart(r partRow) {
	e.nextPart++
	r.id = e.nextPart
	if !r.file {
		r.data = nil
	} else {
		r.value = ""
	}
	e.parts = append(e.parts, r)
}

func (e *messageEditor) formParts(multipart bool) []formdata.Part {
	var out []formdata.Part
	for _, r := range e.parts {
		if strings.TrimSpace(r.name) == "" {
			continue
		}
		p := formdata.Part{Name: r.name, Value: []byte(r.value), Enabled: r.on}
		if r.file {
			p.Value = []byte(r.fileName)
			if multipart {
				p.Value, p.FileName, p.ContentType = r.data, r.fileName, r.contentType
			}
		}
		out = append(out, p)
	}
	return out
}

func newComposeEditor(m proxy.Message) *messageEditor {
	e := newMessageEditor(m, false)
	e.compose = true
	ct := m.Header.Get("Content-Type")
	mt, _, _ := mime.ParseMediaType(ct)
	switch {
	case mt == "multipart/form-data":
		if parts, err := formdata.ParseMultipart(m.Body, ct, maxFilePart); err == nil {
			e.kind = bodyMultipart
			e.partRows(parts)
		}
	case mt == "application/x-www-form-urlencoded":
		e.kind = bodyForm
		e.partRows(formdata.ParseURLEncoded(m.Body))
	case isJSON(mt, m.Body):
		e.kind = bodyJSON
	}
	return e
}

func (e *messageEditor) setKind(kind int) {
	from := e.kind
	e.kind = kind
	text := e.body.Buffer.String()
	switch kind {
	case bodyText, bodyJSON:
		if from >= bodyForm && strings.TrimSpace(text) == "" {
			if kind == bodyText {
				e.body.Buffer.Set(string(formdata.URLEncoded(e.formParts(false))))
			}
		}
		ct := map[int]string{bodyText: "text/plain", bodyJSON: "application/json"}[kind]
		e.body.Buffer.SetLanguage(languageFor(ct))
		if old := e.header("Content-Type"); old == "" || kind == bodyJSON || isFormType(old) {
			e.setHeader("Content-Type", ct)
		}
	case bodyForm, bodyMultipart:
		if len(e.parts) == 0 && strings.Contains(text, "=") && from < bodyForm {
			e.partRows(formdata.ParseURLEncoded([]byte(strings.TrimSpace(text))))
		}
		if len(e.parts) == 0 {
			e.addPart(partRow{on: true})
		}
		e.setHeader("Content-Type", map[int]string{bodyForm: "application/x-www-form-urlencoded", bodyMultipart: "multipart/form-data"}[kind])
	}
}

func isFormType(ct string) bool {
	mt, _, _ := mime.ParseMediaType(ct)
	return mt == "application/x-www-form-urlencoded" || mt == "multipart/form-data"
}

func (e *messageEditor) header(name string) string {
	for _, h := range e.headers {
		if h.on && strings.EqualFold(h.name, name) {
			return h.value
		}
	}
	return ""
}

func (a *App) formView(c *ui.Context, e *messageEditor) {
	p := a.pal
	multipart := e.kind == bodyMultipart
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(8, inset).Gap(4).Children(func() {
			remove := -1
			for i := range e.parts {
				r := &e.parts[i]
				ui.Row(c.Key(r.id)).Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Checkbox(c, &r.on, "").Label("Send this field")
					ui.TextInput(c, &r.name).Placeholder("Name").Label("Field name").Width(170)
					if multipart {
						kind := map[bool]int{true: 1}[r.file]
						if ui.Segmented(c, &kind, "Text", "File").Label("Field kind").Changed() {
							r.file = kind == 1
						}
					}
					switch {
					case r.file && multipart:
						label := r.fileName
						if label == "" {
							label = "No file chosen"
						}
						ui.Text(c, label).TextColor(map[bool]ui.Color{true: p.faint, false: p.text2}[r.fileName == ""]).Grow(1).SingleLine()
						if r.fileName != "" {
							ui.Text(c, formatSize(len(r.data))+" · "+r.contentType).FontSize(11).TextColor(p.muted).SingleLine()
						}
						if ui.Button(c, "Choose…").Clicked() {
							a.chooseFilePart(e, r.id)
						}
					default:
						ui.TextInput(c, &r.value).Placeholder("Value").Label("Field value").Grow(1)
					}
					if plainIconButton(c, "minus", "Remove Field", 12, p.muted, p.hover).Clicked() {
						remove = i
					}
				})
			}
			if remove >= 0 {
				e.parts = slices.Delete(e.parts, remove, remove+1)
			}
			ui.Row(c).Gap(8).Padding(4, 0).Children(func() {
				if ui.Button(c, "Add Field").Clicked() {
					e.addPart(partRow{on: true})
				}
				if multipart && ui.Button(c, "Add File…").Clicked() {
					a.chooseFilePart(e, 0)
				}
			})
		})
	})
}

func (a *App) chooseFilePart(e *messageEditor, id int) {
	parent := a.windows["compose"]
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Title: "Choose a File to Send"})
		if err != nil || len(paths) == 0 {
			return
		}
		path := paths[0]
		data, err := readCapped(path, maxFilePart)
		a.do(func() {
			if err != nil {
				a.toast("Cannot read " + filepath.Base(path) + ": " + err.Error())
				return
			}
			ct := mime.TypeByExtension(filepath.Ext(path))
			if ct == "" {
				ct = http.DetectContentType(data)
			}
			name := filepath.Base(path)
			for i := range e.parts {
				if e.parts[i].id == id {
					r := &e.parts[i]
					r.file, r.fileName, r.contentType, r.data = true, name, ct, data
					if r.name == "" {
						r.name = "file"
					}
					return
				}
			}
			e.addPart(partRow{on: true, name: "file", file: true, fileName: name, contentType: ct, data: data})
		})
	}()
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("it is larger than %s", formatSize(int(limit)))
	}
	return data, nil
}

type curlSheet struct {
	open bool
	text *editor.State
	err  string
}

func (a *App) openCurlSheet() {
	st := &a.compose
	st.curl = curlSheet{open: true, text: &editor.State{Buffer: editor.NewBuffer(""), SoftWrap: true, Label: "cURL command", Placeholder: "curl https://api.example.com/v1/items"}}
}

func (a *App) curlSheetView(c *ui.Context) {
	st := &a.compose
	s := &st.curl
	if !s.open {
		return
	}
	p := a.pal
	ui.Modal(c, &s.open, func() {
		ui.Column(c).Width(sheetWidth(c, 560)).Gap(10).Children(func() {
			ui.Text(c, "Import from cURL").FontSize(15).FontWeight(650)
			ui.Text(c, "Paste a curl command, as a browser's Copy as cURL writes it. Files it reads with @ are left out.").TextColor(p.muted).Wrap()
			ui.Box(c).FillWidth().Height(180).Radius(6).Border(1, p.border).Clip().Children(func() {
				editor.View(c.Key("curlText"), s.text).Fill()
			})
			if s.err != "" {
				ui.Text(c, s.err).FontSize(11).TextColor(p.red).Wrap()
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "Cancel").Clicked() {
					s.open = false
				}
				text := strings.TrimSpace(s.text.Buffer.String())
				if ui.PrimaryButton(c, "Import").Disabled(text == "").Clicked() || text != "" && c.Shortcut(ui.Cmd, ui.KeyEnter) {
					cmd, err := curl.Parse(text)
					if err != nil {
						s.err = err.Error()
						return
					}
					s.open = false
					a.composeCurl(cmd)
				}
			})
		})
	})
}

func (a *App) composeCurl(cmd curl.Command) {
	st := &a.compose
	e := newComposeEditor(proxy.Message{Method: cmd.Method, URL: cmd.URL, Header: cmd.Header, Body: cmd.Body})
	if len(cmd.Parts) > 0 {
		e.kind = bodyMultipart
		e.partRows(cmd.Parts)
	}
	e.tab = map[bool]int{true: 2}[len(cmd.Body) > 0 || len(cmd.Parts) > 0]
	st.edit, st.err, st.result = e, "", ""
	st.follow, st.maxRedirects = cmd.FollowRedirects, cmd.MaxRedirects
	if cmd.Timeout > 0 {
		st.timeout = cmd.Timeout.Seconds()
	}
	notes := slices.Clone(cmd.Warnings)
	if cmd.Insecure && !a.rules.Current().InsecureTLS {
		notes = append(notes, "-k: ProxyGo checks the server's certificate, unless Settings › HTTPS accepts any")
	}
	st.notes = notes
}

func (a *App) composeTemplate(name string) {
	st := &a.compose
	var h flow.Header
	m := proxy.Message{Method: http.MethodGet, URL: "https://api.example.com/v1/items"}
	kind := bodyText
	switch name {
	case "Empty Request":
		m.URL = "https://"
	case "GET with Query":
		h.Set("Accept", "application/json")
		m.URL += "?page=1&limit=20"
	case "POST with JSON":
		m.Method = http.MethodPost
		h.Set("Content-Type", "application/json")
		m.Body = []byte("{\n  \"name\": \"ProxyGo\"\n}")
	case "POST with Form":
		m.Method = http.MethodPost
		h.Set("Content-Type", "application/x-www-form-urlencoded")
		m.Body = []byte("name=ProxyGo")
	case "POST with Multipart":
		m.Method = http.MethodPost
		kind = bodyMultipart
	case "WebSocket":
		m.URL = "wss://api.example.com/socket"
	}
	m.Header = h
	e := newComposeEditor(m)
	if kind == bodyMultipart {
		e.setKind(bodyMultipart)
		e.parts[0].name, e.parts[0].value = "name", "ProxyGo"
		e.addPart(partRow{on: true, name: "file", file: true})
	}
	if m.Method == http.MethodPost {
		e.tab = 2
	}
	st.edit, st.err, st.result, st.notes = e, "", "", nil
}

var composeTemplates = []string{"Empty Request", "GET with Query", "POST with JSON", "POST with Form", "POST with Multipart", "WebSocket"}

func isWebSocketURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "ws" || u.Scheme == "wss")
}

func (a *App) connectCompose(msg proxy.Message) {
	st := &a.compose
	timeout := time.Duration(st.timeout * float64(time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}
	st.cancel = cancel
	go func() {
		defer cancel()
		f, err := a.proxy.OpenWebSocket(ctx, msg)
		a.do(func() {
			st.sending, st.cancel = false, nil
			if err != nil {
				st.err = err.Error()
				return
			}
			st.result = f.UniqueID
			if a.proxy.Composed(f.UniqueID) {
				st.socket = f.UniqueID
			}
			if _, ok := a.store.Lookup(f.UniqueID); !ok {
				a.store.Upsert(f.Clone())
			}
		})
	}()
}

func (a *App) closeComposeSocket() {
	if id := a.compose.socket; id != "" {
		a.proxy.CloseWebSocket(id)
		a.compose.socket = ""
	}
}
