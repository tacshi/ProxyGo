package app

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
	"unicode/utf8"

	ui "github.com/egoist/mygo/proxygoui"
	"github.com/egoist/mygo/proxygoui/editor"
	"golang.org/x/net/html"

	"proxygo/internal/flow"
	"proxygo/internal/preview"
	"proxygo/internal/protobuf"
	"proxygo/locales"
)

const (
	modePretty   = "Pretty"
	modeTree     = "Tree"
	modeRaw      = "Raw"
	modeHex      = "Hex"
	modeImage    = "Image"
	modeForm     = "Form"
	modeParts    = "Multipart"
	modeProtobuf = "Protobuf"
	modeGraphQL  = "GraphQL"
	modeJWT      = "JWT"
	modeSSE      = "Events"
	modeMsgPack  = "MsgPack"
)

const maxPretty = 8 << 20

func modesFor(ct string, body []byte) []string {
	mt, _, _ := mime.ParseMediaType(ct)
	mt = strings.ToLower(mt)
	isProto, _ := protobuf.Is(mt)
	switch {
	case len(body) == 0:
		return nil
	case isProto:
		return []string{modeProtobuf, modeHex}
	case preview.IsSSE(mt):
		return []string{modeSSE, modeRaw, modeHex}
	case preview.IsMsgPack(mt):
		return []string{modeMsgPack, modeHex}
	case mt == "application/jwt" || len(body) < 16<<10 && preview.LooksLikeJWT(string(body)):
		return []string{modeJWT, modeRaw}
	case strings.HasPrefix(mt, "image/"):
		return []string{modeImage, modeHex}
	case strings.Contains(mt, "x-www-form-urlencoded"):
		return []string{modeForm, modeRaw, modeHex}
	case strings.HasPrefix(mt, "multipart/"):
		return []string{modeParts, modeRaw, modeHex}
	case isJSON(mt, body):
		if bytes.Contains(body[:min(len(body), 4096)], []byte(`"query"`)) {
			return []string{modePretty, modeGraphQL, modeTree, modeRaw, modeHex}
		}
		return []string{modePretty, modeTree, modeRaw, modeHex}
	case isTextual(ct, body):
		return []string{modePretty, modeRaw, modeHex}
	case looksMsgPack(body):
		return []string{modeHex, modeMsgPack}
	}
	return []string{modeHex}
}

func looksMsgPack(body []byte) bool {
	if len(body) < 2 || len(body) > 1<<20 {
		return false
	}
	if b := body[0]; !(b >= 0x80 && b <= 0x9f || b >= 0xdc && b <= 0xdf) {
		return false
	}
	_, err := preview.MsgPackText(body)
	return err == nil
}

type bodySource struct {
	f        *flow.Flow
	response bool
	ws       *flow.WebSocketMessage
	protobuf bool
}

func isJSON(mt string, body []byte) bool {
	if strings.Contains(mt, "json") {
		return true
	}
	t := bytes.TrimSpace(body[:min(len(body), 64)])
	return len(t) > 0 && (t[0] == '{' || t[0] == '[') && jsontext.Value(body).IsValid()
}

func isTextual(ct string, body []byte) bool {
	mt := strings.ToLower(ct)
	if strings.HasPrefix(mt, "text/") || strings.Contains(mt, "json") || strings.Contains(mt, "xml") ||
		strings.Contains(mt, "javascript") || strings.Contains(mt, "graphql") || strings.Contains(mt, "x-www-form-urlencoded") ||
		strings.Contains(mt, "html") || strings.Contains(mt, "css") || strings.Contains(mt, "event-stream") || strings.Contains(mt, "yaml") {
		return true
	}
	if strings.HasPrefix(mt, "image/") || strings.HasPrefix(mt, "audio/") || strings.HasPrefix(mt, "video/") || strings.Contains(mt, "octet-stream") || strings.Contains(mt, "protobuf") || strings.Contains(mt, "font") {
		return false
	}
	sample := body[:min(len(body), 2048)]
	return utf8.Valid(sample) && !bytes.ContainsRune(sample, 0)
}

func languageFor(ct string) *editor.Language {
	mt := strings.ToLower(ct)
	switch {
	case strings.Contains(mt, "json"):
		return editor.LanguageNamed("JSON")
	case strings.Contains(mt, "html"):
		return editor.LanguageNamed("HTML")
	case strings.Contains(mt, "xml"):
		return editor.LanguageNamed("XML")
	case strings.Contains(mt, "javascript"), strings.Contains(mt, "ecmascript"):
		return editor.LanguageNamed("JavaScript")
	case strings.Contains(mt, "css"):
		return editor.LanguageNamed("CSS")
	case strings.Contains(mt, "yaml"):
		return editor.LanguageNamed("YAML")
	}
	return nil
}

func (a *App) bodyView(c *ui.Context, f *flow.Flow, response bool, scope string) {
	var body []byte
	var ct, side string
	if response {
		body, ct, side = f.DecodedResponseBody(), f.Response.Header.Get("Content-Type"), scope+"res"
	} else {
		body, ct, side = f.DecodedRequestBody(), f.Request.Header.Get("Content-Type"), scope+"req"
	}
	src := bodySource{f: f, response: response}
	if typ, rule := a.protobufType(src, ct); rule != nil && typ != "" {
		src.protobuf = true
	}
	key := fmt.Sprintf("%s:%s:%d", f.UniqueID, side, len(body))
	a.bodyContent(c, key, body, ct, side, src)
}

func (a *App) bodyContent(c *ui.Context, key string, body []byte, ct, side string, src bodySource) {
	p := a.pal
	modes := modesFor(ct, body)
	if src.protobuf && len(body) > 0 {
		modes = []string{modeProtobuf, modeHex}
	}
	if len(modes) == 0 {
		emptyState(c, p, locales.NoBody())
		return
	}
	mode := a.bodyMode[side+":"+strings.Join(modes, ",")]
	if mode >= len(modes) {
		mode = 0
	}
	ui.Column(c.Key(side + "body")).Fill().Children(func() {
		ui.Row(c).Height(34).FillWidth().Padding(0, inset-5, 0, inset).Gap(8).AlignItems(ui.Center).Children(func() {
			if len(modes) > 1 {
				if ui.Segmented(c, &mode, bodyModeLabels(modes)...).Label(locales.BodyView()).Changed() {
					a.bodyMode[side+":"+strings.Join(modes, ",")] = mode
				}
			}
			crowded := false
			switch modes[mode] {
			case modePretty, modeTree:
				if isJSON(strings.ToLower(ct), body) {
					a.jsonFilterField(c, side)
					crowded = true
				}
			case modeProtobuf:
				a.protobufTypePicker(c, src, ct)
				crowded = true
			}
			ui.Spacer(c)
			about := formatSize(len(body)) + "  " + strings.Split(ct, ";")[0]
			copyLabel := locales.CopyBody()
			if crowded {
				copyLabel = locales.CopyBodyAbout(strings.TrimSpace(about))
			} else {
				ui.Text(c, about).FontSize(11).TextColor(p.muted).SingleLine()
			}
			if plainIconButton(c, "copy", copyLabel, 12, p.muted, p.hover).Clicked() {
				a.copy(string(body), locales.CopiedTheBody())
			}
		})
		ui.Divider(c)
		k := key + ":" + modes[mode]
		if (modes[mode] == modePretty || modes[mode] == modeTree) && a.jsonQueryOf(side).expr != "" && isJSON(strings.ToLower(ct), body) {
			if a.jsonFilterResult(c, k, body, side) {
				return
			}
		}
		switch modes[mode] {
		case modePretty:
			a.textViewer(c, k, prettyText(body, ct), languageName(ct), locales.TabBody())
		case modeRaw:
			a.textViewer(c, k, string(body), "", locales.TabBody())
		case modeHex:
			a.textViewer(c, k, hexDump(body), "", "Hex")
		case modeTree:
			a.jsonTreeView(c, k, body)
		case modeImage:
			a.imageView(c, k, body, ct)
		case modeForm:
			values, _ := url.ParseQuery(string(body))
			var rows [][2]string
			for _, part := range strings.Split(string(body), "&") {
				name, value, _ := strings.Cut(part, "=")
				n, _ := url.QueryUnescape(name)
				v, _ := url.QueryUnescape(value)
				if n != "" {
					rows = append(rows, [2]string{n, v})
				}
			}
			_ = values
			a.pairsTable(c, rows, locales.Field(), locales.Value(), locales.NoFields(), "")
		case modeParts:
			a.multipartView(c, k, body, ct, side)
		case modeProtobuf:
			text, lang := a.protobufText(src, body, ct)
			a.textViewer(c, k+":"+fmt.Sprint(a.schemas.Version()), text, lang, "Protobuf")
		case modeGraphQL:
			a.textViewer(c, k, graphQLText(body), "", "GraphQL")
		case modeJWT:
			a.jwtView(c, k, strings.TrimSpace(string(body)))
		case modeSSE:
			a.sseView(c, k, body, src.f != nil && src.f.IsActive())
		case modeMsgPack:
			text, err := preview.MsgPackText(body)
			if err != nil {
				text = "// " + err.Error() + "\n\n" + hexDump(body)
			}
			a.textViewer(c, k, text, "JSON", "MessagePack")
		}
	})
}

func languageName(ct string) string {
	if l := languageFor(ct); l != nil {
		return l.Name
	}
	return ""
}

func prettyText(body []byte, ct string) string {
	if len(body) > maxPretty {
		return string(body)
	}
	mt := strings.ToLower(ct)
	if isJSON(mt, body) {
		v := jsontext.Value(bytes.Clone(body))
		if err := v.Indent(jsontext.WithIndent("  ")); err == nil {
			return string(v)
		}
	}
	if strings.Contains(mt, "xml") {
		if s, ok := prettyXML(body); ok {
			return s
		}
	}
	if strings.Contains(mt, "html") {
		if s, ok := prettyHTML(body); ok {
			return s
		}
	}
	return string(body)
}

var htmlVoid = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "param": true, "source": true, "track": true, "wbr": true,
}

func prettyHTML(body []byte) (string, bool) {
	type token struct {
		kind html.TokenType
		raw  string
		name string
	}
	var toks []token
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			if z.Err() != io.EOF {
				return "", false
			}
			break
		}
		raw := string(z.Raw())
		if kind == html.TextToken {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
		}
		name, _ := z.TagName()
		toks = append(toks, token{kind, raw, string(name)})
	}
	var b strings.Builder
	depth := 0
	line := func(s string) {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth))
		b.WriteString(s)
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case html.StartTagToken:
			if htmlVoid[t.name] {
				line(t.raw)
				continue
			}
			if i+1 < len(toks) && toks[i+1].kind == html.EndTagToken && toks[i+1].name == t.name {
				line(t.raw + toks[i+1].raw)
				i++
				continue
			}
			if i+2 < len(toks) && toks[i+1].kind == html.TextToken && !strings.Contains(toks[i+1].raw, "\n") &&
				toks[i+2].kind == html.EndTagToken && toks[i+2].name == t.name {
				line(t.raw + toks[i+1].raw + toks[i+2].raw)
				i += 2
				continue
			}
			line(t.raw)
			depth++
		case html.EndTagToken:
			depth = max(depth-1, 0)
			line(t.raw)
		default:
			line(t.raw)
		}
	}
	return b.String(), true
}

var (
	xmlText = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	xmlAttr = strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;")
)

func prettyXML(body []byte) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var toks []xml.Token
	var open []xml.Name
	for {
		t, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		switch t := t.(type) {
		case xml.StartElement:
			open = append(open, t.Name)
		case xml.EndElement:
			if len(open) == 0 || open[len(open)-1] != t.Name {
				return "", false
			}
			open = open[:len(open)-1]
		}
		toks = append(toks, xml.CopyToken(t))
	}
	if len(open) > 0 {
		return "", false
	}
	name := func(n xml.Name) string {
		if n.Space != "" {
			return n.Space + ":" + n.Local
		}
		return n.Local
	}
	var b strings.Builder
	depth := 0
	line := func() {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth))
	}
	for i := 0; i < len(toks); i++ {
		switch t := toks[i].(type) {
		case xml.StartElement:
			line()
			b.WriteString("<" + name(t.Name))
			for _, at := range t.Attr {
				b.WriteString(" " + name(at.Name) + `="` + xmlAttr.Replace(at.Value) + `"`)
			}
			b.WriteString(">")
			end := "</" + name(t.Name) + ">"
			if i+1 < len(toks) {
				if _, ok := toks[i+1].(xml.EndElement); ok {
					b.WriteString(end)
					i++
					continue
				}
			}
			if i+2 < len(toks) {
				text, ok := toks[i+1].(xml.CharData)
				if _, closes := toks[i+2].(xml.EndElement); ok && closes {
					b.WriteString(xmlText.Replace(string(text)) + end)
					i += 2
					continue
				}
			}
			depth++
		case xml.EndElement:
			depth = max(depth-1, 0)
			line()
			b.WriteString("</" + name(t.Name) + ">")
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); s != "" {
				line()
				b.WriteString(xmlText.Replace(s))
			}
		case xml.Comment:
			line()
			b.WriteString("<!--" + string(t) + "-->")
		case xml.ProcInst:
			line()
			b.WriteString("<?" + t.Target)
			if len(t.Inst) > 0 {
				b.WriteString(" " + string(t.Inst))
			}
			b.WriteString("?>")
		case xml.Directive:
			line()
			b.WriteString("<!" + string(t) + ">")
		}
	}
	return b.String(), true
}

func prettyGraphQL(q string) string {
	var b strings.Builder
	depth, parens := 0, 0
	space, nl := false, false
	last := func() byte {
		if b.Len() == 0 {
			return 0
		}
		return b.String()[b.Len()-1]
	}
	newline := func() {
		trimmed := strings.TrimRight(b.String(), " \n")
		b.Reset()
		b.WriteString(trimmed + "\n" + strings.Repeat("  ", depth))
		space, nl = false, false
	}
	put := func(ch byte) {
		switch {
		case nl:
			newline()
		case space && b.Len() > 0:
			text := b.String()
			l := last()
			if depth == 0 || l == ':' || ch == ':' || ch == '(' || ch == '@' || ch == '=' ||
				strings.HasSuffix(text, "...") || strings.HasSuffix(text, " on") {
				b.WriteByte(' ')
			} else {
				newline()
			}
		}
		space = false
		b.WriteByte(ch)
	}
	for i := 0; i < len(q); i++ {
		ch := q[i]
		switch {
		case ch == '"':
			put(ch)
			for i++; i < len(q); i++ {
				b.WriteByte(q[i])
				if q[i] == '\\' && i+1 < len(q) {
					i++
					b.WriteByte(q[i])
				} else if q[i] == '"' {
					break
				}
			}
		case parens > 0:
			if ch == '(' {
				parens++
			} else if ch == ')' {
				parens--
			}
			b.WriteByte(ch)
		case ch == '(':
			put(ch)
			parens++
		case ch == '{':
			space, nl = false, false
			if l := last(); l != 0 && l != ' ' && l != '\n' {
				b.WriteByte(' ')
			}
			b.WriteByte('{')
			depth++
			nl = true
		case ch == '}':
			depth = max(depth-1, 0)
			newline()
			b.WriteByte('}')
			nl = depth > 0
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ',':
			space = true
		default:
			put(ch)
		}
	}
	return strings.TrimSpace(b.String())
}

func graphQLText(body []byte) string {
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	var b strings.Builder
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return string(body)
	}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			break
		}
		name := tok.String()
		val, err := dec.ReadValue()
		if err != nil {
			break
		}
		switch name {
		case "query":
			var q string
			if tok, err := jsontext.NewDecoder(bytes.NewReader(val)).ReadToken(); err == nil {
				q = tok.String()
			}
			b.WriteString("# Query\n" + prettyGraphQL(q) + "\n\n")
		default:
			v := jsontext.Value(bytes.Clone(val))
			_ = v.Indent(jsontext.WithIndent("  "))
			b.WriteString("# " + name + "\n" + string(v) + "\n\n")
		}
	}
	return strings.TrimSpace(b.String())
}

func hexDump(body []byte) string {
	const limit = 1 << 20
	tail := ""
	if len(body) > limit {
		tail = "… " + locales.SizeMore(formatSize(len(body)-limit))
		body = body[:limit]
	}
	return strings.TrimRight(hex.Dump(body), "\n") + "\n" + tail
}

type viewer struct {
	state *editor.State
	used  uint64
}

var viewerClock uint64

func (a *App) textViewer(c *ui.Context, key, text, language, label string) {
	v := a.viewers[key]
	if v == nil {
		buf := editor.NewBuffer(text)
		if language != "" {
			buf.SetLanguage(editor.LanguageNamed(language))
		}
		v = &viewer{state: &editor.State{Buffer: buf, ReadOnly: true, SoftWrap: true, NoScrollPastEnd: true, Label: label, NoActiveLine: true}}
		a.viewers[key] = v
		a.trimViewers()
	}
	viewerClock++
	v.used = viewerClock
	editor.View(c.Key(key), v.state).Grow(1).FillWidth()
}

func (a *App) trimViewers() {
	const keep = 24
	if len(a.viewers) <= keep {
		return
	}
	oldest, at := "", ^uint64(0)
	for k, v := range a.viewers {
		if v.used < at {
			oldest, at = k, v.used
		}
	}
	delete(a.viewers, oldest)
	delete(a.trees, oldest)
	delete(a.images, oldest)
}

type jsonTree struct {
	state    ui.OutlineState[string]
	nodes    map[string]*jsonNode
	roots    []string
	row      int
	err      string
	expanded bool
}

type jsonNode struct {
	key      string
	kind     byte
	value    string
	children []string
	count    int
}

func (a *App) jsonTreeView(c *ui.Context, key string, body []byte) {
	p := a.pal
	t := a.trees[key]
	if t == nil {
		t = parseJSONTree(body)
		a.trees[key] = t
		if a.viewers[key] == nil {
			a.viewers[key] = &viewer{}
		}
	}
	if t.err != "" {
		emptyState(c, p, locales.NotValidJSON(t.err))
		return
	}
	if !t.expanded {
		t.expanded = true
		for _, r := range t.roots {
			t.state.Open.Add(r)
			for _, ch := range t.nodes[r].children {
				t.state.Open.Add(ch)
			}
		}
	}
	t.state.List.Selected = &t.row
	ui.Outline(c.Key(key), &t.state, t.roots, func(id string) []string {
		return t.nodes[id].children
	}, func(id string) {
		n := t.nodes[id]
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			if n.key != "" {
				ui.Text(c, n.key).TextColor(p.purple).FontWeight(500).SingleLine()
			}
			switch n.kind {
			case '{':
				ui.Text(c, "{ "+locales.KeysCount(n.count)+" }").TextColor(p.muted).SingleLine()
			case '[':
				ui.Text(c, "[ "+locales.ItemsCount(n.count)+" ]").TextColor(p.muted).SingleLine()
			case '"':
				ui.Text(c, n.value).TextColor(p.green).SingleLine().Selectable()
			case '0':
				ui.Text(c, n.value).TextColor(p.blue).SingleLine().Selectable()
			default:
				ui.Text(c, n.value).TextColor(p.orange).SingleLine()
			}
		}).ContextMenu(func(m *ui.Menu) {
			if m.Item(locales.CopyValue()).Chosen() {
				a.copy(n.value, locales.CopiedTheValue())
			}
			if m.Item(locales.CopyKey()).Disabled(n.key == "").Chosen() {
				a.copy(n.key, locales.CopiedTheKey())
			}
			if m.Item(locales.CopyPath()).Chosen() {
				a.copy(id, locales.CopiedThePath())
			}
		})
	}).Grow(1).Label(locales.JSONTree())
}

func parseJSONTree(body []byte) *jsonTree {
	t := &jsonTree{nodes: map[string]*jsonNode{}, row: -1}
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	var read func(path, key string) error
	read = func(path, key string) error {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}
		n := &jsonNode{key: key, kind: byte(tok.Kind())}
		t.nodes[path] = n
		switch tok.Kind() {
		case '{':
			for dec.PeekKind() != '}' {
				name, err := dec.ReadToken()
				if err != nil {
					return err
				}
				child := path + "." + name.String()
				if err := read(child, name.String()); err != nil {
					return err
				}
				n.children = append(n.children, child)
			}
			_, err = dec.ReadToken()
			n.count = len(n.children)
			n.value = "{…}"
			return err
		case '[':
			for i := 0; dec.PeekKind() != ']'; i++ {
				child := fmt.Sprintf("%s[%d]", path, i)
				if err := read(child, fmt.Sprintf("[%d]", i)); err != nil {
					return err
				}
				n.children = append(n.children, child)
			}
			_, err = dec.ReadToken()
			n.count = len(n.children)
			n.value = "[…]"
			return err
		case '"':
			n.value = tok.String()
		default:
			n.value = tok.String()
			if tok.Kind() == '0' {
				n.value = string(tok.String())
			}
		}
		return nil
	}
	if err := read("$", ""); err != nil && err != io.EOF {
		t.err = err.Error()
		return t
	}
	t.roots = []string{"$"}
	return t
}

func (a *App) imageView(c *ui.Context, key string, body []byte, ct string) {
	p := a.pal
	bmp, ok := a.images[key]
	if !ok {
		if b, err := ui.DecodeBitmap(body); err == nil {
			bmp = b
		}
		a.images[key] = bmp
		if a.viewers[key] == nil {
			a.viewers[key] = &viewer{}
		}
	}
	if strings.Contains(ct, "svg") {
		if svg, err := ui.ParseSVG(body); err == nil {
			centered(c, 8, func() {
				ui.Image(c, svg).MaxWidth(600).MaxHeight(600)
			})
			return
		}
	}
	if bmp == nil {
		emptyState(c, p, locales.ProxyGoCannotShowThisImageFormat())
		return
	}
	w, h := bmp.Size()
	scale := 1
	if side := max(w, h); side > 0 && side < 96 {
		scale = min(96/side, 8)
	}
	centered(c, 8, func() {
		ui.Image(c, bmp).Width(float32(min(w*scale, 900))).MaxWidth(float32(min(w*scale, 900))).Fit(ui.Contain).Background(p.surface).Radius(4)
		ui.Text(c, fmt.Sprintf("%d × %d · %s", w, h, formatSize(len(body)))).FontSize(11).TextColor(p.muted)
	})
}

type bodyPart struct {
	name, file, ct string
	data           []byte
}

func (a *App) multipartView(c *ui.Context, key string, body []byte, ct, side string) {
	p := a.pal
	_, params, err := mime.ParseMediaType(ct)
	if err != nil || params["boundary"] == "" {
		emptyState(c, p, locales.NoMultipartBoundary())
		return
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var parts []bodyPart
	for {
		part, err := r.NextPart()
		if err != nil {
			break
		}
		data, _ := io.ReadAll(io.LimitReader(part, maxPretty))
		parts = append(parts, bodyPart{name: part.FormName(), file: part.FileName(), ct: part.Header.Get("Content-Type"), data: data})
	}
	if len(parts) == 0 {
		emptyState(c, p, locales.NoParts())
		return
	}
	row := a.partRow[key]
	if row == nil {
		row = new(int)
		a.partRow[key] = row
	}
	*row = min(max(*row, 0), len(parts)-1)
	list := a.listState(key+":parts", false)
	list.Selected = row
	cols := []ui.TableColumn{{Title: locales.Part(), Width: 160}, {Title: locales.Value()}}
	ui.Column(c).Fill().Children(func() {
		ui.Table(c.Key(key+":parts"), list, cols, len(parts), func(i, col int) {
			pt := parts[i]
			if col == 0 {
				ui.Text(c, pt.name).TextColor(p.text2).FontWeight(500).SingleLine()
				return
			}
			value := string(pt.data)
			if pt.file != "" || !utf8.Valid(pt.data) {
				value = fmt.Sprintf("%s (%s, %s)", pt.file, cmp.Or(pt.ct, locales.NoType()), formatSize(len(pt.data)))
			}
			ui.Text(c, value).TextColor(p.text).SingleLine()
		}).Height(float32(min(len(parts), 5))*26 + 30).Label(locales.Parts())
		ui.Divider(c)
		pt := parts[*row]
		ui.Column(c).Grow(1).Children(func() {
			a.bodyContent(c, fmt.Sprintf("%s:part%d", key, *row), pt.data, cmp.Or(pt.ct, "text/plain"), side+"part", bodySource{})
		})
	})
}
