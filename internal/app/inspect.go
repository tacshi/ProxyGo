package app

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/preview"
	"proxygo/internal/protobuf"
	"proxygo/internal/query"
	"proxygo/internal/rules"
)

type jsonQuery struct {
	lang string
	expr string
}

var jsonLangs = []string{"jq", "JSONPath", "Key Path"}

var jsonLangIDs = map[string]string{"jq": query.LangJQ, "JSONPath": query.LangJSONPath, "Key Path": query.LangKeyPath}

func (a *App) jsonQueryOf(side string) *jsonQuery {
	if a.jsonFilter == nil {
		a.jsonFilter = map[string]*jsonQuery{}
	}
	q := a.jsonFilter[side]
	if q == nil {
		q = &jsonQuery{lang: "jq"}
		a.jsonFilter[side] = q
	}
	return q
}

func (a *App) jsonFilterField(c *ui.Context, side string) {
	q := a.jsonQueryOf(side)
	ui.Select(c.Key("jsonLang"), &q.lang, jsonLangs).Label("Filter language").Width(96)
	placeholder := map[string]string{"jq": ".data.items[].id", "JSONPath": "$.data.items[0].id", "Key Path": "data.items.0.id"}[q.lang]
	box, _ := a.searchField(c, "jsonFilter", &q.expr, placeholder, "Filter JSON")
	box.Width(220).Shrink(1)
}

func (a *App) jsonFilterResult(c *ui.Context, key string, body []byte, side string) bool {
	p := a.pal
	q := a.jsonQueryOf(side)
	values, err := query.Run(jsonLangIDs[q.lang], body, q.expr)
	if err != nil {
		ui.Row(c).FillWidth().Padding(6, inset).Gap(6).AlignItems(ui.Center).Background(p.surface).Children(func() {
			glyph(c, "warning", 12, p.yellow)
			ui.Text(c, "The filter does not fit this body: "+err.Error()).FontSize(11).TextColor(p.text2).SingleLine().Selectable().MinWidth(0).Shrink(1).ClipX()
		})
		ui.Divider(c)
		return false
	}
	if len(values) == 0 {
		emptyState(c, p, "The filter selects nothing")
		return true
	}
	a.textViewer(c, key+":q:"+q.lang+":"+q.expr, query.Pretty(values), "JSON", "Filtered JSON")
	return true
}

func (a *App) protobufType(src bodySource, ct string) (string, *rules.ProtobufRule) {
	f := src.f
	if f == nil || f.Request == nil {
		return "", nil
	}
	if r := a.rules.Current().ProtobufFor(f.MethodName(), f.URL()); r != nil {
		if src.response {
			return r.ResponseType, r
		}
		return r.RequestType, r
	}
	if _, grpc := protobuf.Is(ct); grpc {
		if in, out, ok := a.schemas.MethodTypes(f.URLPath()); ok {
			if src.response {
				return out, nil
			}
			return in, nil
		}
	}
	return "", nil
}

func (a *App) protobufText(src bodySource, body []byte, ct string) (string, string) {
	_, grpc := protobuf.Is(ct)
	typ, rule := a.protobufType(src, ct)
	raw := func() string {
		var text string
		var err error
		if grpc {
			text, err = protobuf.DecodeGRPC(body)
		} else {
			text, err = protobuf.DecodeRaw(body)
		}
		if err != nil {
			return "# Not protobuf: " + err.Error() + "\n\n" + hexDump(body)
		}
		return text
	}
	if typ == "" {
		return raw(), "Protobuf"
	}
	payload := protobuf.PayloadAuto
	if rule != nil {
		payload = rule.Payload
	}
	encoding := ""
	if src.f != nil {
		if src.response && src.f.Response != nil {
			encoding = src.f.Response.Header.Get("Grpc-Encoding")
		} else if src.f.Request != nil {
			encoding = src.f.Request.Header.Get("Grpc-Encoding")
		}
	}
	if src.ws != nil {
		payload, grpc = protobuf.PayloadSingle, false
	}
	text, err := a.schemas.DecodeBody(typ, payload, body, grpc, encoding)
	if err != nil {
		return "# " + typ + ": " + err.Error() + "\n# The fields as they are:\n\n" + raw(), "Protobuf"
	}
	return text, "JSON"
}

func (a *App) protobufTypePicker(c *ui.Context, src bodySource, ct string) {
	types := a.schemas.Messages()
	if len(types) == 0 {
		if ui.Button(c, "Import Schema…").Tooltip("Decode protobuf with its .proto or descriptor set").Clicked() {
			a.openWindow("protobuf")
		}
		return
	}
	if src.f == nil || src.f.Request == nil {
		return
	}
	const rawFields = "Raw Fields"
	current, _ := a.protobufType(src, ct)
	choice := current
	if choice == "" {
		choice = rawFields
	}
	options := append([]string{rawFields}, types...)
	if !slices.Contains(options, choice) {
		options = append(options, choice)
	}
	if ui.Select(c.Key("protoType"), &choice, options).Label("Message type").Width(220).Tooltip("Message type of this URL's " + map[bool]string{true: "responses", false: "requests"}[src.response]).Changed() {
		typ := choice
		if typ == rawFields {
			typ = ""
		}
		a.setProtobufType(src.f, src.response, typ)
	}
}

func (a *App) setProtobufType(f *flow.Flow, response bool, typ string) {
	u, _, _ := strings.Cut(f.URL(), "?")
	a.rules.Update(func(d *rules.Data) {
		var r *rules.ProtobufRule
		for _, x := range d.Protobuf {
			if x.Enabled && x.Matches(f.MethodName(), f.URL()) {
				r = x
				break
			}
		}
		if r == nil {
			r = &rules.ProtobufRule{ID: rules.NewID(), Enabled: true, Name: shorten(strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"), 60), Matcher: rules.Matcher{URL: u}}
			d.Protobuf = append(d.Protobuf, r)
		}
		if response {
			r.ResponseType = typ
		} else {
			r.RequestType = typ
		}
	})
}

func (a *App) jwtView(c *ui.Context, key, raw string) {
	p := a.pal
	t, err := preview.DecodeJWT(raw)
	if err != nil {
		emptyState(c, p, err.Error())
		return
	}
	pretty := func(b []byte) string {
		var out bytes.Buffer
		if json.Indent(&out, b, "", "  ") != nil {
			return string(b)
		}
		return out.String()
	}
	ui.Scroll(c.Key(key)).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(inset).Gap(10).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				var h map[string]any
				_ = json.Unmarshal(t.Header, &h)
				ui.Text(c, fmt.Sprintf("JWT · %v", h["alg"])).FontWeight(650).TextColor(p.text)
				switch {
				case t.ExpiresAt.IsZero():
					ui.Text(c, "No expiry").FontSize(11).TextColor(p.muted)
				case t.Expired(time.Now()):
					ui.Text(c, "Expired "+t.ExpiresAt.Local().Format("2006-01-02 15:04:05")).FontSize(10.5).FontWeight(650).TextColor(p.red).Background(p.redSoft).Padding(2, 7).Radius(5)
				default:
					ui.Text(c, "Expires "+t.ExpiresAt.Local().Format("2006-01-02 15:04:05")+" (in "+time.Until(t.ExpiresAt).Round(time.Second).String()+")").FontSize(10.5).FontWeight(650).TextColor(p.green).Background(p.greenSoft).Padding(2, 7).Radius(5)
				}
				ui.Spacer(c)
				if ui.Button(c, "Copy Claims").Clicked() {
					a.copy(pretty(t.Claims), "the claims")
				}
			})
			ui.Text(c, "The signature is not verified.").FontSize(11).TextColor(p.muted)
			for _, d := range []struct {
				label string
				at    time.Time
			}{{"Issued", t.IssuedAt}, {"Not before", t.NotBefore}, {"Expires", t.ExpiresAt}} {
				if !d.at.IsZero() {
					ui.Text(c, d.label+": "+d.at.Local().Format("Mon, 2 Jan 2006 15:04:05 MST")).FontSize(11).TextColor(p.text2).Selectable()
				}
			}
			ui.Text(c, "Header").FontWeight(650).TextColor(p.text2).Margin(4, 0, 0, 0)
			code(c, p, pretty(t.Header))
			ui.Text(c, "Claims").FontWeight(650).TextColor(p.text2)
			code(c, p, pretty(t.Claims))
			ui.Text(c, "Signature").FontWeight(650).TextColor(p.text2)
			code(c, p, hex.EncodeToString(t.Signature))
		})
	})
}

func (a *App) sseView(c *ui.Context, key string, body []byte, live bool) {
	p := a.pal
	stream := preview.ParseSSE(body)
	events := stream.Events
	if stream.Pending != nil {
		events = append(slices.Clone(events), *stream.Pending)
	}
	if len(events) == 0 {
		emptyState(c, p, "No events yet")
		return
	}
	if a.sseRow >= len(events) || a.sseRow < 0 {
		a.sseRow = 0
		if live {
			a.sseRow = len(events) - 1
		}
	}
	list := a.listState("sse:"+key, live)
	list.Selected = &a.sseRow
	cols := []ui.TableColumn{{Title: "#", Width: 44, Align: ui.End}, {Title: "Event", Width: 110}, {Title: "ID", Width: 80}, {Title: "Data"}}
	ui.SplitVerticalPercent(c, &a.listSplit, func() {
		ui.Table(c.Key("sse"), list, cols, len(events), func(row, col int) {
			e := events[row]
			sel := row == a.sseRow
			color := p.text
			if sel {
				color = p.onAccent
			}
			pending := stream.Pending != nil && row == len(events)-1
			switch col {
			case 0:
				ui.Text(c, fmt.Sprint(row+1)).FontSize(11).TextColor(color).FontFeatures("tnum")
			case 1:
				name := e.Type
				if pending {
					name += " …"
				}
				ui.Text(c, name).FontSize(11).TextColor(color).SingleLine()
			case 2:
				ui.Text(c, e.ID).FontSize(11).TextColor(color).SingleLine()
			case 3:
				ui.Text(c, shorten(strings.ReplaceAll(e.Data, "\n", " "), 400)).FontSize(11.5).TextColor(color).SingleLine()
			}
		}).Grow(1).Label("Server-sent events")
	}, func() {
		e := events[a.sseRow]
		ct := ""
		if json.Valid([]byte(e.Data)) {
			ct = "application/json"
		}
		header := fmt.Sprintf("%s · %s", e.Type, formatSize(len(e.Data)))
		if e.Retry > 0 {
			header += " · retry " + e.Retry.String()
		}
		if e.ID != "" {
			header += " · id " + e.ID
		}
		ui.Row(c).Height(30).FillWidth().Padding(0, inset).AlignItems(ui.Center).Children(func() {
			ui.Text(c, header).FontSize(11).TextColor(p.muted).SingleLine()
			if stream.Comments > 0 {
				ui.Spacer(c)
				ui.Text(c, plural(stream.Comments, "comment", "comments")+" (keep-alives)").FontSize(11).TextColor(p.faint)
			}
		})
		ui.Divider(c)
		a.textViewer(c, fmt.Sprintf("%s:sse:%d:%d", key, a.sseRow, len(e.Data)), prettyText([]byte(e.Data), ct), languageName(ct), "Event data")
	}).Grow(1)
}

func (a *App) tlsView(c *ui.Context, f *flow.Flow) {
	p := a.pal
	if f.TLS == nil || f.TLS.Client == nil && f.TLS.Server == nil {
		emptyState(c, p, "No TLS for this flow")
		return
	}
	side := func(title string, t *flow.TLSInfo) {
		if t == nil {
			return
		}
		ui.Text(c, title).FontSize(13).FontWeight(650).TextColor(p.text).Margin(6, 0, 0, 0)
		ui.Form(c, func() {
			row := func(k, v string) {
				if v != "" {
					ui.Field(c, k, func() { ui.Text(c, v).TextColor(p.text).Selectable().Wrap() })
				}
			}
			row("Version", t.Version)
			row("Cipher Suite", t.CipherSuite)
			row("ALPN", t.ALPN)
			row("Server Name", t.ServerName)
			if len(t.Offered) > 0 {
				row("Client Offered", strings.Join(t.Offered, ", "))
			}
			if t.Resumed {
				row("Session", "Resumed")
			}
			row("Error", t.Error)
			if t.PinningLikely {
				row("Note", "The client refused ProxyGo's certificate. If it trusts the ProxyGo root, it likely pins its server's certificate: leave the host out of SSL Proxying, or use a custom server certificate.")
			}
		})
		for i, cert := range t.Certificates {
			ui.Column(c.Key(title+fmt.Sprint(i))).FillWidth().Padding(10, 12).Gap(3).Radius(6).Background(p.surface).Children(func() {
				label := "Certificate"
				switch {
				case i == 0:
					label = "Leaf"
				case i == len(t.Certificates)-1:
					label = "Root or last intermediate"
				default:
					label = "Intermediate"
				}
				ui.Text(c, label).FontSize(10.5).FontWeight(650).TextColor(p.muted)
				ui.Text(c, cert.Subject).TextColor(p.text).Selectable().Wrap()
				ui.Text(c, "Issued by "+cert.Issuer).FontSize(11).TextColor(p.text2).Selectable().Wrap()
				validity := cert.NotBefore.Local().Format("2 Jan 2006") + " – " + cert.NotAfter.Local().Format("2 Jan 2006")
				if time.Now().After(cert.NotAfter) {
					validity += " (expired)"
				}
				ui.Text(c, validity).FontSize(11).TextColor(p.text2)
				if len(cert.DNSNames) > 0 {
					ui.Text(c, "Names: "+shorten(strings.Join(cert.DNSNames, ", "), 300)).FontSize(11).TextColor(p.text2).Selectable().Wrap()
				}
				ui.Text(c, "SHA-256 "+cert.SHA256).FontSize(10).TextColor(p.muted).Selectable().Wrap()
			})
		}
	}
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).FillWidth().Padding(inset).Gap(8).Children(func() {
			side("Client ↔ ProxyGo", f.TLS.Client)
			side("ProxyGo ↔ Server", f.TLS.Server)
		})
	})
}
