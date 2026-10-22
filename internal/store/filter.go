package store

import (
	"cmp"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"proxygo/internal/flow"
	"proxygo/internal/query"
)

var (
	ProtocolKinds = []string{"HTTP", "HTTPS", "WebSocket"}
	ContentKinds  = []string{"JSON", "Form", "XML", "JS", "CSS", "GraphQL", "Document", "Media", "Other"}
	VersionKinds  = []string{"h1", "h2"}
)

type Field string

const (
	FieldURL              Field = "URL"
	FieldHost             Field = "Host"
	FieldPath             Field = "Path"
	FieldMethod           Field = "Method"
	FieldStatus           Field = "Status Code"
	FieldClient           Field = "Client"
	FieldContentType      Field = "Content Type"
	FieldRequestHeader    Field = "Request Header"
	FieldResponseHeader   Field = "Response Header"
	FieldRequestBody      Field = "Request Body"
	FieldResponseBody     Field = "Response Body"
	FieldGraphQL          Field = "GraphQL Operation"
	FieldComment          Field = "Comment"
	FieldDuration         Field = "Duration (ms)"
	FieldSize             Field = "Response Size (bytes)"
	FieldQuery            Field = "Query"
	FieldRequestJQ        Field = "Request JSON (jq)"
	FieldResponseJQ       Field = "Response JSON (jq)"
	FieldRequestJSONPath  Field = "Request JSON (JSON Path)"
	FieldResponseJSONPath Field = "Response JSON (JSON Path)"
)

var Fields = []Field{
	FieldURL, FieldHost, FieldPath, FieldQuery, FieldMethod, FieldStatus, FieldClient, FieldContentType,
	FieldRequestHeader, FieldResponseHeader, FieldRequestBody, FieldResponseBody,
	FieldRequestJQ, FieldResponseJQ, FieldRequestJSONPath, FieldResponseJSONPath,
	FieldGraphQL, FieldComment, FieldDuration, FieldSize,
}

func (f Field) NeedsKey() bool {
	switch f {
	case FieldRequestJQ, FieldResponseJQ, FieldRequestJSONPath, FieldResponseJSONPath:
		return true
	}
	return false
}

func (f Field) queryOf() (lang string, response bool) {
	switch f {
	case FieldRequestJQ:
		return query.LangJQ, false
	case FieldResponseJQ:
		return query.LangJQ, true
	case FieldRequestJSONPath:
		return query.LangJSONPath, false
	case FieldResponseJSONPath:
		return query.LangJSONPath, true
	}
	return "", false
}

type Op string

const (
	OpContains    Op = "contains"
	OpNotContains Op = "does not contain"
	OpEquals      Op = "is"
	OpNotEquals   Op = "is not"
	OpStartsWith  Op = "starts with"
	OpEndsWith    Op = "ends with"
	OpRegex       Op = "matches regex"
	OpGreater     Op = "greater than"
	OpLess        Op = "less than"
)

var Ops = []Op{OpContains, OpNotContains, OpEquals, OpNotEquals, OpStartsWith, OpEndsWith, OpRegex, OpGreater, OpLess}

type Condition struct {
	Enabled bool   `json:"enabled"`
	Field   Field  `json:"field"`
	Op      Op     `json:"op"`
	Value   string `json:"value"`
	Key     string `json:"key,omitempty"`
}

func (c Condition) Active() bool {
	return c.Enabled && (c.Value != "" || c.Field.NeedsKey() && c.Key != "")
}

func (c Condition) Match(f *flow.Flow) bool {
	if !c.Active() {
		return true
	}
	if c.Field.NeedsKey() {
		return c.matchJSON(f)
	}
	switch c.Field {
	case FieldDuration:
		return compareNumber(float64(f.Duration().Milliseconds()), c.Op, c.Value)
	case FieldSize:
		return compareNumber(float64(f.ResponseBodySize()), c.Op, c.Value)
	case FieldStatus:
		if c.Op == OpGreater || c.Op == OpLess {
			return compareNumber(float64(f.StatusCode()), c.Op, c.Value)
		}
	case FieldRequestHeader, FieldResponseHeader:
		h := flow.Header{}
		if c.Field == FieldRequestHeader && f.Request != nil {
			h = f.Request.Header
		} else if c.Field == FieldResponseHeader && f.Response != nil {
			h = f.Response.Header
		}
		positive := c.Op != OpNotContains && c.Op != OpNotEquals
		for _, e := range h.Entries {
			if e.Enabled && compareText(e.Key.Name+": "+e.Value, c.Op, c.Value) == positive {
				return positive
			}
		}
		return !positive
	}
	return compareText(fieldText(f, c.Field), c.Op, c.Value)
}

func (c Condition) matchJSON(f *flow.Flow) bool {
	lang, response := c.Field.queryOf()
	body := f.DecodedRequestBody()
	if response {
		body = f.DecodedResponseBody()
	}
	positive := c.Op != OpNotContains && c.Op != OpNotEquals
	if len(body) == 0 {
		return !positive
	}
	values, err := query.Run(lang, body, c.Key)
	if err != nil || len(values) == 0 {
		return !positive
	}
	if c.Value == "" {
		return true
	}
	for _, v := range values {
		if v == nil {
			continue
		}
		if compareText(query.Text(v), c.Op, c.Value) == positive {
			return positive
		}
	}
	return !positive
}

func fieldText(f *flow.Flow, field Field) string {
	switch field {
	case FieldURL:
		return f.URL()
	case FieldQuery:
		_, q, _ := strings.Cut(f.URL(), "?")
		q, _, _ = strings.Cut(q, "#")
		if dq, err := url.QueryUnescape(q); err == nil {
			return dq
		}
		return q
	case FieldHost:
		return f.Host()
	case FieldPath:
		return f.URLPath()
	case FieldMethod:
		return f.MethodName()
	case FieldStatus:
		return f.StatusText()
	case FieldClient:
		return f.Client.Name
	case FieldContentType:
		return f.ContentType()
	case FieldRequestBody:
		return string(f.DecodedRequestBody())
	case FieldResponseBody:
		return string(f.DecodedResponseBody())
	case FieldGraphQL:
		return f.GraphQLOperation()
	case FieldComment:
		return f.Comment
	}
	return ""
}

func compareText(s string, op Op, value string) bool {
	ls, lv := strings.ToLower(s), strings.ToLower(value)
	switch op {
	case OpNotContains:
		return !strings.Contains(ls, lv)
	case OpEquals:
		return ls == lv
	case OpNotEquals:
		return ls != lv
	case OpStartsWith:
		return strings.HasPrefix(ls, lv)
	case OpEndsWith:
		return strings.HasSuffix(ls, lv)
	case OpRegex:
		re := cachedRegexp(value)
		return re != nil && re.MatchString(s)
	case OpGreater, OpLess:
		return compareNumber(numberIn(s), op, value)
	default:
		return strings.Contains(ls, lv)
	}
}

func numberIn(s string) float64 {
	n, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return n
}

func compareNumber(n float64, op Op, value string) bool {
	v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return false
	}
	switch op {
	case OpGreater:
		return n > v
	case OpLess:
		return n < v
	case OpNotEquals:
		return n != v
	default:
		return n == v
	}
}

var regexps sync.Map

func cachedRegexp(pattern string) *regexp.Regexp {
	if v, ok := regexps.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		re = nil
	}
	regexps.Store(pattern, re)
	return re
}

func ValidKey(f Field, key string) string {
	if !f.NeedsKey() {
		return ""
	}
	lang, _ := f.queryOf()
	if err := query.Check(lang, key); err != nil {
		return err.Error()
	}
	return ""
}

func ValidRegexp(pattern string) string {
	if _, err := regexp.Compile(pattern); err != nil {
		return err.Error()
	}
	return ""
}

type Filter struct {
	Query      string
	Deep       bool
	Kinds      map[string]bool
	Client     string
	Host       string
	Path       string
	Hosts      []string
	Saved      bool
	Conditions []Condition
	Any        bool
}

func (f Filter) Active() bool {
	return f.Query != "" || len(f.Kinds) > 0 || f.Client != "" || f.Host != "" || f.Path != "" || len(f.Hosts) > 0 || f.Saved || slices.ContainsFunc(f.Conditions, Condition.Active)
}

func (f Filter) Match(fl *flow.Flow) bool {
	if f.Client != "" && cmp.Or(fl.Client.Name, "System") != f.Client {
		return false
	}
	if f.Host != "" && !strings.EqualFold(fl.Host(), f.Host) {
		return false
	}
	if f.Path != "" {
		p, _, _ := strings.Cut(fl.URLPath(), "?")
		if fl.IsTunnel() || (p != f.Path && !strings.HasPrefix(p, f.Path+"/")) {
			return false
		}
	}
	if len(f.Hosts) > 0 && !slices.ContainsFunc(f.Hosts, func(h string) bool { return strings.EqualFold(h, fl.Host()) }) {
		return false
	}
	if f.Saved && !fl.Saved {
		return false
	}
	if !f.kindsMatch(fl) {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(f.Query)); q != "" && !queryMatch(fl, q, f.Deep) {
		return false
	}
	return f.conditionsMatch(fl)
}

func (f Filter) kindsMatch(fl *flow.Flow) bool {
	if len(f.Kinds) == 0 {
		return true
	}
	group := func(kinds []string, is func(string) bool) bool {
		chosen := false
		for _, k := range kinds {
			if f.Kinds[k] {
				chosen = true
				if is(k) {
					return true
				}
			}
		}
		return !chosen
	}
	return group(ProtocolKinds, func(k string) bool {
		switch k {
		case "WebSocket":
			return fl.IsWebSocket()
		case "HTTPS":
			return fl.IsHTTPS() && !fl.IsWebSocket()
		default:
			return !fl.IsHTTPS() && !fl.IsWebSocket()
		}
	}) && group(ContentKinds, func(k string) bool {
		return slices.Contains(fl.ContentCategories(), k)
	}) && group(VersionKinds, func(k string) bool {
		return fl.HTTPVersionLabel() == k
	})
}

func (f Filter) conditionsMatch(fl *flow.Flow) bool {
	active := 0
	for _, c := range f.Conditions {
		if !c.Active() {
			continue
		}
		active++
		ok := c.Match(fl)
		if f.Any && ok {
			return true
		}
		if !f.Any && !ok {
			return false
		}
	}
	return !f.Any || active == 0
}

func queryMatch(f *flow.Flow, q string, deep bool) bool {
	for _, s := range []string{f.URL(), f.MethodName(), f.StatusText(), f.Client.Name, f.Comment, f.GraphQLOperation()} {
		if strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	if !deep {
		return false
	}
	headers := func(h flow.Header) bool {
		return slices.ContainsFunc(h.Entries, func(e flow.HeaderEntry) bool {
			return strings.Contains(strings.ToLower(e.Key.Name+": "+e.Value), q)
		})
	}
	if f.Request != nil && (headers(f.Request.Header) || containsFold(f.DecodedRequestBody(), q)) {
		return true
	}
	return f.Response != nil && (headers(f.Response.Header) || containsFold(f.DecodedResponseBody(), q))
}

func containsFold(b []byte, lowerQ string) bool {
	return len(b) > 0 && strings.Contains(strings.ToLower(string(b)), lowerQ)
}

func Apply(flows []*flow.Flow, f Filter) []*flow.Flow {
	if !f.Active() {
		return slices.Clone(flows)
	}
	out := make([]*flow.Flow, 0, len(flows))
	for _, fl := range flows {
		if f.Match(fl) {
			out = append(out, fl)
		}
	}
	return out
}

const (
	SortRow      = "id"
	SortURL      = "url"
	SortClient   = "client"
	SortMethod   = "method"
	SortStatus   = "statusCode"
	SortTime     = "time"
	SortDuration = "duration"
	SortRequest  = "request"
	SortResponse = "response"
	SortComment  = "comment"
)

func Sort(flows []*flow.Flow, column string, descending bool) {
	compare := func(a, b *flow.Flow) int {
		switch column {
		case SortURL:
			return strings.Compare(a.URL(), b.URL())
		case SortClient:
			return strings.Compare(a.Client.Name, b.Client.Name)
		case SortMethod:
			return strings.Compare(a.MethodName(), b.MethodName())
		case SortStatus:
			return cmp.Compare(a.StatusCode(), b.StatusCode())
		case SortTime:
			return a.RequestTime().Compare(b.RequestTime())
		case SortDuration:
			return cmp.Compare(a.Duration(), b.Duration())
		case SortRequest:
			return cmp.Compare(a.RequestBodySize(), b.RequestBodySize())
		case SortResponse:
			return cmp.Compare(a.ResponseBodySize(), b.ResponseBodySize())
		case SortComment:
			return strings.Compare(a.Comment, b.Comment)
		}
		return 0
	}
	slices.SortStableFunc(flows, func(a, b *flow.Flow) int {
		c := cmp.Or(compare(a, b), cmp.Compare(rowNumber(a), rowNumber(b)))
		if descending {
			return -c
		}
		return c
	})
}

func rowNumber(f *flow.Flow) int {
	n, _ := strconv.Atoi(f.ID)
	return n
}

type Preset struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Query      string      `json:"query,omitempty"`
	Deep       bool        `json:"deep,omitempty"`
	Kinds      []string    `json:"kinds,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
	Any        bool        `json:"any,omitempty"`
}

func (p Preset) Filter() Filter {
	f := Filter{Query: p.Query, Deep: p.Deep, Conditions: slices.Clone(p.Conditions), Any: p.Any, Kinds: map[string]bool{}}
	for _, k := range p.Kinds {
		f.Kinds[k] = true
	}
	return f
}

func PresetOf(id, name string, f Filter) Preset {
	p := Preset{ID: id, Name: name, Query: f.Query, Deep: f.Deep, Any: f.Any}
	for _, c := range f.Conditions {
		if c.Active() {
			p.Conditions = append(p.Conditions, c)
		}
	}
	for k, on := range f.Kinds {
		if on {
			p.Kinds = append(p.Kinds, k)
		}
	}
	slices.Sort(p.Kinds)
	return p
}
