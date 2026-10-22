package curl

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/formdata"
)

type Command struct {
	Method string
	URL    string
	Header flow.Header
	Body   []byte
	Parts  []formdata.Part

	FollowRedirects bool
	MaxRedirects    int
	Insecure        bool
	Timeout         time.Duration

	Warnings []string
}

func Looks(s string) bool {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "$ "))
	name, _, _ := strings.Cut(s, " ")
	return path.Base(name) == "curl" && len(s) > len(name)
}

var withValue = map[string]string{
	"-X": "request", "--request": "request",
	"-H": "header", "--header": "header",
	"-d": "data", "--data": "data", "--data-ascii": "data",
	"--data-raw": "data-raw", "--data-binary": "data-binary",
	"--data-urlencode": "data-urlencode", "--json": "json",
	"-F": "form", "--form": "form", "--form-string": "form-string",
	"-u": "user", "--user": "user",
	"-A": "user-agent", "--user-agent": "user-agent",
	"-e": "referer", "--referer": "referer",
	"-b": "cookie", "--cookie": "cookie",
	"--url": "url",
	"-m":    "max-time", "--max-time": "max-time",
	"--max-redirs": "max-redirs",
	"-x":           "proxy", "--proxy": "proxy",
	"-o": "ignore", "--output": "ignore", "-w": "ignore", "--write-out": "ignore",
	"--connect-timeout": "ignore", "--retry": "ignore", "--retry-delay": "ignore",
	"--cacert": "cacert", "--cert": "cert", "--key": "cert", "-E": "cert",
	"--resolve": "resolve", "--connect-to": "resolve",
	"-c": "ignore", "--cookie-jar": "ignore", "-r": "range", "--range": "range",
	"-T": "upload", "--upload-file": "upload",
}

var flags = map[string]string{
	"-L": "location", "--location": "location", "--location-trusted": "location",
	"-k": "insecure", "--insecure": "insecure",
	"-G": "get", "--get": "get",
	"-I": "head", "--head": "head",
	"--compressed": "compressed",
	"-s":           "", "--silent": "", "-S": "", "--show-error": "", "-v": "", "--verbose": "",
	"-i": "", "--include": "", "-O": "", "--remote-name": "", "-#": "", "--progress-bar": "",
	"-f": "", "--fail": "", "--fail-with-body": "", "-g": "", "--globoff": "", "-N": "", "--no-buffer": "",
	"--http1.1": "", "--http2": "", "--http2-prior-knowledge": "", "--http3": "", "--tlsv1.2": "", "--tlsv1.3": "",
	"--path-as-is": "", "-n": "", "--netrc": "", "-q": "", "--disable": "", "-Z": "", "--parallel": "",
	"--raw": "", "-4": "", "-6": "", "--ipv4": "", "--ipv6": "", "--tcp-nodelay": "", "--no-keepalive": "",
}

func Parse(command string) (Command, error) {
	args, err := Split(strings.TrimPrefix(strings.TrimSpace(command), "$ "))
	if err != nil {
		return Command{}, err
	}
	if len(args) == 0 || path.Base(args[0]) != "curl" {
		return Command{}, errors.New("not a curl command")
	}
	args = expand(args[1:])
	out := Command{}
	var (
		data      []string
		method    string
		get, head bool
		json      bool
		urls      []string
	)
	warn := func(format string, a ...any) { out.Warnings = append(out.Warnings, fmt.Sprintf(format, a...)) }
	for i := 0; i < len(args); i++ {
		arg := args[i]
		kind, takes := withValue[arg]
		if !takes {
			k, known := flags[arg]
			switch {
			case !strings.HasPrefix(arg, "-") || arg == "-":
				urls = append(urls, arg)
			case !known:
				warn("ProxyGo ignores %s", arg)
			case k == "location":
				out.FollowRedirects = true
			case k == "insecure":
				out.Insecure = true
			case k == "get":
				get = true
			case k == "head":
				head = true
			case k == "compressed":
				if out.Header.Get("Accept-Encoding") == "" {
					out.Header.Add("Accept-Encoding", "deflate, gzip, br, zstd")
				}
			}
			continue
		}
		if i+1 >= len(args) {
			return Command{}, fmt.Errorf("%s needs a value", arg)
		}
		i++
		value := args[i]
		switch kind {
		case "request":
			method = strings.ToUpper(value)
		case "header":
			addHeader(&out.Header, value)
		case "data", "data-binary":
			if strings.HasPrefix(value, "@") {
				warn("%s %s reads a file: paste the body instead", arg, value)
				continue
			}
			data = append(data, value)
		case "data-raw":
			data = append(data, value)
		case "data-urlencode":
			encoded, ok := urlencode(value)
			if !ok {
				warn("%s %s reads a file: paste the body instead", arg, value)
				continue
			}
			data = append(data, encoded)
		case "json":
			json = true
			if strings.HasPrefix(value, "@") {
				warn("--json %s reads a file: paste the body instead", value)
				continue
			}
			data = append(data, value)
		case "form", "form-string":
			p, fileErr := formPart(value, kind == "form-string")
			if fileErr != "" {
				warn("%s", fileErr)
			}
			out.Parts = append(out.Parts, p)
		case "user":
			out.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(value)))
		case "user-agent":
			out.Header.Set("User-Agent", value)
		case "referer":
			out.Header.Set("Referer", strings.TrimSuffix(value, ";auto"))
		case "cookie":
			if !strings.Contains(value, "=") {
				warn("-b %s reads cookies from a file: ProxyGo sends none", value)
				continue
			}
			out.Header.Set("Cookie", value)
		case "url":
			urls = append(urls, value)
		case "max-time":
			if s, err := strconv.ParseFloat(value, 64); err == nil && s > 0 {
				out.Timeout = time.Duration(s * float64(time.Second))
			}
		case "max-redirs":
			if n, err := strconv.Atoi(value); err == nil {
				out.MaxRedirects = n
			}
		case "proxy":
			warn("ProxyGo sends the request itself, not through the proxy %s", value)
		case "cacert", "cert":
			warn("ProxyGo ignores %s %s: set certificates in its settings", arg, value)
		case "resolve":
			warn("ProxyGo ignores %s %s: use DNS Spoofing", arg, value)
		case "range":
			out.Header.Set("Range", "bytes="+value)
		case "upload":
			warn("%s %s uploads a file: paste the body instead", arg, value)
			method = cmpOr(method, http.MethodPut)
		}
	}
	if len(urls) == 0 {
		return Command{}, errors.New("the curl command has no URL")
	}
	if len(urls) > 1 {
		warn("ProxyGo sends the first of %d URLs", len(urls))
	}
	raw := urls[0]
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Command{}, fmt.Errorf("invalid URL %q", urls[0])
	}
	body := strings.Join(data, "&")
	if (get || head) && data != nil {
		if u.RawQuery != "" && body != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += body
		data, body = nil, ""
	}
	out.URL = u.String()
	switch {
	case len(out.Parts) > 0:
		b, ct, err := formdata.Multipart(out.Parts)
		if err != nil {
			return Command{}, err
		}
		out.Body = b
		out.Header.Set("Content-Type", ct)
		method = cmpOr(method, http.MethodPost)
	case data != nil:
		out.Body = []byte(body)
		method = cmpOr(method, http.MethodPost)
		if out.Header.Get("Content-Type") == "" {
			if json {
				out.Header.Set("Content-Type", "application/json")
			} else {
				out.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}
	}
	if json && out.Header.Get("Accept") == "" {
		out.Header.Set("Accept", "application/json")
	}
	switch {
	case method != "":
		out.Method = method
	case head:
		out.Method = http.MethodHead
	default:
		out.Method = http.MethodGet
	}
	return out, nil
}

func expand(args []string) []string {
	var out []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") || len(arg) <= 2 || arg[0] != '-' {
			out = append(out, arg)
			continue
		}
		for j := 1; j < len(arg); j++ {
			name := "-" + arg[j:j+1]
			out = append(out, name)
			if _, takes := withValue[name]; takes {
				if rest := arg[j+1:]; rest != "" {
					out = append(out, rest)
				}
				break
			}
		}
	}
	return out
}

func addHeader(h *flow.Header, line string) {
	if name, ok := strings.CutSuffix(strings.TrimSpace(line), ";"); ok && !strings.Contains(name, ":") {
		h.Add(strings.TrimSpace(name), "")
		return
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if name == "" {
		return
	}
	if value == "" {
		h.Del(name)
		return
	}
	h.Add(name, value)
}

func urlencode(v string) (string, bool) {
	if i := strings.IndexAny(v, "=@"); i >= 0 {
		if v[i] == '@' {
			return "", false
		}
		if i == 0 {
			return url.QueryEscape(v[1:]), true
		}
		return v[:i] + "=" + url.QueryEscape(v[i+1:]), true
	}
	return url.QueryEscape(v), true
}

func formPart(v string, literal bool) (formdata.Part, string) {
	name, value, _ := strings.Cut(v, "=")
	p := formdata.Part{Name: name, Enabled: true}
	if literal || (!strings.HasPrefix(value, "@") && !strings.HasPrefix(value, "<")) {
		value, ctype := splitFormParams(value)
		p.Value, p.ContentType = []byte(value), ctype
		return p, ""
	}
	file, ctype := splitFormParams(value[1:])
	p.ContentType = ctype
	if value[0] == '@' {
		p.FileName = path.Base(file)
		if fn := formParam(value, "filename"); fn != "" {
			p.FileName = fn
		}
	}
	return p, fmt.Sprintf("-F %s reads the file %s: choose it in the Body tab", name, file)
}

func splitFormParams(v string) (string, string) {
	value, params, ok := strings.Cut(v, ";")
	if !ok {
		return v, ""
	}
	return value, formParam(";"+params, "type")
}

func formParam(v, key string) string {
	for part := range strings.SplitSeq(v, ";") {
		if k, val, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == key {
			return strings.Trim(val, `"`)
		}
	}
	return ""
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func Split(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
				continue
			}
			if i+2 < len(s) && s[i+1] == '\r' && s[i+2] == '\n' {
				i += 2
				continue
			}
			if i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
				in = true
			}
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(s[i+1 : i+1+end])
			i += end + 1
			in = true
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			n, err := ansiC(s[i+2:], &cur)
			if err != nil {
				return nil, err
			}
			i += n + 1
			in = true
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					switch s[j+1] {
					case '"', '\\', '$', '`':
						j++
						cur.WriteByte(s[j])
						continue
					case '\n':
						j++
						continue
					}
				}
				cur.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, errors.New("unterminated double quote")
			}
			i = j
			in = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if in {
				args = append(args, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if in {
		args = append(args, cur.String())
	}
	return args, nil
}

func ansiC(s string, b *strings.Builder) (int, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' {
			return i + 1, nil
		}
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch e := s[i]; e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\\', '\'', '"', '?':
			b.WriteByte(e)
		case 'x', 'u', 'U':
			max := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			j := i + 1
			for j < len(s) && j-i-1 < max && isHex(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteByte('\\')
				b.WriteByte(e)
				continue
			}
			n, _ := strconv.ParseUint(s[i+1:j], 16, 32)
			if e == 'x' {
				b.WriteByte(byte(n))
			} else {
				b.WriteRune(rune(n))
			}
			i = j - 1
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(s) && j-i < 3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			n, _ := strconv.ParseUint(s[i:j], 8, 8)
			b.WriteByte(byte(n))
			i = j - 1
		default:
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return 0, errors.New("unterminated $' quote")
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
