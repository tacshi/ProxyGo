package curl

import (
	"slices"
	"strings"
	"testing"
	"time"

	"proxygo/internal/formdata"
)

func TestSplit(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{`curl 'https://a.example/x?y=1' -H 'A: b'`, []string{"curl", "https://a.example/x?y=1", "-H", "A: b"}},
		{"curl \\\n  -X POST \\\r\n  url", []string{"curl", "-X", "POST", "url"}},
		{`curl "a \"quoted\" \$x" b\ c`, []string{"curl", `a "quoted" $x`, "b c"}},
		{`curl $'{"a":"it\'s\n"}' $'\x41é\101'`, []string{"curl", "{\"a\":\"it's\n\"}", "Aé" + "A"}},
		{`curl 'it'\''s'`, []string{"curl", "it's"}},
	} {
		got, err := Split(tc.in)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("Split(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := Split(`curl 'open`); err == nil {
		t.Error("an unterminated quote is an error")
	}
}

func TestParseChromeCommand(t *testing.T) {
	cmd := `curl 'https://api.example.com/v1/items?page=2' \
  -H 'accept: application/json' \
  -H 'content-type: application/json' \
  -b 'session=abc; theme=dark' \
  --data-raw $'{"name":"it\'s"}' \
  --compressed`
	c, err := Parse(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if c.Method != "POST" || c.URL != "https://api.example.com/v1/items?page=2" {
		t.Errorf("%s %s", c.Method, c.URL)
	}
	if string(c.Body) != `{"name":"it's"}` {
		t.Errorf("body %q", c.Body)
	}
	for k, v := range map[string]string{"Content-Type": "application/json", "Cookie": "session=abc; theme=dark", "Accept-Encoding": "deflate, gzip, br, zstd", "Accept": "application/json"} {
		if got := c.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if len(c.Warnings) != 0 {
		t.Errorf("warnings %q", c.Warnings)
	}
}

func TestParseOptions(t *testing.T) {
	c, err := Parse(`curl -sSL -XPUT -u ada:secret --max-time 2.5 --max-redirs 3 -k example.com/a -d x=1 -d y=2`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Method != "PUT" || c.URL != "http://example.com/a" || !c.FollowRedirects || !c.Insecure || c.MaxRedirects != 3 || c.Timeout != 2500*time.Millisecond {
		t.Errorf("%+v", c)
	}
	if string(c.Body) != "x=1&y=2" || c.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("body %q, %q", c.Body, c.Header.Get("Content-Type"))
	}
	if c.Header.Get("Authorization") != "Basic YWRhOnNlY3JldA==" {
		t.Errorf("auth %q", c.Header.Get("Authorization"))
	}

	g, err := Parse(`curl -G https://e.example/s?a=1 --data-urlencode 'q=hello world' -d n=2`)
	if err != nil {
		t.Fatal(err)
	}
	if g.Method != "GET" || g.URL != "https://e.example/s?a=1&q=hello+world&n=2" || len(g.Body) != 0 {
		t.Errorf("-G: %s %s %q", g.Method, g.URL, g.Body)
	}

	j, err := Parse(`curl --json '{"a":1}' https://e.example`)
	if err != nil || j.Method != "POST" || j.Header.Get("Content-Type") != "application/json" || j.Header.Get("Accept") != "application/json" {
		t.Errorf("--json: %+v %v", j, err)
	}

	h, _ := Parse(`curl -I https://e.example -H 'X-Empty;' -H 'Accept:'`)
	if h.Method != "HEAD" || len(h.Header.Entries) != 1 || h.Header.Entries[0].Key.Name != "X-Empty" {
		t.Errorf("-I: %s %+v", h.Method, h.Header.Entries)
	}
}

func TestParseForm(t *testing.T) {
	c, err := Parse(`curl -F 'name=Ada' -F 'avatar=@/tmp/a.png;type=image/png' https://e.example/upload`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Method != "POST" || !strings.HasPrefix(c.Header.Get("Content-Type"), "multipart/form-data; boundary=") {
		t.Fatalf("%s %q", c.Method, c.Header.Get("Content-Type"))
	}
	parts, err := formdata.ParseMultipart(c.Body, c.Header.Get("Content-Type"), 1<<20)
	if err != nil || len(parts) != 2 {
		t.Fatalf("%v %+v", err, parts)
	}
	if parts[0].Name != "name" || string(parts[0].Value) != "Ada" || parts[1].FileName != "a.png" || parts[1].ContentType != "image/png" {
		t.Errorf("%+v", parts)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "/tmp/a.png") {
		t.Errorf("a file is not read, and says so: %q", c.Warnings)
	}
}

func TestParseReportsWhatItIgnores(t *testing.T) {
	c, err := Parse(`curl -d @body.json --proxy http://p:1 --foo https://e.example`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) != 3 {
		t.Errorf("warnings %q", c.Warnings)
	}
	if _, err := Parse(`curl -H`); err == nil {
		t.Error("an option without its value is an error")
	}
	if _, err := Parse(`wget https://e.example`); err == nil {
		t.Error("not curl")
	}
	if !Looks("  $ curl https://x") || Looks("https://curl.se") || Looks("curl") {
		t.Error("Looks")
	}
}
