package formdata

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"
)

type Part struct {
	Name        string
	Value       []byte
	FileName    string
	ContentType string
	Enabled     bool
}

func Multipart(parts []Part) ([]byte, string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for _, p := range parts {
		if !p.Enabled {
			continue
		}
		h := textproto.MIMEHeader{}
		disposition := "form-data; name=" + quote(p.Name)
		if p.FileName != "" {
			disposition += "; filename=" + quote(p.FileName)
		}
		h.Set("Content-Disposition", disposition)
		switch {
		case p.ContentType != "":
			h.Set("Content-Type", p.ContentType)
		case p.FileName != "":
			h.Set("Content-Type", "application/octet-stream")
		}
		pw, err := w.CreatePart(h)
		if err != nil {
			return nil, "", err
		}
		if _, err := pw.Write(p.Value); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return b.Bytes(), w.FormDataContentType(), nil
}

func quote(s string) string {
	return `"` + strings.NewReplacer("\"", "%22", "\r", "%0D", "\n", "%0A").Replace(s) + `"`
}

func ParseMultipart(body []byte, contentType string, limit int64) ([]Part, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}
	if params["boundary"] == "" {
		return nil, fmt.Errorf("no multipart boundary")
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var out []Part
	for {
		p, err := r.NextRawPart()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		data, err := io.ReadAll(io.LimitReader(p, limit))
		if err != nil {
			return out, err
		}
		out = append(out, Part{Name: p.FormName(), FileName: p.FileName(), ContentType: p.Header.Get("Content-Type"), Value: data, Enabled: true})
	}
}

func URLEncoded(parts []Part) []byte {
	var b strings.Builder
	for _, p := range parts {
		if !p.Enabled {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.Name))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(string(p.Value)))
	}
	return []byte(b.String())
}

func ParseURLEncoded(body []byte) []Part {
	var out []Part
	for field := range strings.SplitSeq(string(body), "&") {
		if field == "" {
			continue
		}
		name, value, _ := strings.Cut(field, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		out = append(out, Part{Name: name, Value: []byte(value), Enabled: true})
	}
	return out
}
