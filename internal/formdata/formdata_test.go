package formdata

import (
	"slices"
	"testing"
)

func TestMultipartRoundTrip(t *testing.T) {
	parts := []Part{
		{Name: "name", Value: []byte("Ada"), Enabled: true},
		{Name: "off", Value: []byte("x")},
		{Name: `we"ird`, Value: []byte("\x00\x01"), FileName: "a\nb.bin", Enabled: true},
	}
	body, ct, err := Multipart(parts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMultipart(body, ct, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "name" || string(got[0].Value) != "Ada" {
		t.Fatalf("parts %+v", got)
	}
	if got[1].FileName != "a%0Ab.bin" || got[1].ContentType != "application/octet-stream" || string(got[1].Value) != "\x00\x01" {
		t.Fatalf("file %+v", got[1])
	}
	if _, err := ParseMultipart(body, "multipart/form-data", 10); err == nil {
		t.Fatal("no boundary accepted")
	}
}

func TestURLEncodedKeepsOrderAndRepeats(t *testing.T) {
	parts := ParseURLEncoded([]byte("b=2&a=1&b=3&sp=a+b&pct=%26"))
	var names []string
	for _, p := range parts {
		names = append(names, p.Name+"="+string(p.Value))
	}
	if !slices.Equal(names, []string{"b=2", "a=1", "b=3", "sp=a b", "pct=&"}) {
		t.Fatalf("parsed %q", names)
	}
	if s := string(URLEncoded(parts)); s != "b=2&a=1&b=3&sp=a+b&pct=%26" {
		t.Fatalf("written %q", s)
	}
}
