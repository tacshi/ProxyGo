package preview

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"proxygo/internal/flow"
)

func token(header, claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(claims)) + "." + enc([]byte("sig"))
}

func TestDecodeJWT(t *testing.T) {
	raw := token(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"ada","exp":1700000000,"iat":1699990000.5}`)
	if !LooksLikeJWT(raw) {
		t.Fatal("LooksLikeJWT")
	}
	jwt, err := DecodeJWT(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(jwt.Claims) != `{"sub":"ada","exp":1700000000,"iat":1699990000.5}` || string(jwt.Signature) != "sig" {
		t.Errorf("%s %q", jwt.Claims, jwt.Signature)
	}
	if !jwt.ExpiresAt.Equal(time.Unix(1700000000, 0)) || jwt.IssuedAt.UnixMilli() != 1699990000500 {
		t.Errorf("exp %v iat %v", jwt.ExpiresAt, jwt.IssuedAt)
	}
	if !jwt.Expired(time.Unix(1700000000, 0)) || jwt.Expired(time.Unix(1699999999, 0)) {
		t.Error("Expired")
	}
	if noExp, _ := DecodeJWT(token(`{"alg":"none"}`, `{}`)); noExp.Expired(time.Now()) {
		t.Error("a token without exp never expires")
	}

	for _, bad := range []string{"a.b", "a.b.c.d.e", token(`{"typ":"JWT"}`, `{}`), "eyJ.!!.x"} {
		if _, err := DecodeJWT(bad); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
	if !strings.Contains(func() string { _, err := DecodeJWT("a.b"); return err.Error() }(), "2 parts") {
		t.Error("the error names the parts")
	}
	if LooksLikeJWT("hello.world.again") || LooksLikeJWT("eyJ") {
		t.Error("LooksLikeJWT accepts non-tokens")
	}

	f := flow.New("A")
	f.Request = &flow.Request{}
	f.Request.Header.Set("Authorization", "Bearer "+raw)
	if FlowJWT(f) == nil {
		t.Error("FlowJWT")
	}
	f.Request.Header.Set("Authorization", "Basic YWRhOnB3")
	if FlowJWT(f) != nil {
		t.Error("Basic is not a JWT")
	}
}

func TestDecodeBase64(t *testing.T) {
	for in, want := range map[string]string{"aGVsbG8=": "hello", "aGVsbG8": "hello", "aGk_": "hi?", "aGk/": "hi?", " aGVs\nbG8= ": "hello"} {
		if got, ok := DecodeBase64(in); !ok || string(got) != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if _, ok := DecodeBase64("not base64!"); ok {
		t.Error("decoded garbage")
	}
}

func TestParseSSE(t *testing.T) {
	body := "\xEF\xBB\xBF: keep-alive\r\n" +
		"event: update\r\nid: 7\r\ndata: line one\r\ndata:line two\r\nretry: 3000\r\n\r\n" +
		"data: {\"n\":1}\n\n" +
		"event: noData\n\n" +
		"data\rdata: x\r\r" +
		"retry: soon\nid: bad\x00id\ndata: y\n\n" +
		"data: partial"
	s := ParseSSE([]byte(body))
	if s.Comments != 1 {
		t.Errorf("comments %d", s.Comments)
	}
	want := []SSEEvent{
		{Type: "update", Data: "line one\nline two", ID: "7", Retry: 3 * time.Second},
		{Type: "message", Data: `{"n":1}`, ID: "7"},
		{Type: "message", Data: "\nx", ID: "7"},
		{Type: "message", Data: "y", ID: "7"},
	}
	if len(s.Events) != len(want) {
		t.Fatalf("%d events: %+v", len(s.Events), s.Events)
	}
	for i := range want {
		if s.Events[i] != want[i] {
			t.Errorf("event %d: %+v, want %+v", i, s.Events[i], want[i])
		}
	}
	if s.Pending == nil || s.Pending.Data != "partial" {
		t.Errorf("pending %+v", s.Pending)
	}
	if !IsSSE("text/event-stream; charset=utf-8") || IsSSE("text/plain") {
		t.Error("IsSSE")
	}
}

func TestMsgPackText(t *testing.T) {
	b := []byte{0x84,
		0xa1, 'b', 0x01,
		0xa1, 'a', 0x95, 0xc3, 0xc0, 0xff, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xa1, 'x',
		0x07, 0xc4, 0x02, 0x01, 0x02,
		0xa1, 't', 0xd6, 0xff, 0x65, 0x53, 0xf1, 0x00,
	}
	got, err := MsgPackText(b)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "b": 1,
  "a": [
    true,
    null,
    -1,
    1.5,
    "x"
  ],
  "7": "<bin 2 bytes> 0102",
  "t": "2023-11-14T22:13:20Z"
}`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	for _, bad := range [][]byte{{0xc1}, {0x92, 0x01}, {0xdc, 0xff, 0xff}, {0xa5, 'a'}} {
		if _, err := MsgPackText(bad); err == nil {
			t.Errorf("%x decoded", bad)
		}
	}
	if !IsMsgPack("application/x-msgpack") || IsMsgPack("application/json") {
		t.Error("IsMsgPack")
	}
}
