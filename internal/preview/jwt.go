package preview

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"proxygo/internal/flow"
)

type JWT struct {
	Raw                            string
	Header                         json.RawMessage
	Claims                         json.RawMessage
	Signature                      []byte
	ExpiresAt, IssuedAt, NotBefore time.Time
}

func (t *JWT) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

var ErrNotJWT = errors.New("invalid JWT token")

func DecodeJWT(raw string) (*JWT, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	switch len(parts) {
	case 3:
	case 5:
		return nil, errors.New("an encrypted JWT (JWE) cannot be read without its key")
	default:
		return nil, fmt.Errorf("malformed JWT: it has %d parts, not 3", len(parts))
	}
	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("JWT header: %w", err)
	}
	claims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWT claims: %w", err)
	}
	var h map[string]any
	if json.Unmarshal(header, &h) != nil {
		return nil, ErrNotJWT
	}
	if _, ok := h["alg"]; !ok {
		return nil, fmt.Errorf("%w: its header has no alg", ErrNotJWT)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[2], "="))
	if err != nil {
		return nil, fmt.Errorf("JWT signature: %w", err)
	}
	t := &JWT{Raw: raw, Header: header, Claims: claims, Signature: sig}
	var c map[string]any
	dec := json.NewDecoder(bytes.NewReader(claims))
	dec.UseNumber()
	if dec.Decode(&c) == nil {
		t.ExpiresAt = numericDate(c["exp"])
		t.IssuedAt = numericDate(c["iat"])
		t.NotBefore = numericDate(c["nbf"])
	}
	return t, nil
}

func decodeSegment(s string) (json.RawMessage, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, errors.New("not JSON")
	}
	return b, nil
}

func numericDate(v any) time.Time {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}
	}
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return time.Time{}
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9))
}

func LooksLikeJWT(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 16 || len(s) > 64<<10 || strings.Count(s, ".") != 2 || !strings.HasPrefix(s, "eyJ") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !jwtByte(s[i]) {
			return false
		}
	}
	return true
}

func jwtByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '='
}

func BearerToken(h flow.Header) string {
	v := strings.TrimSpace(h.Get("Authorization"))
	if len(v) > 7 && strings.EqualFold(v[:7], "Bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

func FlowJWT(f *flow.Flow) *JWT {
	if f == nil || f.Request == nil {
		return nil
	}
	tok := BearerToken(f.Request.Header)
	if !LooksLikeJWT(tok) {
		return nil
	}
	t, err := DecodeJWT(tok)
	if err != nil {
		return nil
	}
	return t
}

func DecodeBase64(s string) ([]byte, bool) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func Printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
