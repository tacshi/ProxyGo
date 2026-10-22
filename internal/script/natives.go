package script

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- scripts ask for MD5 and SHA-1 by name, as Node's crypto offers them.
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- scripts ask for MD5 and SHA-1 by name, as Node's crypto offers them.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	gohash "hash"
	"io"
	"regexp"
	"strings"
	"uuid"

	"github.com/dop251/goja"
)

func installNatives(vm *goja.Runtime) {
	o := vm.NewObject()
	set := func(name string, fn any) { _ = o.Set(name, fn) }
	set("base64Encode", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) })
	set("base64Decode", func(s string) (string, error) {
		b, err := decodeBase64(s)
		return string(b), err
	})
	set("base64URLDecode", func(s string) (string, error) {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		return string(b), err
	})
	set("base64Bytes", func(v goja.Value) (string, error) {
		switch x := v.Export().(type) {
		case goja.ArrayBuffer:
			return base64.StdEncoding.EncodeToString(x.Bytes()), nil
		case []byte:
			return base64.StdEncoding.EncodeToString(x), nil
		}
		return "", errors.New("not binary data")
	})
	set("hash", func(alg, s string) (string, error) {
		h, err := hasher(alg)
		if err != nil {
			return "", err
		}
		h.Write([]byte(s))
		return hex.EncodeToString(h.Sum(nil)), nil
	})
	set("hmac", func(alg, s, key string) (string, error) {
		if _, err := hasher(alg); err != nil {
			return "", err
		}
		m := hmac.New(func() gohash.Hash { h, _ := hasher(alg); return h }, []byte(key))
		m.Write([]byte(s))
		return hex.EncodeToString(m.Sum(nil)), nil
	})
	set("uuid", func() string { return uuid.New().String() })
	set("aesEncrypt", aesEncrypt)
	set("aesDecrypt", aesDecrypt)
	set("compress", compress)
	set("decompress", decompress)
	set("formatXML", formatXML)
	set("minifyXML", minifyXML)
	set("formatCSS", formatCSS)
	set("minifyCSS", minifyCSS)
	_ = vm.Set("__proxygo", o)
}

func hasher(alg string) (gohash.Hash, error) {
	switch strings.ToLower(alg) {
	case "md5":
		return md5.New(), nil // #nosec G401 -- scripts ask for MD5 and SHA-1 by name, as Node's crypto offers them.
	case "sha1":
		return sha1.New(), nil // #nosec G401 -- scripts ask for MD5 and SHA-1 by name, as Node's crypto offers them.
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("unknown hash %q", alg)
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not Base64")
}

func evpBytesToKey(pass, salt []byte, keyLen, ivLen int) ([]byte, []byte) {
	var out, prev []byte
	for len(out) < keyLen+ivLen {
		h := md5.New() // #nosec G401 -- scripts ask for MD5 and SHA-1 by name, as Node's crypto offers them.
		h.Write(prev)
		h.Write(pass)
		h.Write(salt)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen], out[keyLen : keyLen+ivLen]
}

func aesEncrypt(text, pass string) (string, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, iv := evpBytesToKey([]byte(pass), salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(text)%aes.BlockSize
	plain := append([]byte(text), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)
	return base64.StdEncoding.EncodeToString(append(append([]byte("Salted__"), salt...), ct...)), nil
}

func aesDecrypt(b64, pass string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	if len(data) < 16 || string(data[:8]) != "Salted__" || (len(data)-16)%aes.BlockSize != 0 || len(data) == 16 {
		return "", errors.New("not text CryptoJS encrypted with a passphrase")
	}
	key, iv := evpBytesToKey([]byte(pass), data[8:16], 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plain := make([]byte, len(data)-16)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data[16:])
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(plain) || !bytes.Equal(plain[len(plain)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return "", errors.New("wrong passphrase")
	}
	return string(plain[:len(plain)-pad]), nil
}

func compress(kind, text string) (string, error) {
	var b bytes.Buffer
	var w io.WriteCloser
	switch kind {
	case "gzip":
		w = gzip.NewWriter(&b)
	default:
		w = zlib.NewWriter(&b)
	}
	if _, err := io.WriteString(w, text); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

func decompress(kind, b64 string) (string, error) {
	data, err := decodeBase64(b64)
	if err != nil {
		return "", err
	}
	var r io.ReadCloser
	if kind == "gzip" {
		r, err = gzip.NewReader(bytes.NewReader(data))
	} else {
		r, err = zlib.NewReader(bytes.NewReader(data))
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(io.LimitReader(r, 64<<20))
	return string(out), err
}

func formatXML(s string) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(s))
	var b strings.Builder
	enc := xml.NewEncoder(&b)
	enc.Indent("", "  ")
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if cd, ok := tok.(xml.CharData); ok {
			if strings.TrimSpace(string(cd)) == "" {
				continue
			}
		}
		if err := enc.EncodeToken(xml.CopyToken(tok)); err != nil {
			return "", err
		}
	}
	if err := enc.Flush(); err != nil {
		return "", err
	}
	return b.String(), nil
}

var betweenTags = regexp.MustCompile(`>\s+<`)

func minifyXML(s string) string { return strings.TrimSpace(betweenTags.ReplaceAllString(s, "><")) }

var (
	cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssSpace   = regexp.MustCompile(`\s+`)
	cssPunct   = regexp.MustCompile(`\s*([{};:,>])\s*`)
)

func minifyCSS(s string) string {
	s = cssComment.ReplaceAllString(s, "")
	s = cssSpace.ReplaceAllString(s, " ")
	s = cssPunct.ReplaceAllString(s, "$1")
	return strings.TrimSpace(strings.ReplaceAll(s, ";}", "}"))
}

func formatCSS(s string) string {
	s = minifyCSS(s)
	var b strings.Builder
	depth := 0
	indent := func() { b.WriteString(strings.Repeat("  ", depth)) }
	inString := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString != 0 {
			b.WriteByte(c)
			if c == inString && s[i-1] != '\\' {
				inString = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inString = c
			b.WriteByte(c)
		case '{':
			b.WriteString(" {\n")
			depth++
			indent()
		case ';':
			b.WriteString(";\n")
			indent()
		case '}':
			if !strings.HasSuffix(b.String(), "\n"+strings.Repeat("  ", depth)) {
				b.WriteString(";\n")
			} else {
				str := b.String()
				b.Reset()
				b.WriteString(strings.TrimRight(str, " "))
			}
			depth = max(depth-1, 0)
			indent()
			b.WriteString("}\n")
			indent()
		case ':':
			if j := strings.IndexAny(s[i:], "{;}"); depth > 0 && (j < 0 || s[i+j] != '{') {
				b.WriteString(": ")
			} else {
				b.WriteByte(c)
			}
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String()) + "\n"
}
