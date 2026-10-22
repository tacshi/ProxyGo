package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/itchyny/gojq"
	"github.com/theory/jsonpath"
)

const (
	LangJQ       = "jq"
	LangJSONPath = "jsonpath"
	LangKeyPath  = "keypath"
)

const (
	timeout    = 2 * time.Second
	maxResults = 1000
)

func Run(lang string, input []byte, expr string) ([]any, error) {
	switch lang {
	case LangJQ:
		return JQ(input, expr)
	case LangJSONPath:
		return JSONPath(input, expr)
	case LangKeyPath, "":
		v, err := KeyPath(input, expr)
		if err != nil {
			return nil, err
		}
		return []any{v}, nil
	}
	return nil, fmt.Errorf("unknown query language %q", lang)
}

func Decode(input []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if dec.More() {
		return nil, errors.New("not JSON: more than one value")
	}
	return normalize(v), nil
}

func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			if n == int64(int(n)) {
				return int(n)
			}
		}
		if !strings.ContainsAny(string(x), ".eE") {
			if b, ok := new(big.Int).SetString(string(x), 10); ok {
				return b
			}
		}
		f, _ := x.Float64()
		return f
	case map[string]any:
		for k, e := range x {
			x[k] = normalize(e)
		}
	case []any:
		for i, e := range x {
			x[i] = normalize(e)
		}
	}
	return v
}

var jqCode sync.Map

func compileJQ(expr string) (*gojq.Code, error) {
	if c, ok := jqCode.Load(expr); ok {
		return c.(*gojq.Code), nil
	}
	q, err := gojq.Parse(expr)
	if err != nil {
		return nil, err
	}
	c, err := gojq.Compile(q)
	if err != nil {
		return nil, err
	}
	jqCode.Store(expr, c)
	return c, nil
}

func JQ(input []byte, expr string) ([]any, error) {
	code, err := compileJQ(strings.TrimSpace(expr))
	if err != nil {
		return nil, err
	}
	v, err := Decode(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	iter := code.RunWithContext(ctx, v)
	var out []any
	for {
		r, ok := iter.Next()
		if !ok {
			return out, nil
		}
		if err, ok := r.(error); ok {
			var halt *gojq.HaltError
			if errors.As(err, &halt) && halt.Value() == nil {
				return out, nil
			}
			return out, err
		}
		if len(out) == maxResults {
			return out, fmt.Errorf("more than %d results", maxResults)
		}
		out = append(out, r)
	}
}

var paths sync.Map

func JSONPath(input []byte, expr string) ([]any, error) {
	expr = strings.TrimSpace(expr)
	var p *jsonpath.Path
	if c, ok := paths.Load(expr); ok {
		p = c.(*jsonpath.Path)
	} else {
		var err error
		if p, err = jsonpath.Parse(expr); err != nil {
			return nil, err
		}
		paths.Store(expr, p)
	}
	v, err := Decode(input)
	if err != nil {
		return nil, err
	}
	nodes := p.Select(v)
	if len(nodes) > maxResults {
		nodes = nodes[:maxResults]
	}
	return []any(nodes), nil
}

func KeyPath(input []byte, path string) (any, error) {
	v, err := Decode(input)
	if err != nil {
		return nil, err
	}
	path = strings.NewReplacer("[", ".", "]", "").Replace(strings.TrimSpace(path))
	path = strings.TrimPrefix(strings.TrimPrefix(path, "$"), ".")
	for part := range strings.SplitSeq(path, ".") {
		if part == "" {
			continue
		}
		switch cur := v.(type) {
		case map[string]any:
			next, ok := cur[part]
			if !ok {
				return nil, fmt.Errorf("no key %q", part)
			}
			v = next
		case []any:
			n, err := strconv.Atoi(part)
			if err != nil || n < -len(cur) || n >= len(cur) {
				return nil, fmt.Errorf("no item %q in %d", part, len(cur))
			}
			if n < 0 {
				n += len(cur)
			}
			v = cur[n]
		default:
			return nil, fmt.Errorf("%q is in a %s, not an object or array", part, kind(v))
		}
	}
	return v, nil
}

func kind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	}
	return "number"
}

func Text(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func Join(values []any) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = Text(v)
	}
	return strings.Join(parts, "\n")
}

func Pretty(values []any) string {
	var b strings.Builder
	for i, v := range values {
		if i > 0 {
			b.WriteByte('\n')
		}
		out, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			fmt.Fprint(&b, v)
			continue
		}
		b.Write(out)
	}
	return b.String()
}

func Check(lang, expr string) error {
	switch lang {
	case LangJQ:
		_, err := compileJQ(strings.TrimSpace(expr))
		return err
	case LangJSONPath:
		_, err := jsonpath.Parse(strings.TrimSpace(expr))
		return err
	}
	return nil
}
