package preview

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

var ErrNotMsgPack = errors.New("invalid MessagePack data")

func IsMsgPack(contentType string) bool {
	mt, _, _ := strings.Cut(strings.ToLower(contentType), ";")
	switch strings.TrimSpace(mt) {
	case "application/msgpack", "application/x-msgpack", "application/vnd.msgpack":
		return true
	}
	return false
}

func MsgPackText(b []byte) (string, error) {
	d := &mpDecoder{b: b}
	var out strings.Builder
	for n := 0; d.i < len(d.b); n++ {
		if n > 0 {
			out.WriteString("\n")
		}
		if err := d.value(&out, 0); err != nil {
			return "", err
		}
		if n > 10000 {
			return "", ErrNotMsgPack
		}
	}
	if out.Len() == 0 {
		return "", ErrNotMsgPack
	}
	return out.String(), nil
}

type mpDecoder struct {
	b []byte
	i int
}

func (d *mpDecoder) take(n int) ([]byte, error) {
	if n < 0 || d.i+n > len(d.b) {
		return nil, ErrNotMsgPack
	}
	p := d.b[d.i : d.i+n]
	d.i += n
	return p, nil
}

func (d *mpDecoder) uint(n int) (uint64, error) {
	p, err := d.take(n)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return uint64(p[0]), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(p)), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(p)), nil
	}
	return binary.BigEndian.Uint64(p), nil
}

func (d *mpDecoder) value(out *strings.Builder, depth int) error {
	if depth > 128 {
		return ErrNotMsgPack
	}
	c, err := d.take(1)
	if err != nil {
		return err
	}
	t := c[0]
	switch {
	case t <= 0x7f:
		out.WriteString(strconv.Itoa(int(t)))
		return nil
	case t >= 0xe0:
		out.WriteString(strconv.Itoa(int(int8(t))))
		return nil
	case t&0xf0 == 0x80:
		return d.mapOf(out, int(t&0x0f), depth)
	case t&0xf0 == 0x90:
		return d.array(out, int(t&0x0f), depth)
	case t&0xe0 == 0xa0:
		return d.str(out, int(t&0x1f))
	}
	switch t {
	case 0xc0:
		out.WriteString("null")
	case 0xc2:
		out.WriteString("false")
	case 0xc3:
		out.WriteString("true")
	case 0xc4, 0xc5, 0xc6:
		n, err := d.uint(1 << (t - 0xc4))
		if err != nil {
			return err
		}
		p, err := d.take(int(n))
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%q", fmt.Sprintf("<bin %d bytes> %s", len(p), short(hex.EncodeToString(p))))
	case 0xc7, 0xc8, 0xc9:
		n, err := d.uint(1 << (t - 0xc7))
		if err != nil {
			return err
		}
		return d.ext(out, int(n))
	case 0xca:
		v, err := d.uint(4)
		if err != nil {
			return err
		}
		out.WriteString(number(float64(math.Float32frombits(uint32(v)))))
	case 0xcb:
		v, err := d.uint(8)
		if err != nil {
			return err
		}
		out.WriteString(number(math.Float64frombits(v)))
	case 0xcc, 0xcd, 0xce, 0xcf:
		v, err := d.uint(1 << (t - 0xcc))
		if err != nil {
			return err
		}
		out.WriteString(strconv.FormatUint(v, 10))
	case 0xd0, 0xd1, 0xd2, 0xd3:
		size := 1 << (t - 0xd0)
		v, err := d.uint(size)
		if err != nil {
			return err
		}
		var n int64
		switch size {
		case 1:
			n = int64(int8(v))
		case 2:
			n = int64(int16(v))
		case 4:
			n = int64(int32(v))
		default:
			n = int64(v)
		}
		out.WriteString(strconv.FormatInt(n, 10))
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8:
		return d.ext(out, 1<<(t-0xd4))
	case 0xd9, 0xda, 0xdb:
		n, err := d.uint(1 << (t - 0xd9))
		if err != nil {
			return err
		}
		return d.str(out, int(n))
	case 0xdc, 0xdd:
		n, err := d.uint(2 << (t - 0xdc))
		if err != nil {
			return err
		}
		return d.array(out, int(n), depth)
	case 0xde, 0xdf:
		n, err := d.uint(2 << (t - 0xde))
		if err != nil {
			return err
		}
		return d.mapOf(out, int(n), depth)
	default:
		return ErrNotMsgPack
	}
	return nil
}

func (d *mpDecoder) str(out *strings.Builder, n int) error {
	p, err := d.take(n)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(string(p))
	out.Write(b)
	return nil
}

func (d *mpDecoder) array(out *strings.Builder, n, depth int) error {
	if n > len(d.b)-d.i {
		return ErrNotMsgPack
	}
	if n == 0 {
		out.WriteString("[]")
		return nil
	}
	out.WriteString("[\n")
	for k := range n {
		indent(out, depth+1)
		if err := d.value(out, depth+1); err != nil {
			return err
		}
		if k < n-1 {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	indent(out, depth)
	out.WriteByte(']')
	return nil
}

func (d *mpDecoder) mapOf(out *strings.Builder, n, depth int) error {
	if 2*n > len(d.b)-d.i {
		return ErrNotMsgPack
	}
	if n == 0 {
		out.WriteString("{}")
		return nil
	}
	out.WriteString("{\n")
	for k := range n {
		indent(out, depth+1)
		var key strings.Builder
		if err := d.value(&key, depth+1); err != nil {
			return err
		}
		ks := key.String()
		if !strings.HasPrefix(ks, `"`) {
			b, _ := json.Marshal(ks)
			ks = string(b)
		}
		out.WriteString(ks + ": ")
		if err := d.value(out, depth+1); err != nil {
			return err
		}
		if k < n-1 {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	indent(out, depth)
	out.WriteByte('}')
	return nil
}

func (d *mpDecoder) ext(out *strings.Builder, n int) error {
	tb, err := d.take(1)
	if err != nil {
		return err
	}
	p, err := d.take(n)
	if err != nil {
		return err
	}
	typ := int8(tb[0])
	if typ == -1 {
		if t, ok := timestamp(p); ok {
			fmt.Fprintf(out, "%q", t.UTC().Format(time.RFC3339Nano))
			return nil
		}
	}
	fmt.Fprintf(out, "%q", fmt.Sprintf("<ext %d, %d bytes> %s", typ, len(p), short(hex.EncodeToString(p))))
	return nil
}

func timestamp(p []byte) (time.Time, bool) {
	switch len(p) {
	case 4:
		return time.Unix(int64(binary.BigEndian.Uint32(p)), 0), true
	case 8:
		v := binary.BigEndian.Uint64(p)
		return time.Unix(int64(v&0x3ffffffff), int64(v>>34)), true
	case 12:
		ns := binary.BigEndian.Uint32(p[:4])
		return time.Unix(int64(binary.BigEndian.Uint64(p[4:])), int64(ns)), true
	}
	return time.Time{}, false
}

func number(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return strconv.Quote(strconv.FormatFloat(f, 'g', -1, 64))
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func short(s string) string {
	if len(s) > 128 {
		return s[:128] + "…"
	}
	return s
}

func indent(out *strings.Builder, depth int) {
	for range depth {
		out.WriteString("  ")
	}
}
