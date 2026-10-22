package protobuf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrNotProtobuf = errors.New("not a protobuf message")

func DecodeRaw(b []byte) (string, error) {
	var out strings.Builder
	if err := decode(&out, b, 0); err != nil {
		return "", err
	}
	return out.String(), nil
}

func DecodeGRPC(b []byte) (string, error) {
	var out strings.Builder
	n := 0
	for len(b) > 0 {
		if len(b) < 5 {
			return "", fmt.Errorf("truncated gRPC frame")
		}
		compressed := b[0] == 1
		size := int(binary.BigEndian.Uint32(b[1:5]))
		if size > len(b)-5 {
			return "", fmt.Errorf("gRPC frame of %d bytes, %d left", size, len(b)-5)
		}
		msg := b[5 : 5+size]
		b = b[5+size:]
		n++
		fmt.Fprintf(&out, "# message %d (%d bytes)\n", n, size)
		if compressed {
			out.WriteString("# compressed; not decoded\n")
			continue
		}
		if err := decode(&out, msg, 0); err != nil {
			fmt.Fprintf(&out, "# %v\n", err)
		}
	}
	return out.String(), nil
}

func varint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

type field struct {
	num  uint64
	wire int
	v    uint64
	data []byte
}

func parse(b []byte) ([]field, error) {
	var fields []field
	for len(b) > 0 {
		key, n := varint(b)
		if n == 0 {
			return nil, ErrNotProtobuf
		}
		b = b[n:]
		f := field{num: key >> 3, wire: int(key & 7)}
		if f.num == 0 || f.num > 536870911 {
			return nil, ErrNotProtobuf
		}
		switch f.wire {
		case 0:
			v, n := varint(b)
			if n == 0 {
				return nil, ErrNotProtobuf
			}
			f.v, b = v, b[n:]
		case 1:
			if len(b) < 8 {
				return nil, ErrNotProtobuf
			}
			f.v, b = binary.LittleEndian.Uint64(b), b[8:]
		case 2:
			l, n := varint(b)
			if n == 0 || l > uint64(len(b)-n) {
				return nil, ErrNotProtobuf
			}
			f.data, b = b[n:n+int(l)], b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, ErrNotProtobuf
			}
			f.v, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		default:
			return nil, ErrNotProtobuf
		}
		fields = append(fields, f)
	}
	return fields, nil
}

func decode(out *strings.Builder, b []byte, depth int) error {
	fields, err := parse(b)
	if err != nil {
		return err
	}
	indent := strings.Repeat("  ", depth)
	for _, f := range fields {
		switch f.wire {
		case 0:
			fmt.Fprintf(out, "%s%d: %d\n", indent, f.num, f.v)
		case 1:
			fmt.Fprintf(out, "%s%d: 0x%016x  # double %s\n", indent, f.num, f.v, formatFloat(math.Float64frombits(f.v)))
		case 5:
			fmt.Fprintf(out, "%s%d: 0x%08x  # float %s\n", indent, f.num, f.v, formatFloat(float64(math.Float32frombits(uint32(f.v)))))
		case 2:
			if len(f.data) > 0 && depth < 32 && looksLikeMessage(f.data) {
				fmt.Fprintf(out, "%s%d {\n", indent, f.num)
				_ = decode(out, f.data, depth+1)
				fmt.Fprintf(out, "%s}\n", indent)
				continue
			}
			if utf8.Valid(f.data) && printable(string(f.data)) {
				fmt.Fprintf(out, "%s%d: %s\n", indent, f.num, strconv.Quote(string(f.data)))
				continue
			}
			if packed, ok := packedVarints(f.data); ok {
				fmt.Fprintf(out, "%s%d: <%d bytes> %x  # packed %s\n", indent, f.num, len(f.data), f.data[:min(len(f.data), 64)], packed)
				continue
			}
			fmt.Fprintf(out, "%s%d: <%d bytes> %x\n", indent, f.num, len(f.data), f.data[:min(len(f.data), 64)])
		}
	}
	return nil
}

func packedVarints(b []byte) (string, bool) {
	var vals []string
	for len(b) > 0 {
		v, n := varint(b)
		if n == 0 {
			return "", false
		}
		if len(vals) == 32 {
			vals = append(vals, "…")
			break
		}
		vals = append(vals, strconv.FormatUint(v, 10))
		b = b[n:]
	}
	return "[" + strings.Join(vals, ", ") + "]", len(vals) > 0
}

func looksLikeMessage(b []byte) bool {
	fields, err := parse(b)
	if err != nil || len(fields) == 0 {
		return false
	}
	if utf8.Valid(b) && printable(string(b)) {
		return false
	}
	return true
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func Is(contentType string) (proto, grpc bool) {
	ct := strings.ToLower(contentType)
	grpc = strings.HasPrefix(ct, "application/grpc") && !strings.Contains(ct, "grpc-web-text")
	proto = grpc || strings.Contains(ct, "protobuf") || strings.Contains(ct, "x-proto")
	return proto, grpc
}
