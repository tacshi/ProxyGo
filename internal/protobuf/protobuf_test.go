package protobuf

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

func tag(num, wire int) []byte { return binary.AppendUvarint(nil, uint64(num<<3|wire)) }

func lenField(num int, b []byte) []byte {
	out := tag(num, 2)
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}

func message() []byte {
	inner := append(tag(1, 0), binary.AppendUvarint(nil, 7)...)
	inner = append(inner, lenField(2, []byte("nested"))...)
	var b []byte
	b = append(b, tag(1, 0)...)
	b = binary.AppendUvarint(b, 150)
	b = append(b, lenField(2, []byte("hello"))...)
	b = append(b, lenField(3, inner)...)
	b = append(b, tag(4, 1)...)
	b = binary.LittleEndian.AppendUint64(b, math.Float64bits(2.5))
	b = append(b, tag(5, 5)...)
	b = binary.LittleEndian.AppendUint32(b, math.Float32bits(1.5))
	b = append(b, lenField(6, []byte{0xff, 0x00, 0x10})...)
	return b
}

func TestDecodeRaw(t *testing.T) {
	out, err := DecodeRaw(message())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"1: 150\n", `2: "hello"`, "3 {\n  1: 7\n  2: \"nested\"\n}\n", "# double 2.5", "# float 1.5", "6: <3 bytes> ff0010",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if _, err := DecodeRaw([]byte("{\"json\": true}")); err == nil {
		t.Fatal("JSON decoded as protobuf")
	}
}

func TestDecodeGRPC(t *testing.T) {
	msg := message()
	frame := func(b []byte, compressed byte) []byte {
		out := []byte{compressed}
		out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
		return append(out, b...)
	}
	body := append(frame(msg, 0), frame([]byte{1, 2, 3}, 1)...)
	out, err := DecodeGRPC(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# message 1") || !strings.Contains(out, `2: "hello"`) || !strings.Contains(out, "# message 2 (3 bytes)\n# compressed") {
		t.Fatalf("grpc:\n%s", out)
	}
	if _, err := DecodeGRPC(body[:7]); err == nil {
		t.Fatal("truncated frame accepted")
	}
	if p, g := Is("application/grpc+proto"); !p || !g {
		t.Fatal("grpc content type")
	}
	if p, g := Is("application/x-protobuf"); !p || g {
		t.Fatal("protobuf content type")
	}
}

func TestPackedVarints(t *testing.T) {
	out, err := DecodeRaw([]byte{0x0a, 0x04, 0x01, 0x02, 0x03, 0x96})
	if err != nil || strings.Contains(out, "packed") {
		t.Fatalf("bytes ending inside a varint shown as packed: %q %v", out, err)
	}
	out, err = DecodeRaw([]byte{0x0a, 0x05, 0x01, 0x02, 0x03, 0x96, 0x01})
	if err != nil || !strings.Contains(out, "# packed [1, 2, 3, 150]") {
		t.Fatalf("%q %v", out, err)
	}
}
