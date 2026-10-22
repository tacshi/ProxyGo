package protobuf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const userProto = `syntax = "proto3";
package demo.v1;
import "demo/v1/common.proto";
import "google/protobuf/timestamp.proto";

message GetUserRequest { string id = 1; }
message User {
  string name = 1;
  int32 age = 2;
  Status status = 3;
  google.protobuf.Timestamp created = 4;
  repeated string tags = 5;
}
service Users { rpc GetUser(GetUserRequest) returns (User); }
`

const commonProto = `syntax = "proto3";
package demo.v1;
enum Status { UNKNOWN = 0; ACTIVE = 1; }
`

func writeProtos(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "demo", "v1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "user.proto"), []byte(userProto), 0o644)
	os.WriteFile(filepath.Join(dir, "common.proto"), []byte(commonProto), 0o644)
	return filepath.Join(dir, "user.proto")
}

func userMessage(t *testing.T, s *Schemas) []byte {
	t.Helper()
	d, err := s.files.FindDescriptorByName("demo.v1.User")
	if err != nil {
		t.Fatal(err)
	}
	md := d.(protoreflect.MessageDescriptor)
	m := dynamicpb.NewMessage(md)
	m.Set(md.Fields().ByName("name"), protoreflect.ValueOfString("Ada"))
	m.Set(md.Fields().ByName("age"), protoreflect.ValueOfInt32(36))
	m.Set(md.Fields().ByName("status"), protoreflect.ValueOfEnum(1))
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSchemasFromProto(t *testing.T) {
	dir := t.TempDir()
	s := OpenSchemas(dir)
	if _, err := s.Decode("demo.v1.User", nil); err != ErrNoSchema {
		t.Fatalf("no schema yet: %v", err)
	}
	sc, err := s.Import(writeProtos(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(sc.Files, ","), "demo/v1/common.proto") {
		t.Errorf("files %v", sc.Files)
	}
	if got := strings.Join(s.Messages(), ","); !strings.Contains(got, "demo.v1.User") || !strings.Contains(got, "google.protobuf.Timestamp") {
		t.Errorf("messages %s", got)
	}
	in, out, ok := s.MethodTypes("/demo.v1.Users/GetUser")
	if !ok || in != "demo.v1.GetUserRequest" || out != "demo.v1.User" {
		t.Errorf("method types %q %q %v", in, out, ok)
	}
	if _, _, ok := s.MethodTypes("/demo.v1.Users/Nope"); ok {
		t.Error("an unknown method")
	}

	msg := userMessage(t, s)
	text, err := s.Decode("demo.v1.User", msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name": "Ada"`, `"age": 36`, `"status": "ACTIVE"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in %s", want, text)
		}
	}

	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	zw.Write(msg)
	zw.Close()
	frame := func(flag byte, b []byte) []byte {
		return append(binary.BigEndian.AppendUint32([]byte{flag}, uint32(len(b))), b...)
	}
	body := append(frame(0, msg), frame(1, zipped.Bytes())...)
	text, err = s.DecodeBody("demo.v1.User", PayloadAuto, body, true, "gzip")
	if err != nil || strings.Count(text, `"name": "Ada"`) != 2 || !strings.Contains(text, "message 2 of 2") {
		t.Errorf("gRPC: %v\n%s", err, text)
	}
	if _, err := s.DecodeBody("demo.v1.User", PayloadAuto, body, true, ""); err == nil {
		t.Error("a compressed frame without its encoding")
	}
	delimited := append(binary.AppendUvarint(nil, uint64(len(msg))), msg...)
	delimited = append(delimited, delimited...)
	if text, err := s.DecodeBody("demo.v1.User", PayloadDelimited, delimited, false, ""); err != nil || strings.Count(text, "Ada") != 2 {
		t.Errorf("delimited: %v %s", err, text)
	}
	if _, err := s.Decode("demo.v1.User", []byte{0xff, 0xff}); err == nil {
		t.Error("garbage decoded")
	}

	s2 := OpenSchemas(dir)
	if len(s2.List()) != 1 || len(s2.Messages()) == 0 {
		t.Fatalf("reopened: %+v", s2.List())
	}
	if err := s2.Remove(sc.ID); err != nil || len(s2.Messages()) != 0 || len(OpenSchemas(dir).List()) != 0 {
		t.Errorf("remove: %v", err)
	}
}

func TestSchemasFromDescriptorSet(t *testing.T) {
	src := OpenSchemas(t.TempDir())
	if _, err := src.Import(writeProtos(t)); err != nil {
		t.Fatal(err)
	}
	var set descriptorpb.FileDescriptorSet
	for _, f := range src.sets[src.schemas[0].ID].File {
		if !strings.HasPrefix(f.GetName(), "google/") {
			set.File = append(set.File, f)
		}
	}
	b, _ := proto.Marshal(&set)
	path := filepath.Join(t.TempDir(), "api.desc")
	os.WriteFile(path, b, 0o644)
	s := OpenSchemas(t.TempDir())
	if _, err := s.Import(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decode("demo.v1.User", userMessage(t, s)); err != nil {
		t.Error(err)
	}
	var partial descriptorpb.FileDescriptorSet
	for _, f := range set.File {
		if f.GetName() == "demo/v1/user.proto" {
			partial.File = append(partial.File, f)
		}
	}
	b, _ = proto.Marshal(&partial)
	os.WriteFile(path, b, 0o644)
	if _, err := OpenSchemas(t.TempDir()).Import(path); err == nil || !strings.Contains(err.Error(), "--include_imports") {
		t.Errorf("a partial set: %v", err)
	}
	os.WriteFile(path, []byte("not a set"), 0o644)
	if _, err := OpenSchemas(t.TempDir()).Import(path); err == nil {
		t.Error("garbage imported")
	}
}
