package protobuf

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	_ "google.golang.org/protobuf/types/known/anypb"
	_ "google.golang.org/protobuf/types/known/durationpb"
	_ "google.golang.org/protobuf/types/known/emptypb"
	_ "google.golang.org/protobuf/types/known/fieldmaskpb"
	_ "google.golang.org/protobuf/types/known/structpb"
	_ "google.golang.org/protobuf/types/known/timestamppb"
	_ "google.golang.org/protobuf/types/known/wrapperspb"
)

type Schema struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Source   string    `json:"source"`
	Files    []string  `json:"files"`
	Imported time.Time `json:"imported"`
}

type Schemas struct {
	dir string

	mu      sync.RWMutex
	schemas []Schema
	sets    map[string]*descriptorpb.FileDescriptorSet
	files   *protoregistry.Files
	types   *dynamicpb.Types
	err     error
	version uint64
}

func OpenSchemas(dir string) *Schemas {
	s := &Schemas{dir: dir, sets: map[string]*descriptorpb.FileDescriptorSet{}}
	if b, err := os.ReadFile(s.index()); err == nil {
		_ = json.Unmarshal(b, &s.schemas)
	}
	kept := s.schemas[:0]
	for _, sc := range s.schemas {
		b, err := os.ReadFile(s.setPath(sc.ID))
		if err != nil {
			continue
		}
		var set descriptorpb.FileDescriptorSet
		if proto.Unmarshal(b, &set) != nil {
			continue
		}
		s.sets[sc.ID] = &set
		kept = append(kept, sc)
	}
	s.schemas = kept
	s.link()
	return s
}

func (s *Schemas) index() string            { return filepath.Join(s.dir, "schemas.json") }
func (s *Schemas) setPath(id string) string { return filepath.Join(s.dir, id+".binpb") }

func (s *Schemas) Import(path string) (Schema, error) {
	var set *descriptorpb.FileDescriptorSet
	var err error
	if strings.EqualFold(filepath.Ext(path), ".proto") {
		set, err = compileProto(path)
	} else {
		set, err = readSet(path)
	}
	if err != nil {
		return Schema{}, err
	}
	if err := complete(set); err != nil {
		return Schema{}, err
	}
	if _, err := protodesc.NewFiles(set); err != nil {
		return Schema{}, fmt.Errorf("the schema does not link: %w", err)
	}
	sc := Schema{ID: newID(), Name: filepath.Base(path), Source: path, Imported: time.Now()}
	for _, f := range set.File {
		sc.Files = append(sc.Files, f.GetName())
	}
	b, err := proto.Marshal(set)
	if err != nil {
		return Schema{}, err
	}
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return Schema{}, err
	}
	if err := os.WriteFile(s.setPath(sc.ID), b, 0o600); err != nil {
		return Schema{}, err
	}
	s.mu.Lock()
	s.schemas = slices.DeleteFunc(s.schemas, func(old Schema) bool {
		if old.Source == sc.Source {
			delete(s.sets, old.ID)
			_ = os.Remove(s.setPath(old.ID))
			return true
		}
		return false
	})
	s.schemas = append(s.schemas, sc)
	s.sets[sc.ID] = set
	s.link()
	err = s.saveLocked()
	s.mu.Unlock()
	return sc, err
}

func (s *Schemas) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schemas = slices.DeleteFunc(s.schemas, func(sc Schema) bool { return sc.ID == id })
	delete(s.sets, id)
	_ = os.Remove(s.setPath(id))
	s.link()
	return s.saveLocked()
}

func (s *Schemas) saveLocked() error {
	b, err := json.MarshalIndent(s.schemas, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.index(), b, 0o600)
}

func (s *Schemas) link() {
	s.version++
	byName := map[string]*descriptorpb.FileDescriptorProto{}
	var order []string
	for _, sc := range s.schemas {
		for _, f := range s.sets[sc.ID].GetFile() {
			if _, ok := byName[f.GetName()]; !ok {
				order = append(order, f.GetName())
			}
			byName[f.GetName()] = f
		}
	}
	all := &descriptorpb.FileDescriptorSet{}
	for _, name := range order {
		all.File = append(all.File, byName[name])
	}
	s.files, s.types, s.err = nil, nil, nil
	if len(all.File) == 0 {
		return
	}
	files, err := protodesc.NewFiles(all)
	if err != nil {
		s.err = err
		return
	}
	s.files, s.types = files, dynamicpb.NewTypes(files)
}

func (s *Schemas) List() []Schema {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.schemas)
}

func (s *Schemas) Version() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *Schemas) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}

func (s *Schemas) Messages() []string {
	s.mu.RLock()
	files := s.files
	s.mu.RUnlock()
	if files == nil {
		return nil
	}
	var out []string
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := range ms.Len() {
			m := ms.Get(i)
			if !m.IsMapEntry() {
				out = append(out, string(m.FullName()))
			}
			walk(m.Messages())
		}
	}
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		walk(fd.Messages())
		return true
	})
	slices.Sort(out)
	return out
}

func (s *Schemas) MethodTypes(path string) (in, out string, ok bool) {
	s.mu.RLock()
	files := s.files
	s.mu.RUnlock()
	if files == nil {
		return "", "", false
	}
	path, _, _ = strings.Cut(path, "?")
	svc, method, found := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !found || svc == "" || method == "" || strings.Contains(method, "/") {
		return "", "", false
	}
	d, err := files.FindDescriptorByName(protoreflect.FullName(svc))
	if err != nil {
		return "", "", false
	}
	sd, isSvc := d.(protoreflect.ServiceDescriptor)
	if !isSvc {
		return "", "", false
	}
	md := sd.Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return "", "", false
	}
	return string(md.Input().FullName()), string(md.Output().FullName()), true
}

const (
	PayloadAuto      = ""
	PayloadSingle    = "single"
	PayloadDelimited = "delimited"
	PayloadGRPC      = "grpc"
)

var ErrNoSchema = errors.New("import a .proto or descriptor set first")

func (s *Schemas) Decode(typeName string, b []byte) (string, error) {
	s.mu.RLock()
	files, types := s.files, s.types
	s.mu.RUnlock()
	if files == nil {
		return "", ErrNoSchema
	}
	d, err := files.FindDescriptorByName(protoreflect.FullName(typeName))
	if err != nil {
		return "", fmt.Errorf("no message type %s in the schemas", typeName)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		return "", fmt.Errorf("%s is not a message type", typeName)
	}
	msg := dynamicpb.NewMessage(md)
	if err := (proto.UnmarshalOptions{Resolver: types}).Unmarshal(b, msg); err != nil {
		return "", fmt.Errorf("not a %s: %w", typeName, err)
	}
	out, err := protojson.MarshalOptions{UseProtoNames: true, Resolver: types}.Marshal(msg)
	if err != nil {
		return "", err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, out, "", "  "); err != nil {
		return string(out), nil
	}
	return pretty.String(), nil
}

func (s *Schemas) DecodeBody(typeName, payload string, body []byte, grpc bool, encoding string) (string, error) {
	if payload == PayloadAuto {
		payload = PayloadSingle
		if grpc {
			payload = PayloadGRPC
		}
	}
	var msgs [][]byte
	switch payload {
	case PayloadSingle:
		msgs = [][]byte{body}
	case PayloadDelimited:
		for len(body) > 0 {
			n, k := binary.Uvarint(body)
			if k <= 0 || n > uint64(len(body)-k) {
				return "", errors.New("a length-delimited message is cut off")
			}
			msgs = append(msgs, body[k:k+int(n)])
			body = body[k+int(n):]
		}
	case PayloadGRPC:
		frames, err := GRPCFrames(body)
		if err != nil {
			return "", err
		}
		for _, f := range frames {
			if f.Compressed {
				if !strings.EqualFold(encoding, "gzip") {
					return "", fmt.Errorf("a gRPC message is compressed with %s", cmp.Or(encoding, "an unknown encoding"))
				}
				zr, err := gzip.NewReader(bytes.NewReader(f.Data))
				if err != nil {
					return "", err
				}
				data, err := io.ReadAll(io.LimitReader(zr, 64<<20))
				if err != nil {
					return "", err
				}
				f.Data = data
			}
			msgs = append(msgs, f.Data)
		}
	default:
		return "", fmt.Errorf("unknown payload %q", payload)
	}
	if len(msgs) == 1 {
		return s.Decode(typeName, msgs[0])
	}
	var out strings.Builder
	for i, m := range msgs {
		text, err := s.Decode(typeName, m)
		if err != nil {
			return "", fmt.Errorf("message %d: %w", i+1, err)
		}
		fmt.Fprintf(&out, "// message %d of %d\n%s\n", i+1, len(msgs), text)
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

type Frame struct {
	Compressed bool
	Data       []byte
}

func GRPCFrames(b []byte) ([]Frame, error) {
	var out []Frame
	for len(b) > 0 {
		if len(b) < 5 {
			return nil, errors.New("truncated gRPC frame")
		}
		size := int(binary.BigEndian.Uint32(b[1:5]))
		if size > len(b)-5 {
			return nil, fmt.Errorf("gRPC frame of %d bytes, %d left", size, len(b)-5)
		}
		out = append(out, Frame{Compressed: b[0]&1 == 1, Data: b[5 : 5+size]})
		b = b[5+size:]
	}
	return out, nil
}

func readSet(path string) (*descriptorpb.FileDescriptorSet, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- a descriptor set the user imports, or ProxyGo's copy of one.
	if err != nil {
		return nil, err
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(b, &set); err != nil || len(set.File) == 0 {
		return nil, fmt.Errorf("%s is not a descriptor set (protoc -o): %v", filepath.Base(path), cmp.Or[error](err, errors.New("no files")))
	}
	return &set, nil
}

func compileProto(path string) (*descriptorpb.FileDescriptorSet, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var first error
	root := filepath.Dir(abs)
	for range 8 {
		rel, _ := filepath.Rel(root, abs)
		c := protocompile.Compiler{Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{ImportPaths: []string{root}})}
		files, err := c.Compile(context.Background(), filepath.ToSlash(rel))
		if err == nil {
			set := &descriptorpb.FileDescriptorSet{}
			seen := map[string]bool{}
			var add func(protoreflect.FileDescriptor)
			add = func(fd protoreflect.FileDescriptor) {
				if seen[fd.Path()] {
					return
				}
				seen[fd.Path()] = true
				for i := range fd.Imports().Len() {
					add(fd.Imports().Get(i).FileDescriptor)
				}
				set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
			}
			for _, fd := range files {
				add(fd)
			}
			return set, nil
		}
		if first == nil {
			first = err
		}
		if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "no such file") {
			break
		}
		up := filepath.Dir(root)
		if up == root {
			break
		}
		root = up
	}
	return nil, first
}

func complete(set *descriptorpb.FileDescriptorSet) error {
	have := map[string]bool{}
	for _, f := range set.File {
		have[f.GetName()] = true
	}
	var missing []string
	for _, f := range set.File {
		for _, dep := range f.GetDependency() {
			if have[dep] {
				continue
			}
			fd, err := protoregistry.GlobalFiles.FindFileByPath(dep)
			if err != nil {
				missing = append(missing, dep)
				continue
			}
			have[dep] = true
			set.File = append([]*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(fd)}, set.File...)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the schema imports files it does not include: %s (export it with protoc --include_imports)", strings.Join(missing, ", "))
	}
	return nil
}

func newID() string { return strings.ToLower(rand.Text()[:12]) }
