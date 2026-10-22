//go:build darwin

package certs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

const (
	errSecItemNotFound   = -25300
	cfStringEncodingUTF8 = 0x08000100
)

type secAPI struct {
	itemAdd          func(attrs, result uintptr) int32
	itemUpdate       func(query, attrs uintptr) int32
	itemCopyMatching func(query uintptr, result *uintptr) int32
	itemDelete       func(query uintptr) int32
	errorMessage     func(status int32, reserved uintptr) uintptr

	stringCreate func(alloc uintptr, s string, encoding uint32) uintptr
	stringGet    func(s uintptr, buf []byte, size int, encoding uint32) bool
	dataCreate   func(alloc uintptr, b []byte, n int) uintptr
	dataLength   func(data uintptr) int
	dataBytes    func(data uintptr) uintptr
	dictCreate   func(alloc uintptr, keys, values []uintptr, n int, keyCallBacks, valueCallBacks uintptr) uintptr
	release      func(ref uintptr)
	memmove      func(dst []byte, src, n uintptr)

	keyCallBacks, valueCallBacks uintptr
	yes, class, genericPassword  uintptr
	service, account, valueData  uintptr
	returnData, matchLimit, one  uintptr
}

var loadSecAPI = sync.OnceValues(func() (*secAPI, error) {
	open := func(path string) (uintptr, error) {
		return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	}
	cf, err := open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
	if err != nil {
		return nil, err
	}
	sec, err := open("/System/Library/Frameworks/Security.framework/Security")
	if err != nil {
		return nil, err
	}
	libc, err := open("/usr/lib/libSystem.B.dylib")
	if err != nil {
		return nil, err
	}
	s := &secAPI{}
	purego.RegisterLibFunc(&s.itemAdd, sec, "SecItemAdd")
	purego.RegisterLibFunc(&s.itemUpdate, sec, "SecItemUpdate")
	purego.RegisterLibFunc(&s.itemCopyMatching, sec, "SecItemCopyMatching")
	purego.RegisterLibFunc(&s.itemDelete, sec, "SecItemDelete")
	purego.RegisterLibFunc(&s.errorMessage, sec, "SecCopyErrorMessageString")
	purego.RegisterLibFunc(&s.stringCreate, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&s.stringGet, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&s.dataCreate, cf, "CFDataCreate")
	purego.RegisterLibFunc(&s.dataLength, cf, "CFDataGetLength")
	purego.RegisterLibFunc(&s.dataBytes, cf, "CFDataGetBytePtr")
	purego.RegisterLibFunc(&s.dictCreate, cf, "CFDictionaryCreate")
	purego.RegisterLibFunc(&s.release, cf, "CFRelease")
	purego.RegisterLibFunc(&s.memmove, libc, "memmove")
	if s.keyCallBacks, err = purego.Dlsym(cf, "kCFTypeDictionaryKeyCallBacks"); err != nil {
		return nil, err
	}
	if s.valueCallBacks, err = purego.Dlsym(cf, "kCFTypeDictionaryValueCallBacks"); err != nil {
		return nil, err
	}
	for _, c := range []struct {
		lib  uintptr
		name string
		to   *uintptr
	}{
		{cf, "kCFBooleanTrue", &s.yes},
		{sec, "kSecClass", &s.class},
		{sec, "kSecClassGenericPassword", &s.genericPassword},
		{sec, "kSecAttrService", &s.service},
		{sec, "kSecAttrAccount", &s.account},
		{sec, "kSecValueData", &s.valueData},
		{sec, "kSecReturnData", &s.returnData},
		{sec, "kSecMatchLimit", &s.matchLimit},
		{sec, "kSecMatchLimitOne", &s.one},
	} {
		addr, err := purego.Dlsym(c.lib, c.name)
		if err != nil {
			return nil, err
		}
		*c.to = uintptr(binary.NativeEndian.Uint64(s.read(addr, 8)))
	}
	return s, nil
})

func (s *secAPI) read(addr uintptr, n int) []byte {
	b := make([]byte, n)
	if n > 0 {
		s.memmove(b, addr, uintptr(n))
	}
	return b
}

func (s *secAPI) dict(pairs ...uintptr) uintptr {
	var keys, values []uintptr
	for i := 0; i+1 < len(pairs); i += 2 {
		keys, values = append(keys, pairs[i]), append(values, pairs[i+1])
	}
	return s.dictCreate(0, keys, values, len(keys), s.keyCallBacks, s.valueCallBacks)
}

func (s *secAPI) query(ref string, extra ...uintptr) uintptr {
	service := s.stringCreate(0, keychainService, cfStringEncodingUTF8)
	defer s.release(service)
	account := s.stringCreate(0, ref, cfStringEncodingUTF8)
	defer s.release(account)
	return s.dict(append([]uintptr{s.class, s.genericPassword, s.service, service, s.account, account}, extra...)...)
}

func (s *secAPI) err(status int32) error {
	msg := s.errorMessage(status, 0)
	if msg == 0 {
		return fmt.Errorf("keychain: error %d", status)
	}
	defer s.release(msg)
	buf := make([]byte, 1024)
	if !s.stringGet(msg, buf, len(buf), cfStringEncodingUTF8) {
		return fmt.Errorf("keychain: error %d", status)
	}
	text, _, _ := bytes.Cut(buf, []byte{0})
	return fmt.Errorf("keychain: %s", text)
}

type keychain struct{}

func (keychain) Set(ref, secret string) error {
	s, err := loadSecAPI()
	if err != nil {
		return err
	}
	data := s.dataCreate(0, []byte(secret), len(secret))
	defer s.release(data)
	q := s.query(ref)
	defer s.release(q)
	update := s.dict(s.valueData, data)
	defer s.release(update)
	status := s.itemUpdate(q, update)
	if status == errSecItemNotFound {
		attrs := s.query(ref, s.valueData, data)
		defer s.release(attrs)
		status = s.itemAdd(attrs, 0)
	}
	if status != 0 {
		return s.err(status)
	}
	return nil
}

func (keychain) Get(ref string) (string, error) {
	s, err := loadSecAPI()
	if err != nil {
		return "", err
	}
	q := s.query(ref, s.returnData, s.yes, s.matchLimit, s.one)
	defer s.release(q)
	var data uintptr
	if status := s.itemCopyMatching(q, &data); status != 0 {
		if status == errSecItemNotFound {
			return "", fmt.Errorf("keychain: no password for %s", ref)
		}
		return "", s.err(status)
	}
	defer s.release(data)
	return string(s.read(s.dataBytes(data), s.dataLength(data))), nil
}

func (keychain) Delete(ref string) error {
	s, err := loadSecAPI()
	if err != nil {
		return err
	}
	q := s.query(ref)
	defer s.release(q)
	s.itemDelete(q)
	return nil
}
