//go:build darwin

package clientinfo

import (
	"bytes"
	"sync"

	"github.com/ebitengine/purego"
)

const cfStringEncodingUTF8 = 0x08000100

type cfAPI struct {
	urlCreate        func(alloc uintptr, path string, n int, isDir bool) uintptr
	bundleCreate     func(alloc, url uintptr) uintptr
	bundleIdentifier func(bundle uintptr) uintptr
	stringGet        func(s uintptr, buf []byte, size int, encoding uint32) bool
	release          func(ref uintptr)
}

var loadCF = sync.OnceValues(func() (*cfAPI, error) {
	lib, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	cf := &cfAPI{}
	purego.RegisterLibFunc(&cf.urlCreate, lib, "CFURLCreateFromFileSystemRepresentation")
	purego.RegisterLibFunc(&cf.bundleCreate, lib, "CFBundleCreate")
	purego.RegisterLibFunc(&cf.bundleIdentifier, lib, "CFBundleGetIdentifier")
	purego.RegisterLibFunc(&cf.stringGet, lib, "CFStringGetCString")
	purego.RegisterLibFunc(&cf.release, lib, "CFRelease")
	return cf, nil
})

func bundleIdentifier(bundle string) string {
	cf, err := loadCF()
	if err != nil {
		return ""
	}
	url := cf.urlCreate(0, bundle, len(bundle), true)
	if url == 0 {
		return ""
	}
	defer cf.release(url)
	b := cf.bundleCreate(0, url)
	if b == 0 {
		return ""
	}
	defer cf.release(b)
	id := cf.bundleIdentifier(b)
	if id == 0 {
		return ""
	}
	buf := make([]byte, 1024)
	if !cf.stringGet(id, buf, len(buf), cfStringEncodingUTF8) {
		return ""
	}
	s, _, _ := bytes.Cut(buf, []byte{0})
	return string(s)
}
