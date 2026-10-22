//go:build darwin

package clientinfo

import (
	"bytes"
	"sync"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

func executablePath(pid int) string {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(b) < 5 {
		return ""
	}
	path, _, _ := bytes.Cut(b[4:], []byte{0})
	return string(path)
}

var procPidpath = sync.OnceValue(func() func(pid int32, buf []byte, size uint32) int32 {
	var fn func(pid int32, buf []byte, size uint32) int32
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil
	}
	purego.RegisterLibFunc(&fn, lib, "proc_pidpath")
	return fn
})

func processPath(pid int) string {
	fn := procPidpath()
	if fn == nil {
		return ""
	}
	buf := make([]byte, 4096)
	n := fn(int32(pid), buf, uint32(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}
