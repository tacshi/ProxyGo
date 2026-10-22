//go:build darwin

package app

import (
	"os"
	"sync"

	"github.com/ebitengine/purego"
)

type rusageInfo struct {
	UUID                        [16]byte
	UserTime, SystemTime        uint64
	PkgIdleWkups, Interrupts    uint64
	Pageins, WiredSize          uint64
	ResidentSize, PhysFootprint uint64
	StartAbstime, ExitAbstime   uint64
}

var procPidRusage = sync.OnceValue(func() func(pid, flavor int32, info *rusageInfo) int32 {
	var fn func(pid, flavor int32, info *rusageInfo) int32
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil
	}
	purego.RegisterLibFunc(&fn, lib, "proc_pid_rusage")
	return fn
})

func residentMemory() int64 {
	fn := procPidRusage()
	var info rusageInfo
	if fn == nil || fn(int32(os.Getpid()), 0, &info) != 0 {
		return 0
	}
	return int64(info.ResidentSize)
}
