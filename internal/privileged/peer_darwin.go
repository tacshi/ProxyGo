//go:build darwin

package privileged

import (
	"errors"
	"net"
	"os"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

const (
	csOpsStatus = 0
	csOpsCDHash = 5
	csValid     = 0x1
	cdhashLen   = 20
)

type auditToken [8]uint32

var (
	getsockopt      func(fd, level, name int32, val unsafe.Pointer, size *uint32) int32
	csops           func(pid int32, ops uint32, buf unsafe.Pointer, size uintptr) int32
	csopsAuditToken func(pid int32, ops uint32, buf unsafe.Pointer, size uintptr, token *auditToken) int32
	procPidpath     func(pid int32, buf unsafe.Pointer, size uint32) int32
)

var loadLib = sync.OnceValue(func() error {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return err
	}
	purego.RegisterLibFunc(&getsockopt, lib, "getsockopt")
	purego.RegisterLibFunc(&csops, lib, "csops")
	purego.RegisterLibFunc(&csopsAuditToken, lib, "csops_audittoken")
	purego.RegisterLibFunc(&procPidpath, lib, "proc_pidpath")
	return nil
})

func ownCDHash() ([]byte, error) {
	if err := loadLib(); err != nil {
		return nil, err
	}
	hash := make([]byte, cdhashLen)
	if csops(int32(os.Getpid()), csOpsCDHash, unsafe.Pointer(&hash[0]), cdhashLen) != 0 { // #nosec G103 -- passes a buffer for the system call to fill.
		return nil, errors.New("this copy of ProxyGo is not code signed")
	}
	return hash, nil
}

func peerOf(c *net.UnixConn) (peer, error) {
	if err := loadLib(); err != nil {
		return peer{}, err
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return peer{}, err
	}
	var tok auditToken
	ok := false
	if err := raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(tok))
		ok = getsockopt(int32(fd), unix.SOL_LOCAL, unix.LOCAL_PEERTOKEN, unsafe.Pointer(&tok), &size) == 0 // #nosec G103 -- passes a buffer for the system call to fill.
	}); err != nil {
		return peer{}, err
	}
	if !ok {
		return peer{}, errors.New("no peer credentials")
	}
	pid := int32(tok[5])
	var status uint32
	if csopsAuditToken(pid, csOpsStatus, unsafe.Pointer(&status), unsafe.Sizeof(status), &tok) != 0 || status&csValid == 0 { // #nosec G103 -- passes a buffer for the system call to fill.
		return peer{}, errors.New("the peer's code signature is not valid")
	}
	hash := make([]byte, cdhashLen)
	if csopsAuditToken(pid, csOpsCDHash, unsafe.Pointer(&hash[0]), cdhashLen, &tok) != 0 { // #nosec G103 -- passes a buffer for the system call to fill.
		return peer{}, errors.New("the peer has no code directory hash")
	}
	buf := make([]byte, 4096)
	n := procPidpath(pid, unsafe.Pointer(&buf[0]), uint32(len(buf))) // #nosec G103 -- passes a buffer for the system call to fill.
	if n <= 0 {
		return peer{}, errors.New("no path for the peer")
	}
	return peer{uid: int(tok[1]), cdhash: hash, path: string(buf[:n])}, nil
}
