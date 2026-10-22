//go:build darwin

package privileged

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"

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
	getsockopt      func(fd, level, name int32, val *auditToken, size *uint32) int32
	csops           func(pid int32, ops uint32, buf []byte, size uintptr) int32
	csopsAuditToken func(pid int32, ops uint32, buf []byte, size uintptr, token *auditToken) int32
	procPidpath     func(pid int32, buf []byte, size uint32) int32
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
	if csops(int32(os.Getpid()), csOpsCDHash, hash, cdhashLen) != 0 {
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
		size := uint32(binary.Size(tok))
		ok = getsockopt(int32(fd), unix.SOL_LOCAL, unix.LOCAL_PEERTOKEN, &tok, &size) == 0
	}); err != nil {
		return peer{}, err
	}
	if !ok {
		return peer{}, errors.New("no peer credentials")
	}
	pid := int32(tok[5])
	status := make([]byte, 4)
	if csopsAuditToken(pid, csOpsStatus, status, uintptr(len(status)), &tok) != 0 || binary.NativeEndian.Uint32(status)&csValid == 0 {
		return peer{}, errors.New("the peer's code signature is not valid")
	}
	hash := make([]byte, cdhashLen)
	if csopsAuditToken(pid, csOpsCDHash, hash, cdhashLen, &tok) != 0 {
		return peer{}, errors.New("the peer has no code directory hash")
	}
	buf := make([]byte, 4096)
	n := procPidpath(pid, buf, uint32(len(buf)))
	if n <= 0 {
		return peer{}, errors.New("no path for the peer")
	}
	return peer{uid: int(tok[1]), pid: int(pid), cdhash: hash, path: string(buf[:n])}, nil
}

func processAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}
