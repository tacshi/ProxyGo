//go:build darwin

package clientinfo

import (
	"bytes"

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
