//go:build !darwin && !linux

package control

import (
	"net"
	"os"
)

func peerUID(net.Conn) (int, error) { return os.Geteuid(), nil }
