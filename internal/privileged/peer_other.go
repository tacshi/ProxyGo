//go:build !darwin

package privileged

import (
	"errors"
	"net"
)

var errUnsupported = errors.New("ProxyGo's helper runs only on macOS")

func ownCDHash() ([]byte, error) { return nil, errUnsupported }

func peerOf(*net.UnixConn) (peer, error) { return peer{}, errUnsupported }
