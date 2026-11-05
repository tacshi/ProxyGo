package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
)

var ErrForeignSocket = errors.New("the socket belongs to another user")

func DialSocket(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	uid, err := peerUID(c)
	if err == nil && !trustedPeer(uid, os.Geteuid()) {
		err = fmt.Errorf("%s: %w", path, ErrForeignSocket)
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func trustedPeer(peer, self int) bool { return self == 0 || peer == self }
