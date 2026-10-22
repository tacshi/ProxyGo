package proxy

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"proxygo/internal/rules"
)

type socksListener struct {
	mu   sync.Mutex
	ln   net.Listener
	at   int
	bind string
}

func (l *socksListener) port() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return 0
	}
	return l.at
}

func (l *socksListener) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		_ = l.ln.Close()
		l.ln, l.at = nil, 0
	}
}

func (l *socksListener) reconcile(s *Server, cfg rules.Socks) {
	l.mu.Lock()
	defer l.mu.Unlock()
	want := 0
	if cfg.Enabled {
		want = cmp.Or(cfg.Port, rules.DefaultSocksPort)
	}
	host, network := s.bindHost()
	bind := host + "|" + network
	if l.ln != nil && l.at == want && l.bind == bind {
		return
	}
	if l.ln != nil {
		_ = l.ln.Close()
		l.ln, l.at = nil, 0
	}
	if want == 0 {
		return
	}
	ln, err := net.Listen(network, net.JoinHostPort(host, strconv.Itoa(want)))
	if err != nil {
		s.logf("socks :%d: %v", want, err)
		return
	}
	l.ln, l.at, l.bind = ln, want, bind
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveSocks(c)
		}
	}()
}

const (
	socksOK              = 0x00
	socksNotAllowed      = 0x02
	socksHostUnreachable = 0x04
	socksRefused         = 0x05
	socksBadCommand      = 0x07
	socksBadAddress      = 0x08
)

func (s *Server) serveSocks(c net.Conn) {
	if !s.allowed(c.RemoteAddr().String()) {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	cmd, host, port, err := socksHandshake(br, c)
	if err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	if cmd == socksUDPAssociate {
		if s.blockedApp(s.clientFor(c.RemoteAddr().String())) != nil {
			_ = socksReply(c, socksNotAllowed)
			_ = c.Close()
			return
		}
		s.serveUDPAssociate(c, br, host, port)
		return
	}
	t := &target{host: host, port: port, client: s.clientFor(c.RemoteAddr().String()), remote: c.RemoteAddr().String(), proto: [2]int{1, 1}, socks: true}
	if blocked, _, _ := s.rules().BlockedHost(host, port); blocked || s.blockedApp(t.client) != nil {
		_ = socksReply(c, socksNotAllowed)
		_ = c.Close()
		return
	}
	reply := func(err error) error {
		if err != nil {
			code := byte(socksHostUnreachable)
			if errors.Is(err, syscall.ECONNREFUSED) {
				code = socksRefused
			}
			return socksReply(c, code)
		}
		return socksReply(c, socksOK)
	}
	s.tunnel(&bufferedConn{Conn: c, r: br}, t, reply)
}

const (
	socksConnect      = 1
	socksUDPAssociate = 3
)

func socksHandshake(br *bufio.Reader, w io.Writer) (byte, string, int, error) {
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return 0, "", 0, err
	}
	if head[0] != 5 {
		return 0, "", 0, errors.New("not SOCKS5")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return 0, "", 0, err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = w.Write([]byte{5, 0xff})
		return 0, "", 0, errors.New("SOCKS client needs authentication")
	}
	if _, err := w.Write([]byte{5, 0}); err != nil {
		return 0, "", 0, err
	}
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return 0, "", 0, err
	}
	if req[0] != 5 {
		return 0, "", 0, errors.New("bad SOCKS request")
	}
	if req[1] != socksConnect && req[1] != socksUDPAssociate {
		_ = socksReply(w, socksBadCommand)
		return 0, "", 0, errors.New("only CONNECT and UDP ASSOCIATE are supported")
	}
	var host string
	switch req[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(ip[:]).String()
	case 3:
		n, err := br.ReadByte()
		if err != nil {
			return 0, "", 0, err
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(br, name); err != nil {
			return 0, "", 0, err
		}
		host = string(name)
	case 4:
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(ip[:]).String()
	default:
		_ = socksReply(w, socksBadAddress)
		return 0, "", 0, errors.New("bad SOCKS address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return 0, "", 0, err
	}
	return req[1], host, int(binary.BigEndian.Uint16(p[:])), nil
}

func socksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
