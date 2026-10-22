package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

const udpIdle = 5 * time.Minute

func (s *Server) serveUDPAssociate(c net.Conn, br *bufio.Reader, wantHost string, wantPort int) {
	defer func() { _ = c.Close() }()
	local, _ := c.LocalAddr().(*net.TCPAddr)
	remote, _ := c.RemoteAddr().(*net.TCPAddr)
	if local == nil || remote == nil {
		_ = socksReply(c, socksRefused)
		return
	}
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		_ = socksReply(c, socksRefused)
		return
	}
	defer func() { _ = front.Close() }()
	back, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = socksReply(c, socksRefused)
		return
	}
	defer func() { _ = back.Close() }()
	if err := socksReplyAddr(c, front.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(io.Discard, br)
		_ = front.Close()
		_ = back.Close()
	}()
	var client *net.UDPAddr
	if ip := net.ParseIP(wantHost); ip != nil && !ip.IsUnspecified() && wantPort != 0 {
		client = &net.UDPAddr{IP: ip, Port: wantPort}
	}
	clients := make(chan *net.UDPAddr, 1)
	go func() {
		to := <-clients
		if to == nil {
			return
		}
		buf := make([]byte, 64<<10)
		for {
			_ = back.SetReadDeadline(time.Now().Add(udpIdle))
			n, from, err := back.ReadFromUDP(buf)
			if err != nil {
				_ = c.Close()
				return
			}
			_, _ = front.WriteToUDP(socksUDPHeader(from, buf[:n]), to)
		}
	}()
	defer close(clients)
	buf := make([]byte, 64<<10)
	for {
		_ = front.SetReadDeadline(time.Now().Add(udpIdle))
		n, from, err := front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !from.IP.Equal(remote.IP) || client != nil && from.Port != client.Port && client.Port != 0 {
			continue
		}
		if client == nil || client.Port == 0 {
			client = from
		}
		select {
		case clients <- client:
		default:
		}
		host, port, payload, err := splitSOCKSUDP(buf[:n])
		if err != nil {
			continue
		}
		if blocked, _, _ := s.rules().BlockedHost(host, port); blocked {
			continue
		}
		if rule := s.rules().DNSFor(host); rule != nil {
			host = rule.IP
			if rule.Port > 0 {
				port = rule.Port
			}
		}
		dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		_, _ = back.WriteToUDP(payload, dst)
	}
}

func socksReplyAddr(w io.Writer, a *net.UDPAddr) error {
	b := []byte{5, socksOK, 0}
	b = appendSOCKSAddr(b, a.IP, a.Port)
	_, err := w.Write(b)
	return err
}

func appendSOCKSAddr(b []byte, ip net.IP, port int) []byte {
	if v4 := ip.To4(); v4 != nil {
		b = append(append(b, 1), v4...)
	} else {
		b = append(append(b, 4), ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

func socksUDPHeader(from *net.UDPAddr, payload []byte) []byte {
	b := appendSOCKSAddr([]byte{0, 0, 0}, from.IP, from.Port)
	return append(b, payload...)
}

var errFragment = errors.New("fragmented SOCKS datagrams are not supported")

func splitSOCKSUDP(b []byte) (string, int, []byte, error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	if b[2] != 0 {
		return "", 0, nil, errFragment
	}
	var host string
	off := 0
	switch b[3] {
	case 1:
		if len(b) < 10 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host, off = net.IP(b[4:8]).String(), 8
	case 4:
		if len(b) < 22 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host, off = net.IP(b[4:20]).String(), 20
	case 3:
		if len(b) < 5 || len(b) < 5+int(b[4])+2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host, off = string(b[5:5+int(b[4])]), 5+int(b[4])
	default:
		return "", 0, nil, errors.New("bad SOCKS address type")
	}
	return host, int(binary.BigEndian.Uint16(b[off : off+2])), b[off+2:], nil
}
