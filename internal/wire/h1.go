package wire

import (
	"bytes"
	"strconv"
	"strings"
)

const maxHead = 1 << 20

const (
	h1Head = iota
	h1Body
	h1ChunkSize
	h1ChunkData
	h1ChunkEnd
	h1Trailer
	h1Done
)

type h1 struct {
	rec     *recorder
	request bool
	server  bool

	state   int
	line    []byte
	started bool
	size    int
	h       head
	length  int64
	chunked bool
	upgrade bool
	remain  int64
}

func (p *h1) feed(b []byte) {
	for len(b) > 0 && p.state != h1Done {
		if p.state == h1Body || p.state == h1ChunkData {
			n := min(int64(len(b)), p.remain)
			b, p.remain = b[n:], p.remain-n
			switch {
			case p.remain > 0:
			case p.state == h1Body:
				p.state = h1Head
			default:
				p.state = h1ChunkEnd
			}
			continue
		}
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			p.line = append(p.line, b...)
			if len(p.line) > maxHead {
				p.state = h1Done
			}
			return
		}
		p.line = append(p.line, b[:i]...)
		b = b[i+1:]
		line := strings.TrimSuffix(string(p.line), "\r")
		p.line = p.line[:0]
		p.onLine(line)
	}
}

func (p *h1) onLine(line string) {
	switch p.state {
	case h1Head:
		p.headLine(line)
	case h1ChunkSize:
		size, _, _ := strings.Cut(line, ";")
		n, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
		switch {
		case err != nil || n < 0:
			p.state = h1Done
		case n == 0:
			p.state = h1Trailer
		default:
			p.state, p.remain = h1ChunkData, n
		}
	case h1ChunkEnd:
		p.state = h1ChunkSize
		if line != "" {
			p.state = h1Done
		}
	case h1Trailer:
		if line == "" {
			p.state = h1Head
		}
	}
}

func (p *h1) headLine(line string) {
	p.size += len(line) + 2
	if p.size > maxHead {
		p.state = h1Done
		return
	}
	if !p.started {
		if line == "" {
			return
		}
		p.started, p.h, p.length, p.chunked, p.upgrade = true, head{}, -1, false, false
		if !p.startLine(line) {
			p.state = h1Done
		}
		return
	}
	if line == "" {
		p.started, p.size = false, 0
		p.endHead()
		return
	}
	if line[0] == ' ' || line[0] == '\t' {
		return
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	name = strings.TrimRight(name, " \t")
	value = strings.TrimSpace(value)
	p.h.fields = append(p.h.fields, Field{Name: name, Value: value})
	switch strings.ToLower(name) {
	case "content-length":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
			p.length = n
		}
	case "transfer-encoding":
		p.chunked = strings.HasSuffix(strings.ToLower(value), "chunked")
	case "upgrade":
		p.upgrade = true
	}
}

func (p *h1) startLine(line string) bool {
	parts := strings.SplitN(line, " ", 3)
	if p.request {
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
			return false
		}
		p.h.method, p.h.target = parts[0], parts[1]
		return true
	}
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return false
	}
	code, err := strconv.Atoi(parts[1])
	p.h.status = code
	return err == nil
}

func (p *h1) endHead() {
	h := p.h
	if p.request {
		if p.server {
			p.rec.addRequest(h)
		} else {
			p.rec.wrote(h)
		}
		switch {
		case h.method == "CONNECT" || p.upgrade:
			p.state = h1Done
		default:
			p.body(p.length)
		}
		return
	}
	if h.status < 200 {
		if h.status == 101 {
			p.state = h1Done
		}
		return
	}
	method := p.rec.method()
	p.rec.addResponse(h)
	switch {
	case method == "HEAD" || h.status == 204 || h.status == 304:
	case method == "CONNECT":
		p.state = h1Done
	case p.length < 0 && !p.chunked:
		p.state = h1Done
	default:
		p.body(p.length)
	}
}

func (p *h1) body(length int64) {
	switch {
	case p.chunked:
		p.state = h1ChunkSize
	case length > 0:
		p.state, p.remain = h1Body, length
	}
}
