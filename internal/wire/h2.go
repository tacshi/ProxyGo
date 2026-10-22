package wire

import (
	"encoding/binary"
	"strconv"

	"golang.org/x/net/http2/hpack"
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	frameHeaders      = 0x1
	framePushPromise  = 0x5
	frameContinuation = 0x9

	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
)

const (
	h2Requests = iota
	h2Sent
	h2Responses
)

type h2 struct {
	rec     *recorder
	reads   int
	preface int
	dec     *hpack.Decoder
	dead    bool

	hdr     [9]byte
	hn      int
	typ     byte
	flags   byte
	stream  uint32
	remain  int
	payload []byte
	block   []byte
	push    bool
}

func newH2(rec *recorder, reads int) *h2 {
	p := &h2{rec: rec, reads: reads, dec: hpack.NewDecoder(4096, nil)}
	p.dec.SetAllowedMaxDynamicTableSize(1 << 24)
	if reads != h2Responses {
		p.preface = len(clientPreface)
	}
	return p
}

func (p *h2) feed(b []byte) {
	for len(b) > 0 && !p.dead {
		if p.preface > 0 {
			at := len(clientPreface) - p.preface
			n := min(p.preface, len(b))
			if string(b[:n]) != clientPreface[at:at+n] {
				p.dead = true
				return
			}
			b, p.preface = b[n:], p.preface-n
			continue
		}
		if p.hn < len(p.hdr) {
			n := copy(p.hdr[p.hn:], b)
			b, p.hn = b[n:], p.hn+n
			if p.hn < len(p.hdr) {
				return
			}
			p.remain = int(p.hdr[0])<<16 | int(p.hdr[1])<<8 | int(p.hdr[2])
			p.typ, p.flags = p.hdr[3], p.hdr[4]
			p.stream = binary.BigEndian.Uint32(p.hdr[5:]) & 0x7fffffff
			p.payload = p.payload[:0]
			if p.remain == 0 {
				p.endFrame()
			}
			continue
		}
		n := min(p.remain, len(b))
		if p.typ == frameHeaders || p.typ == framePushPromise || p.typ == frameContinuation {
			p.payload = append(p.payload, b[:n]...)
		}
		b, p.remain = b[n:], p.remain-n
		if p.remain == 0 {
			p.endFrame()
		}
	}
}

func (p *h2) endFrame() {
	p.hn = 0
	payload := p.payload
	switch p.typ {
	case frameHeaders, framePushPromise:
		if p.flags&flagPadded != 0 {
			if len(payload) < 1 || int(payload[0]) > len(payload)-1 {
				p.dead = true
				return
			}
			payload = payload[1 : len(payload)-int(payload[0])]
		}
		skip := 0
		if p.typ == framePushPromise {
			skip = 4
		} else if p.flags&flagPriority != 0 {
			skip = 5
		}
		if len(payload) < skip {
			p.dead = true
			return
		}
		p.block = append(p.block[:0], payload[skip:]...)
		p.push = p.typ == framePushPromise
	case frameContinuation:
		p.block = append(p.block, payload...)
	default:
		return
	}
	if len(p.block) > maxHead {
		p.dead = true
		return
	}
	if p.flags&flagEndHeaders != 0 {
		p.decode()
	}
}

func (p *h2) decode() {
	fields, err := p.dec.DecodeFull(p.block)
	if err != nil {
		p.dead = true
		return
	}
	if p.push {
		return
	}
	h := head{stream: p.stream}
	for _, f := range fields {
		h.fields = append(h.fields, Field{Name: f.Name, Value: f.Value})
		switch f.Name {
		case ":method":
			h.method = f.Value
		case ":path":
			h.target = f.Value
		case ":status":
			h.status, _ = strconv.Atoi(f.Value)
		}
	}
	switch {
	case p.reads == h2Requests && h.method != "":
		p.rec.addRequest(h)
	case p.reads == h2Sent && h.method != "":
		p.rec.wrote(h)
	case p.reads == h2Responses && h.status >= 200:
		p.rec.addResponse(h)
	}
}
