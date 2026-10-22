package proxy

import (
	"context"
	"io"
	"time"
)

type rateWriter struct {
	ctx   context.Context
	w     io.Writer
	flush func()
	rate  float64
	start time.Time
	sent  int64
}

func (r *rateWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := min(len(p), max(int(r.rate/10), 256))
		n, err := r.w.Write(p[:chunk])
		written += n
		r.sent += int64(n)
		if err != nil {
			return written, err
		}
		p = p[chunk:]
		if r.flush != nil {
			r.flush()
		}
		if err := waitFor(r.ctx, r.start, r.sent, r.rate); err != nil {
			return written, err
		}
	}
	return written, nil
}

type rateReader struct {
	ctx   context.Context
	r     io.Reader
	rate  float64
	start time.Time
	read  int64
}

func (r *rateReader) Read(p []byte) (int, error) {
	if len(p) > max(int(r.rate/10), 256) {
		p = p[:max(int(r.rate/10), 256)]
	}
	n, err := r.r.Read(p)
	r.read += int64(n)
	if werr := waitFor(r.ctx, r.start, r.read, r.rate); werr != nil {
		return n, werr
	}
	return n, err
}

func waitFor(ctx context.Context, start time.Time, n int64, rate float64) error {
	due := start.Add(time.Duration(float64(n) / rate * float64(time.Second)))
	d := time.Until(due)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
