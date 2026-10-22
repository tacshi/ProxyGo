package app

import (
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{0, "–"},
		{750 * time.Microsecond, "0.8 ms"},
		{127 * time.Millisecond, "127 ms"},
		{2340 * time.Millisecond, "2.34 s"},
		{time.Minute, "1 min"},
		{2*time.Minute + 1400*time.Millisecond, "2 min 1 s"},
		{59*time.Minute + 59600*time.Millisecond, "1 h"},
		{time.Hour + 5*time.Minute + 20*time.Second, "1 h 5 min"},
	} {
		if got := formatDuration(c.d); got != c.want {
			t.Errorf("formatDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
