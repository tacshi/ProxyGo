package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/i18n"

	"proxygo/locales"
)

func TestSinceText(t *testing.T) {
	t.Cleanup(func() { i18n.SetLocaleFunc(nil) })
	for locale, want := range map[string][4]string{
		"en":      {"just now", "1 minute ago", "3 hours ago", "yesterday"},
		"zh-Hans": {"刚刚", "1分钟前", "3小时前", "昨天"},
		"ja":      {"たった今", "1 分前", "3 時間前", "昨日"},
		"ko":      {"방금", "1분 전", "3시간 전", "어제"},
	} {
		i18n.SetLocaleFunc(func() string { return locale })
		for i, d := range []time.Duration{10 * time.Second, 90 * time.Second, 3*time.Hour + time.Minute, 30 * time.Hour} {
			if got := sinceText(time.Now().Add(-d)); got != want[i] {
				t.Errorf("%s: %v ago reads %q, want %q", locale, d, got, want[i])
			}
		}
		if got, want := locales.StartedAgo(sinceSeconds(5*time.Second)), map[string]string{"en": "Started 5 seconds ago", "zh-Hans": "5秒钟前开始", "ja": "5 秒前に開始", "ko": "5초 전에 시작"}[locale]; got != want {
			t.Errorf("%s: %q, want %q", locale, got, want)
		}
	}
}

func TestScriptCompletionsParse(t *testing.T) {
	got := scriptCompletions()
	if len(got) != 7 {
		t.Fatalf("%d completions, want all 7 to parse", len(got))
	}
	for _, c := range got {
		if c.Snippet == nil || c.Label == "" {
			t.Errorf("%+v offers no snippet", c)
		}
	}
}
