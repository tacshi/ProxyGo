package app

import (
	"testing"

	"proxygo/internal/flow"
	"proxygo/internal/proxy"
	"proxygo/internal/rules"
)

func TestBreakpointTemplates(t *testing.T) {
	a, _ := testApp(t)
	pause := func(response bool) *pending {
		f := flow.New("T1")
		f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, FullPath: "https://api.dev/v1/items?x=1"}
		m := proxy.Message{Method: "GET", URL: "https://api.dev/v1/items?x=1", StatusCode: 200, Body: []byte("real")}
		pd := &pending{Pause: &proxy.Pause{ID: "p", Flow: f, Message: m, Response: response}, done: make(chan decision, 1)}
		pd.edit = newMessageEditor(m, response)
		a.pauses = []*pending{pd}
		return pd
	}
	unavailable := &rules.BreakpointTemplate{Name: "503", Response: true, Raw: "HTTP/1.1 503 Service Unavailable\nContent-Type: application/json\nContent-Length: 1\n\n{\"down\":true}"}

	pd := pause(false)
	a.answerWithTemplate(pd, unavailable)
	d := <-pd.done
	if len(a.pauses) != 0 || !d.ok || !d.msg.Respond || d.msg.StatusCode != 503 || string(d.msg.Body) != `{"down":true}` || d.msg.Header.Get("Content-Length") != "13" {
		t.Fatalf("answer %+v", d.msg)
	}

	pd = pause(true)
	a.answerWithTemplate(pd, unavailable)
	d = <-pd.done
	if !d.ok || d.msg.Respond || d.msg.StatusCode != 503 || d.msg.URL != "https://api.dev/v1/items?x=1" {
		t.Fatalf("replace %+v", d.msg)
	}

	pd = pause(false)
	a.applyTemplate(pd, &rules.BreakpointTemplate{Raw: "POST /v2/items HTTP/1.1\nX-T: 1\n\nbody"})
	m := pd.edit.message()
	if m.Method != "POST" || m.URL != "https://api.dev/v2/items" || string(m.Body) != "body" || m.Header.Get("X-T") != "1" {
		t.Fatalf("applied %+v", m)
	}

	pd = pause(false)
	a.decide(pd.ID, proxy.Message{Drop: true}, false)
	if d := <-pd.done; !d.msg.Drop || len(a.pauses) != 0 {
		t.Fatalf("drop %+v", d)
	}
}
