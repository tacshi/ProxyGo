package script

import (
	"sync"
	"testing"
	"time"

	"proxygo/internal/flow"
	"proxygo/internal/rules"
)

func TestScriptsRunConcurrently(t *testing.T) {
	e := New()
	r := rule(`function onRequest(c, u, r) {
		sharedState.started = (sharedState.started || 0) + 1;
		sleep(300);
		r.comment = "done";
		return r;
	}`)
	start := time.Now()
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			req := request()
			if _, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), req); err != nil || req.Comment != "done" {
				t.Errorf("comment %q err %v", req.Comment, err)
			}
		})
	}
	wg.Wait()
	if d := time.Since(start); d >= 500*time.Millisecond {
		t.Fatalf("two 300 ms scripts took %v", d)
	}
	if comment, _ := runScript(t, e, `function onRequest(c, u, r) { r.comment = String(sharedState.started); return r; }`); comment != "2" {
		t.Fatalf("started %q", comment)
	}
}

func TestSharedStateUnderLoad(t *testing.T) {
	e := New()
	r := rule(`function onRequest(c, u, r) {
		sharedState.n = (sharedState.n || 0) + 1;
		sharedState.obj = sharedState.obj || { count: 0, seen: [] };
		sleep(1);
		sharedState.obj.count++;
		sharedState.obj.seen.push(sharedState.n);
		return r;
	}`)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 25 {
				if _, err := e.RunRequest([]*rules.ScriptRule{r}, flow.New("F"), request()); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	comment, _ := runScript(t, e, `function onRequest(c, u, r) {
		r.comment = JSON.stringify([sharedState.n, sharedState.obj.count, sharedState.obj.seen.length]);
		return r;
	}`)
	if comment != "[200,200,200]" {
		t.Fatalf("counters %s", comment)
	}
}

func TestSharedStateValues(t *testing.T) {
	e := New()
	runScript(t, e, `function onRequest(c, u, r) {
		sharedState.a = { b: [1, "x"] };
		sharedState.alias = sharedState.a;
		sharedState.gone = true;
		const loop = { name: "loop" };
		loop.self = loop;
		sharedState.loop = loop;
		return r;
	}`)
	comment, logs := runScript(t, e, `function onRequest(c, u, r) {
		sharedState.alias.b.push(true);
		delete sharedState.gone;
		delete sharedState.loop;
		console.log(sharedState);
		r.comment = [Object.keys(sharedState).join(), "gone" in sharedState, sharedState.a.b.length, sharedState.a.b[2]].join(" ");
		return r;
	}`)
	if comment != "a,alias false 3 true" {
		t.Errorf("comment %q", comment)
	}
	if len(logs) != 1 || logs[0].Text != `{"a":{"b":[1,"x",true]},"alias":{"b":[1,"x",true]}}` {
		t.Errorf("logs %+v", logs)
	}
}

func TestSharedStateWebSocket(t *testing.T) {
	e := New()
	r := rule(`
	const kept = sharedState;
	function onWebsocket(context, url, request, response, message) {
		kept.ws = (kept.ws || 0) + 1;
		sleep(1);
		kept.ws += 0;
	}`)
	f := flow.New("WS")
	req := &Request{Method: "GET", Scheme: "https", Host: "chat.dev", Port: 443, Path: "/socket"}
	s := e.NewWebSocketSession([]*rules.ScriptRule{r}, f, req, &Response{StatusCode: 101})
	for range 5 {
		s.Add(flow.WebSocketMessage{From: "client", Type: "text", Data: "hi"})
	}
	bump := rule(`function onRequest(c, u, r) { sharedState.http = (sharedState.http || 0) + 1; return r; }`)
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if _, err := e.RunRequest([]*rules.ScriptRule{bump}, flow.New("F"), request()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	s.Close()
	s.Wait()
	if comment, _ := runScript(t, e, `function onRequest(c, u, r) { r.comment = sharedState.ws + "," + sharedState.http; return r; }`); comment != "5,5" {
		t.Fatalf("counters %q", comment)
	}
}
