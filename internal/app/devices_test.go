package app

import (
	"testing"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
)

func TestRemoteDevices(t *testing.T) {
	a, _ := testApp(t)
	phone := func(id, host string) *flow.Flow {
		f := flow.New(id)
		f.Request = &flow.Request{Method: flow.Method{Name: "GET"}, Host: host, Scheme: "http", FullPath: "http://" + host + "/"}
		f.Client = flow.Client{Name: "192.168.1.7", PID: -1}
		return f
	}
	for _, f := range append(fixtures(), phone("R1", "dns.weixin.qq.com"), phone("R2", "sgshort.wechat.com")) {
		a.store.Upsert(f)
	}
	a.refreshFlows()
	tree := a.sourceTree()
	if tree.devices["192.168.1.7"] != 2 || tree.apps["192.168.1.7"] != 0 {
		t.Fatalf("devices %v apps %v", tree.devices, tree.apps)
	}
	if remoteIP(fixtures()[0]) != "" || remoteIP(&flow.Flow{Client: flow.Client{Name: "127.0.0.1", PID: -1}}) != "" {
		t.Fatal("this Mac's flows are not a device's")
	}
	tt := ui.NewTester(a.view, 1440, 900)
	tt.Frame()
	if !tt.HasText("Remote Devices (1)") || !tt.HasText("192.168.1.7") {
		t.Fatalf("no device in the sidebar: %v", tt.Texts())
	}
	a.setDeviceName("192.168.1.7", "  Rocky's iPhone ")
	tt.Frame()
	if a.set.DeviceNames["192.168.1.7"] != "Rocky's iPhone" || !tt.HasText("Rocky's iPhone") {
		t.Fatalf("nickname %q", a.set.DeviceNames)
	}
	if got := a.clientLabel(phone("R3", "x.com")); got != "Rocky's iPhone" {
		t.Fatalf("label %q", got)
	}
	a.setDeviceName("192.168.1.7", "")
	if _, ok := a.set.DeviceNames["192.168.1.7"]; ok {
		t.Fatal("an empty nickname gives the address back")
	}
	if a.askDevice("192.168.1.7") {
		t.Fatal("asked without a window")
	}
}
