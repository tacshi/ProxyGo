//go:build darwin

package app

import (
	"github.com/ebitengine/purego/objc"
	"github.com/egoist/mygo"
)

func setBundleIcon(bundle string, icns []byte) bool {
	ok := false
	mygo.RunOnMain(func() {
		sel := objc.RegisterName
		var img objc.ID
		if icns != nil {
			data := objc.ID(objc.GetClass("NSData")).Send(sel("dataWithBytes:length:"), icns, uint64(len(icns)))
			img = objc.ID(objc.GetClass("NSImage")).Send(sel("alloc")).Send(sel("initWithData:"), data)
			if img == 0 {
				return
			}
			defer img.Send(sel("release"))
		}
		path := objc.ID(objc.GetClass("NSString")).Send(sel("stringWithUTF8String:"), bundle)
		ws := objc.ID(objc.GetClass("NSWorkspace")).Send(sel("sharedWorkspace"))
		ok = objc.Send[bool](ws, sel("setIcon:forFile:options:"), img, path, uint64(0))
		ws.Send(sel("noteFileSystemChanged:"), path)
	})
	return ok
}
