//go:build darwin

package app

import (
	"strings"

	"github.com/ebitengine/purego/objc"
	"github.com/egoist/mygo"
)

func nsURL(path string) objc.ID {
	if strings.Contains(path, "://") {
		return objc.ID(objc.GetClass("NSURL")).Send(objc.RegisterName("URLWithString:"), nsString(path))
	}
	return objc.ID(objc.GetClass("NSURL")).Send(objc.RegisterName("fileURLWithPath:"), nsString(path))
}

func revealInFinder(path string) {
	mygo.RunOnMain(func() {
		urls := objc.ID(objc.GetClass("NSArray")).Send(objc.RegisterName("arrayWithObject:"), nsURL(path))
		workspace().Send(objc.RegisterName("activateFileViewerSelectingURLs:"), urls)
	})
}

func openPath(path string) {
	mygo.RunOnMain(func() {
		if url := nsURL(path); url != 0 {
			workspace().Send(objc.RegisterName("openURL:"), url)
		}
	})
}

func workspace() objc.ID {
	return objc.ID(objc.GetClass("NSWorkspace")).Send(objc.RegisterName("sharedWorkspace"))
}
