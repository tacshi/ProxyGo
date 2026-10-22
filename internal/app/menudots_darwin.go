//go:build darwin

package app

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ebitengine/purego/objc"
	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/locales"
)

type menuDots struct {
	once   sync.Once
	block  objc.Block
	mu     sync.Mutex
	colors map[string]ui.Color
	images map[string]objc.ID
}

func (a *App) setMenuDots() {
	d := &a.dots
	d.mu.Lock()
	defer d.mu.Unlock()
	d.colors = map[string]ui.Color{}
	for _, name := range highlightColors {
		d.colors[colorName(name)] = a.pal.swatch(name)
	}
	if d.images == nil {
		d.images = map[string]objc.ID{}
	}
}

func (a *App) watchMenuDots() {
	d := &a.dots
	d.once.Do(func() {
		mygo.RunOnMain(func() {
			sel := objc.RegisterName
			d.block = objc.NewBlock(func(_ objc.Block, note objc.ID) {
				d.decorate(note.Send(sel("object")), false)
			})
			center := objc.ID(objc.GetClass("NSNotificationCenter")).Send(sel("defaultCenter"))
			center.Send(sel("addObserverForName:object:queue:usingBlock:"), nsString("NSMenuDidBeginTrackingNotification"), objc.ID(0), objc.ID(0), d.block)
		})
	})
}

func (d *menuDots) decorate(menu objc.ID, highlight bool) {
	if menu == 0 {
		return
	}
	sel := objc.RegisterName
	n := objc.Send[int](menu, sel("numberOfItems"))
	for i := range n {
		item := menu.Send(sel("itemAtIndex:"), i)
		name := goString(item.Send(sel("title")))
		if highlight {
			if img := d.dot(name); img != 0 {
				item.Send(sel("setImage:"), img)
			}
		}
		if sub := item.Send(sel("submenu")); sub != 0 {
			d.decorate(sub, name == locales.Highlight())
		}
	}
}

func (d *menuDots) dot(name string) objc.ID {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.colors[name]
	if !ok {
		return 0
	}
	key := fmt.Sprintf("%02x%02x%02x", c.R, c.G, c.B)
	if img, ok := d.images[key]; ok {
		return img
	}
	pdf := dotPDF(c)
	sel := objc.RegisterName
	data := objc.ID(objc.GetClass("NSData")).Send(sel("dataWithBytes:length:"), pdf, uint64(len(pdf)))
	img := objc.ID(objc.GetClass("NSImage")).Send(sel("alloc")).Send(sel("initWithData:"), data)
	d.images[key] = img
	return img
}

func dotPDF(c ui.Color) []byte {
	const k = 2.7614
	content := fmt.Sprintf("%.3f %.3f %.3f rg\n6 11 m\n%.4f 11 11 %.4f 11 6 c\n11 %.4f %.4f 1 6 1 c\n%.4f 1 1 %.4f 1 6 c\n1 %.4f %.4f 11 6 11 c\nf\n",
		float64(c.R)/255, float64(c.G)/255, float64(c.B)/255,
		6+k, 6+k, 6-k, 6+k, 6-k, 6-k, 6+k, 6-k)
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 12 12] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
	}
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return []byte(b.String())
}

func nsString(s string) objc.ID {
	return objc.ID(objc.GetClass("NSString")).Send(objc.RegisterName("stringWithUTF8String:"), s)
}

func goString(s objc.ID) string {
	if s == 0 {
		return ""
	}
	return objc.Send[string](s, objc.RegisterName("UTF8String"))
}
