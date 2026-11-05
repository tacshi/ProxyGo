package app

import (
	"bytes"
	"image"
	"image/color"
	"image/png"

	"github.com/egoist/mygo"
	ui "github.com/egoist/mygo/proxygoui"
)

type menuDots struct {
	png   map[string][]byte
	icons map[string]*mygo.MenuIcon
	items map[string]*mygo.MenuItem
}

func (a *App) setMenuDots() {
	d := &a.dots
	d.png, d.icons = map[string][]byte{}, map[string]*mygo.MenuIcon{}
	for _, name := range highlightColors {
		b := dotPNG(a.pal.swatch(name))
		d.png[name] = b
		d.icons[name], _ = mygo.NewMenuIcon(b, false)
	}
	for name, it := range d.items {
		it.SetIcon(d.icons[name])
	}
}

func dotPNG(c ui.Color) []byte {
	const size, radius, samples = 32, 10, 4
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := range size {
		for x := range size {
			n := 0
			for sy := range samples {
				for sx := range samples {
					dx := float64(x) + (float64(sx)+0.5)/samples - size/2
					dy := float64(y) + (float64(sy)+0.5)/samples - size/2
					if dx*dx+dy*dy <= radius*radius {
						n++
					}
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{c.R, c.G, c.B, uint8(n * 255 / (samples * samples))})
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}
