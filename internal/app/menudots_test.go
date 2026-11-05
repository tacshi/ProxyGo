package app

import (
	"bytes"
	"image/color"
	"image/png"
	"testing"

	ui "github.com/egoist/mygo/proxygoui"
)

func TestDotPNG(t *testing.T) {
	img, err := png.Decode(bytes.NewReader(dotPNG(ui.Hex("#E0A800"))))
	if err != nil {
		t.Fatal(err)
	}
	if b := img.Bounds(); b.Dx() != 32 || b.Dy() != 32 {
		t.Fatalf("a dot of %v, want 32×32 for a 16-point menu icon", b)
	}
	if got := color.NRGBAModel.Convert(img.At(16, 16)).(color.NRGBA); got != (color.NRGBA{0xE0, 0xA8, 0x00, 0xFF}) {
		t.Errorf("the middle is %v", got)
	}
	for _, p := range [][2]int{{0, 0}, {31, 0}, {0, 31}, {31, 31}, {16, 3}} {
		if _, _, _, a := img.At(p[0], p[1]).RGBA(); a != 0 {
			t.Errorf("(%d, %d) is not clear", p[0], p[1])
		}
	}
}

func TestMenuDotsFollowTheme(t *testing.T) {
	a, _ := testApp(t)
	a.pal = lightPalette
	a.setMenuDots()
	a.highlightItems()
	light := a.dots.png["yellow"]
	if a.dots.items["yellow"].Icon == nil || light == nil {
		t.Fatal("the Highlight items show no dots")
	}
	a.pal = darkPalette
	a.setMenuDots()
	if bytes.Equal(a.dots.png["yellow"], light) {
		t.Error("the dots keep the light theme's yellow in the dark")
	}
	if a.dots.items["yellow"].Icon != a.dots.icons["yellow"] {
		t.Error("the menu's items keep their old dots")
	}
}
