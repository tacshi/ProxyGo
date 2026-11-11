package app

import (
	"bytes"
	"image/color"
	"image/png"
	"testing"
	"time"

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

func TestFlowContextMenuShowsDots(t *testing.T) {
	a, _ := testApp(t)
	for _, f := range fixtures() {
		a.store.Upsert(f)
	}
	a.setMenuDots()
	tt := ui.NewTester(func(c *ui.Context) {
		c.SetMenuPresentation(ui.PopoverMenus)
		a.view(c)
	}, 1440, 900)
	tt.Frame()
	if err := tt.RightClick("https://api.example.com/v1/users?page=2&q=go"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	r, ok := tt.Find("Highlight")
	if !ok {
		t.Fatalf("the menu shows no Highlight item: %v", tt.Menu())
	}
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Advance(time.Second)
	tt.Frame()
	img := tt.Image()
	for _, name := range highlightColors {
		item, ok := tt.Find(colorName(name))
		if !ok {
			t.Fatalf("the Highlight menu shows no %s: %v", colorName(name), tt.Texts())
		}
		want := a.pal.swatch(name)
		found := false
		y := int(item.Y + item.H/2)
		for x := int(item.X); x < int(item.X+item.W) && !found; x++ {
			got := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			found = near(got.R, want.R) && near(got.G, want.G) && near(got.B, want.B)
		}
		if !found {
			t.Errorf("no %s dot beside %q", name, colorName(name))
		}
	}
}

func near(a, b uint8) bool { return max(a, b)-min(a, b) <= 6 }
