package app

import (
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/flow"
	"proxygo/internal/settings"
)

type palette struct {
	dark bool

	bg, sidebar, surface, hover, border, hairline ui.Color
	text, text2, muted, faint                     ui.Color
	accent, onAccent, onAccentMuted               ui.Color
	link                                          ui.Color

	pill, pillText ui.Color

	green, greenSoft   ui.Color
	yellow, yellowSoft ui.Color
	red, redSoft       ui.Color
	blue, blueSoft     ui.Color
	purple, purpleSoft ui.Color
	gray, graySoft     ui.Color
	orange, orangeSoft ui.Color
}

var lightPalette = palette{
	bg: ui.Hex("#FFFFFF"), sidebar: ui.Hex("#F2F2F4"), surface: ui.Hex("#F6F6F8"), hover: ui.Hex("#EBEBEE"),
	border: ui.Hex("#DEDEE2"), hairline: ui.Hex("#EBEBED"),
	text: ui.Hex("#1D1D1F"), text2: ui.Hex("#3A3A3F"), muted: ui.Hex("#6E6E75"), faint: ui.Hex("#A2A2A8"),
	accent: ui.Hex("#2F7CF6"), onAccent: ui.Hex("#FFFFFF"), onAccentMuted: ui.RGBA(255, 255, 255, 0.78),
	link: ui.Hex("#2565D0"),
	pill: ui.Hex("#E6E6E9"), pillText: ui.Hex("#4A4A50"),
	green: ui.Hex("#248A3D"), greenSoft: ui.Hex("#DDF2E0"),
	yellow: ui.Hex("#9A6A00"), yellowSoft: ui.Hex("#FBF0CC"),
	red: ui.Hex("#C9342B"), redSoft: ui.Hex("#FCE1DE"),
	blue: ui.Hex("#2565D0"), blueSoft: ui.Hex("#DCE9FD"),
	purple: ui.Hex("#8944AB"), purpleSoft: ui.Hex("#EFE1F6"),
	gray: ui.Hex("#6E6E75"), graySoft: ui.Hex("#EBEBEE"),
	orange: ui.Hex("#C25E00"), orangeSoft: ui.Hex("#FCE8D6"),
}

var darkPalette = palette{
	dark: true,
	bg:   ui.Hex("#1E1E21"), sidebar: ui.Hex("#26262A"), surface: ui.Hex("#2A2A2E"), hover: ui.Hex("#323237"),
	border: ui.Hex("#3C3C42"), hairline: ui.Hex("#303035"),
	text: ui.Hex("#EDEDF0"), text2: ui.Hex("#C9C9CF"), muted: ui.Hex("#9A9AA2"), faint: ui.Hex("#6B6B73"),
	accent: ui.Hex("#3D8BFF"), onAccent: ui.Hex("#FFFFFF"), onAccentMuted: ui.RGBA(255, 255, 255, 0.78),
	link: ui.Hex("#6AA6FF"),
	pill: ui.Hex("#38383E"), pillText: ui.Hex("#D0D0D6"),
	green: ui.Hex("#4CD26B"), greenSoft: ui.Hex("#1F3A27"),
	yellow: ui.Hex("#F2C744"), yellowSoft: ui.Hex("#3D3418"),
	red: ui.Hex("#FF6B5E"), redSoft: ui.Hex("#45221F"),
	blue: ui.Hex("#6AA6FF"), blueSoft: ui.Hex("#1D2F4D"),
	purple: ui.Hex("#D08CF5"), purpleSoft: ui.Hex("#3A2547"),
	gray: ui.Hex("#9A9AA2"), graySoft: ui.Hex("#323237"),
	orange: ui.Hex("#FF9F45"), orangeSoft: ui.Hex("#45301C"),
}

func (a *App) applyTheme(c *ui.Context) palette {
	system := c.Theme()
	dark := system.Dark
	switch a.set.Appearance {
	case settings.AppearanceDark:
		dark = true
	case settings.AppearanceLight:
		dark = false
	}
	t := *system
	if dark != system.Dark {
		if dark {
			t = *ui.DarkTheme()
		} else {
			t = *ui.LightTheme()
		}
		t.Accent, t.AccentHover, t.AccentPressed = system.Accent, system.AccentHover, system.AccentPressed
	}
	p := lightPalette
	if dark {
		p = darkPalette
	}
	p.accent = t.Accent
	t.Background = p.bg
	t.Surface = p.surface
	t.SurfaceHover = p.hover
	t.Border = p.border
	t.Text = p.text
	t.TextMuted = p.muted
	t.Spacing = 3
	t.FontSize = 12
	t.Radius = 6
	c.SetTheme(&t)
	a.pal = p
	if !a.dotsOn || a.dotsDark != p.dark {
		a.dotsOn, a.dotsDark = true, p.dark
		a.setMenuDots()
	}
	return p
}

const (
	inset        = 12
	windowInset  = 18
	footerHeight = 36
)

var highlightColors = []string{"red", "yellow", "green", "blue", "purple", "gray"}

func (p palette) highlight(name string) ui.Color {
	alpha := float32(0.16)
	if p.dark {
		alpha = 0.24
	}
	switch name {
	case "red":
		return p.red.Alpha(alpha)
	case "yellow":
		return p.yellow.Alpha(alpha + 0.04)
	case "green":
		return p.green.Alpha(alpha)
	case "blue":
		return p.blue.Alpha(alpha)
	case "purple":
		return p.purple.Alpha(alpha)
	case "gray":
		return p.gray.Alpha(alpha)
	}
	return ui.Transparent
}

func (p palette) swatch(name string) ui.Color {
	yellow := p.yellow
	if !p.dark {
		yellow = ui.Hex("#E0A800")
	}
	return map[string]ui.Color{"red": p.red, "yellow": yellow, "green": p.green, "blue": p.blue, "purple": p.purple, "gray": p.gray}[name]
}

func (p palette) methodColors(method string) (ui.Color, ui.Color) {
	switch method {
	case "POST":
		return p.blueSoft, p.blue
	case "PUT":
		return p.orangeSoft, p.orange
	case "PATCH":
		return p.purpleSoft, p.purple
	case "DELETE":
		return p.redSoft, p.red
	}
	return p.pill, p.pillText
}

func (p palette) flowColors(f *flow.Flow) (ui.Color, ui.Color) {
	if f.IsIncomplete() {
		return p.graySoft, p.gray
	}
	return p.statusColors(f.StatusCode(), f.IsActive(), f.IsError())
}

func (p palette) statusColors(code int, active, failed bool) (ui.Color, ui.Color) {
	switch {
	case active:
		return p.yellowSoft, p.yellow
	case failed:
		return p.graySoft, p.gray
	case code >= 500:
		return p.redSoft, p.red
	case code >= 400:
		return p.orangeSoft, p.orange
	case code >= 300:
		return p.blueSoft, p.blue
	case code >= 200:
		return p.greenSoft, p.green
	case code >= 100:
		return p.purpleSoft, p.purple
	}
	return p.graySoft, p.gray
}
