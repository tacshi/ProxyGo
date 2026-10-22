package app

import (
	"fmt"

	ui "github.com/egoist/mygo/proxygoui"
)

var iconSources = map[string]string{ // #nosec G101 -- SVG icon paths, not credentials.
	"blank":        ``,
	"record":       `<circle cx="12" cy="12" r="6.5" fill="currentColor" stroke="none"/>`,
	"compose":      `<path d="M12 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6"/><path d="M17.5 3.5a2.1 2.1 0 0 1 3 3L12 15l-4 1 1-4z"/>`,
	"dockBottom":   `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 13.5h18"/>`,
	"dockRight":    `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M13.5 4v16"/>`,
	"deepSearch":   `<circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5L20 20M8 8.5h5M8 11.5h4"/>`,
	"minus":        `<path d="M6 12h12"/>`,
	"chart":        `<path d="M5 20v-7M11 20V5M17 20v-10M3 20h18"/>`,
	"lockOpen":     `<rect x="4.5" y="10" width="15" height="10.5" rx="2"/><path d="M8 10V7.5a4 4 0 0 1 7.6-1.8"/>`,
	"inspect":      `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7.5 13h9M7.5 16.5h5"/>`,
	"repeat":       `<path d="M17 2.5l3 3-3 3"/><path d="M4 11V9.5a4 4 0 0 1 4-4h12"/><path d="M7 21.5l-3-3 3-3"/><path d="M20 13v1.5a4 4 0 0 1-4 4H4"/>`,
	"bookmarkFill": `<path d="M6 3.5h12v17l-6-4.2-6 4.2v-17z" fill="currentColor"/>`,
	"comment":      `<path d="M4 5h16v11H9.5L4 20V5z"/>`,
	"block":        `<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>`,
	"diff":         `<rect x="3" y="4" width="8" height="16" rx="1.5"/><rect x="13" y="4" width="8" height="16" rx="1.5"/><path d="M5.5 10h3M7 8.5v3M15.5 14h3"/>`,
	"sidebar":      `<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M9 4v16"/>`,
	"pause":        `<rect x="7" y="5" width="3.4" height="14" rx="1"/><rect x="13.6" y="5" width="3.4" height="14" rx="1"/>`,
	"play":         `<path d="M8 5.5v13l11-6.5z"/>`,
	"pencil":       `<path d="M4 20h4l10.5-10.5a2.1 2.1 0 0 0-3-3L5 17v3z"/><path d="M13.5 6.5l4 4"/>`,
	"trash":        `<path d="M4 7h16"/><path d="M9 7V4.8c0-.5.4-.8.8-.8h4.4c.4 0 .8.3.8.8V7"/><path d="M6.5 7l.8 12.2c0 .5.4.8.9.8h7.6c.5 0 .9-.3.9-.8L17.5 7"/><path d="M10 11v5M14 11v5"/>`,
	"search":       `<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/>`,
	"filter":       `<path d="M4 6h16M7 12h10M10 18h4"/>`,
	"columns":      `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M12 4v16"/>`,
	"windows":      `<rect x="3.5" y="6.5" width="12" height="10.5" rx="1.8"/><path d="M8 3.5h11a2 2 0 0 1 2 2V16"/>`,
	"browser":      `<rect x="3" y="4" width="18" height="16" rx="2.4"/><path d="M3 9h18"/><circle cx="6.2" cy="6.5" r=".6" fill="currentColor" stroke="none"/><circle cx="8.4" cy="6.5" r=".6" fill="currentColor" stroke="none"/>`,
	"split":        `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M14.5 4v16"/>`,
	"command":      `<path d="M9 7.5a2.5 2.5 0 1 0-2.5 2.5H9V7.5zM15 7.5A2.5 2.5 0 1 1 17.5 10H15V7.5zM9 16.5A2.5 2.5 0 1 1 6.5 14H9v2.5zM15 16.5a2.5 2.5 0 1 0 2.5-2.5H15v2.5z"/><rect x="9" y="9" width="6" height="6" rx=".8"/>`,
	"person":       `<circle cx="12" cy="8.5" r="3.5"/><path d="M5 20a7 7 0 0 1 14 0"/>`,
	"ellipsis":     `<circle cx="5.5" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="18.5" cy="12" r="1.2" fill="currentColor" stroke="none"/>`,
	"chevronRight": `<path d="M9 5l7 7-7 7"/>`,
	"chevronDown":  `<path d="M5 9l7 7 7-7"/>`,
	"chevronUp":    `<path d="M5 15l7-7 7 7"/>`,
	"globe":        `<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.2 2.4 3.3 5.3 3.3 8.5s-1.1 6.1-3.3 8.5c-2.2-2.4-3.3-5.3-3.3-8.5S9.8 5.9 12 3.5z"/>`,
	"lock":         `<rect x="4.5" y="10" width="15" height="10.5" rx="2"/><path d="M8 10V7.5a4 4 0 0 1 8 0V10"/>`,
	"unlock":       `<rect x="4.5" y="10" width="15" height="10.5" rx="2"/><path d="M8 10V7.5a4 4 0 0 1 7.6-1.8"/>`,
	"device":       `<rect x="6.5" y="2.5" width="11" height="19" rx="2.4"/><path d="M10.5 18.5h3"/>`,
	"appWindow":    `<rect x="3" y="4" width="18" height="16" rx="2.2"/><path d="M3 8.5h18"/><path d="M6.2 6.2h.1M8.7 6.2h.1"/>`,
	"grid":         `<rect x="3.5" y="3.5" width="7" height="7" rx="1.4"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.4"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.4"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.4"/>`,
	"pin":          `<path d="M9 3h6l-1 6 3.5 3.2V15H6.5v-2.8L10 9 9 3z"/><path d="M12 15v6"/>`,
	"bookmark":     `<path d="M6 3.5h12v17l-6-4.2-6 4.2v-17z"/>`,
	"folder":       `<path d="M3.5 7.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V7.5z"/>`,
	"list":         `<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="3.8" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="3.8" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="3.8" cy="18" r="1" fill="currentColor" stroke="none"/>`,
	"xmark":        `<path d="M6 6l12 12M18 6L6 18"/>`,
	"plus":         `<path d="M12 5v14M5 12h14"/>`,
	"gear":         `<circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5v.2h-4v-.2a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3v-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.5V3h4v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.5 1h.1v4h-.1a1.7 1.7 0 0 0-1.5 1z"/>`,
	"shield":       `<path d="M12 3l7 3v5.5c0 4.3-2.9 7.6-7 9.5-4.1-1.9-7-5.2-7-9.5V6l7-3z"/><path d="M9 12l2 2 4-4"/>`,
	"key":          `<circle cx="8" cy="12" r="4"/><path d="M12 12h9M17 12v3M20 12v2.2"/>`,
	"network":      `<rect x="9" y="3" width="6" height="5" rx="1.4"/><rect x="3" y="16" width="6" height="5" rx="1.4"/><rect x="15" y="16" width="6" height="5" rx="1.4"/><path d="M12 8v4M6 16v-4h12v4"/>`,
	"arrowUp":      `<path d="M12 19V5M6 11l6-6 6 6"/>`,
	"arrowDown":    `<path d="M12 5v14M6 13l6 6 6-6"/>`,
	"wifi":         `<path d="M3.5 9.5a13 13 0 0 1 17 0M6.4 13a8.8 8.8 0 0 1 11.2 0M9.4 16.4a4.4 4.4 0 0 1 5.2 0"/><circle cx="12" cy="19.5" r="1" fill="currentColor" stroke="none"/>`,
	"eye":          `<path d="M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>`,
	"copy":         `<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>`,
	"export":       `<path d="M12 15V3M7 8l5-5 5 5"/><path d="M4 14v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5"/>`,
	"code":         `<path d="M8.5 7L3 12l5.5 5M15.5 7L21 12l-5.5 5M13.5 4l-3 16"/>`,
	"wand":         `<path d="M15 4l1 2.2L18 7l-2 1L15 10l-1-2L12 7l2-.8L15 4z"/><path d="M4 20l9-9M6 4l.7 1.4L8 6l-1.3.6L6 8l-.7-1.4L4 6l1.3-.6L6 4z"/>`,
	"bug":          `<rect x="7" y="7" width="10" height="12" rx="5"/><path d="M9 7a3 3 0 0 1 6 0M12 3v4M5 11h2M17 11h2M5 15h2M17 15h2M6 19l1.5-1.5M18 19l-1.5-1.5"/>`,
	"clock":        `<circle cx="12" cy="12" r="8.5"/><path d="M12 7v5.3l3.4 2"/>`,
	"check":        `<path d="M5 12.5l4.5 4.5L19 7"/>`,
	"checkCircle":  `<circle cx="12" cy="12" r="8.5"/><path d="M8 12.2l2.6 2.6L16.4 9"/>`,
	"info":         `<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5M12 7.7v.2"/>`,
	"warning":      `<path d="M12 3.5L21 20H3l9-16.5z"/><path d="M12 9v5M12 17.2v.2"/>`,
	"refresh":      `<path d="M20 11a8 8 0 1 0-2.3 6.4M20 5v6h-6"/>`,
	"sliders":      `<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>`,
	"certificate":  `<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M7 8h10M7 11h6"/><circle cx="16" cy="17" r="3"/><path d="M14.5 19.5L14 23l2-1 2 1-.5-3.5"/>`,
	"map":          `<path d="M9 4L3 6.5v13L9 17l6 2.5 6-2.5v-13L15 7 9 4z"/><path d="M9 4v13M15 7v12.5"/>`,
	"script":       `<path d="M6 3.5h8l4 4v13H6v-17z"/><path d="M14 3.5v4h4"/><path d="M9 12l-1.6 2L9 16M15 12l1.6 2L15 16"/>`,
	"speed":        `<path d="M4.5 18a8.5 8.5 0 1 1 15 0"/><path d="M12 13l4-4"/><circle cx="12" cy="14" r="1.5"/>`,
	"dns":          `<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2 2.3 3 5.1 3 8.5s-1 6.2-3 8.5c-2-2.3-3-5.1-3-8.5s1-6.2 3-8.5z"/>`,
	"reverse":      `<path d="M4 8h13M14 5l3 3-3 3M20 16H7M10 13l-3 3 3 3"/>`,
	"proxy":        `<circle cx="12" cy="12" r="8.5"/><path d="M4 9h16M4 15h16"/>`,
	"save":         `<path d="M5 3.5h11l3.5 3.5v13.5h-14.5V3.5z"/><path d="M8 3.5V10h8V3.5M8 20.5v-6h8v6"/>`,
	"open":         `<path d="M3 7.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v1M3 10h18l-2 9.5H4.5L3 10z"/>`,
	"add":          `<circle cx="12" cy="12" r="8.5"/><path d="M12 8v8M8 12h8"/>`,
	"reset":        `<path d="M4 11a8 8 0 1 1 2.3 6.4M4 5v6h6"/>`,
	"external":     `<path d="M14 4h6v6M20 4l-8 8"/><path d="M18 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5"/>`,
	"circle":       `<circle cx="12" cy="12" r="8.5"/>`,
	"square":       `<rect x="4" y="4" width="16" height="16" rx="2"/>`,
	"playCircle":   `<circle cx="12" cy="12" r="8.5"/><path d="M10 8.5l6 3.5-6 3.5v-7z"/>`,
	"stopCircle":   `<circle cx="12" cy="12" r="8.5"/><rect x="9" y="9" width="6" height="6" rx="1"/>`,
}

var parsedIcons = map[string]*ui.SVG{}

func icon(name string) *ui.SVG {
	if s := parsedIcons[name]; s != nil {
		return s
	}
	src, ok := iconSources[name]
	if !ok {
		src = iconSources["circle"]
	}
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">%s</svg>`, src)
	parsed, err := ui.ParseSVG([]byte(svg))
	if err != nil {
		return nil
	}
	parsedIcons[name] = parsed
	return parsed
}

func glyph(c *ui.Context, name string, size float32, color ui.Color) ui.Element {
	return ui.Icon(c, icon(name)).Size(size, size).TextColor(color)
}
