package app

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	ui "github.com/egoist/mygo/proxygoui"
	"github.com/egoist/mygo/proxygoui/editor"

	"proxygo/internal/flow"
	"proxygo/locales"
)

type diffState struct {
	left, right string
	part        int
	unified     bool
	normalize   bool
	pool        []string
	state       *editor.DiffState
	key         string
}

func (a *App) addToDiffPool(fs []*flow.Flow) {
	for _, f := range fs {
		if !slices.Contains(a.diff.pool, f.UniqueID) {
			a.diff.pool = append(a.diff.pool, f.UniqueID)
		}
	}
	d := &a.diff
	if len(d.pool) >= 2 && (d.left == "" || d.right == "") {
		d.left, d.right, d.key = d.pool[0], d.pool[1], ""
	}
	if len(d.pool) >= 2 {
		a.openWindow("diff")
	} else {
		a.toast(locales.AddedToTheDiffPoolAdd())
	}
}

func diffText(f *flow.Flow, response, normalize bool) string {
	if !normalize {
		if response {
			return rawResponse(f)
		}
		return rawRequest(f)
	}
	var b strings.Builder
	var h flow.Header
	var body []byte
	var ct string
	if response {
		if f.Response == nil {
			return ""
		}
		fmt.Fprintf(&b, "%s\n", f.StatusLine())
		h, body, ct = f.Response.Header, f.DecodedResponseBody(), f.Response.Header.Get("Content-Type")
	} else {
		fmt.Fprintf(&b, "%s %s\n", f.MethodName(), f.URL())
		h, body, ct = f.Request.Header, f.DecodedRequestBody(), f.Request.Header.Get("Content-Type")
	}
	var lines []string
	for _, e := range h.Entries {
		if e.Enabled {
			lines = append(lines, strings.ToLower(e.Key.Name)+": "+e.Value)
		}
	}
	slices.Sort(lines)
	b.WriteString(strings.Join(lines, "\n"))
	b.WriteString("\n\n")
	var v any
	if json.Unmarshal(body, &v) == nil {
		out, _ := json.MarshalIndent(v, "", "  ")
		b.Write(out)
	} else {
		b.WriteString(bodyForRaw(body, ct))
	}
	return b.String()
}

func (a *App) externalDiff(tool string, l, r *flow.Flow) {
	d := a.diff
	left, right := diffText(l, d.part == 1, d.normalize), diffText(r, d.part == 1, d.normalize)
	go func() {
		dir, err := os.MkdirTemp("", "proxygo-diff-")
		if err == nil {
			lp, rp := filepath.Join(dir, "#"+l.ID+".txt"), filepath.Join(dir, "#"+r.ID+".txt")
			if err = os.WriteFile(lp, []byte(left), 0o600); err == nil {
				if err = os.WriteFile(rp, []byte(right), 0o600); err == nil {
					name := map[string]string{"filemerge": "opendiff", "kaleidoscope": "ksdiff"}[tool]
					cmd := exec.Command(name, lp, rp) // #nosec G204 -- opendiff or ksdiff, given two temporary files.
					if err = cmd.Start(); err == nil {
						go func() {
							_ = cmd.Wait()
							time.Sleep(time.Minute)
							_ = os.RemoveAll(dir)
						}()
						return
					}
				}
			}
			_ = os.RemoveAll(dir)
		}
		a.do(func() { a.toast(locales.CannotOpenTheDiff(err.Error())) })
	}()
}

func hasTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (a *App) compare(l, r *flow.Flow) {
	a.diff.left, a.diff.right = l.UniqueID, r.UniqueID
	a.diff.key = ""
	a.openWindow("diff")
}

func (a *App) compareChosen() {
	fs := a.chosenFlows()
	switch {
	case len(fs) >= 2:
		a.compare(fs[0], fs[1])
	case len(fs) == 1 && a.diff.left != "" && a.diff.left != fs[0].UniqueID:
		a.diff.right = fs[0].UniqueID
		a.diff.key = ""
		a.openWindow("diff")
	case len(fs) == 1:
		a.setDiffSide(fs[0], false)
	}
}

func (a *App) setDiffSide(f *flow.Flow, right bool) {
	if right {
		a.diff.right = f.UniqueID
	} else {
		a.diff.left = f.UniqueID
	}
	a.diff.key = ""
	if a.diff.left != "" && a.diff.right != "" {
		a.openWindow("diff")
	} else {
		a.toast(map[bool]string{true: locales.SetAsTheRightSide(), false: locales.SetAsTheLeftSide()}[right])
	}
}

func (a *App) diffWindow(c *ui.Context) {
	p := a.pal
	d := &a.diff
	l, _ := a.store.Lookup(d.left)
	r, _ := a.store.Lookup(d.right)
	a.windowHeader(c, locales.Diff(), locales.CompareTwoFlowsRequestsOrResponses(), func() {
		if ui.Segmented(c, &d.part, locales.PhaseRequest(), locales.PhaseResponse()).Label(locales.Compare()).Changed() {
			d.key = ""
		}
		mode := map[bool]int{true: 1}[d.unified]
		if ui.Segmented(c, &mode, locales.SideBySide(), locales.Unified()).Label(locales.Layout()).Changed() {
			d.unified = mode == 1
			d.key = ""
		}
		if ui.Toggle(c, &d.normalize, locales.Normalize()).Tooltip(locales.SortJSONKeysAndHeadersSo()).Changed() {
			d.key = ""
		}
	})
	if len(d.pool) > 0 {
		a.diffPool(c)
	}
	if l == nil || r == nil {
		ui.Column(c).Grow(1).Center().Gap(8).Children(func() {
			glyph(c, "diff", 28, p.faint)
			ui.Text(c, locales.ChooseTwoFlowsToCompare()).FontSize(14).FontWeight(600).TextColor(p.text2)
			ui.Text(c, locales.SelectTwoFlowsAndChooseCompare()).TextColor(p.muted)
		})
		return
	}
	side := func(f *flow.Flow) string { return diffText(f, d.part == 1, d.normalize) }
	key := fmt.Sprint(l.UniqueID, r.UniqueID, d.part, d.unified, d.normalize, len(side(l)), len(side(r)))
	if d.key != key || d.state == nil {
		d.key = key
		d.state = &editor.DiffState{Old: editor.NewBuffer(side(l)), New: editor.NewBuffer(side(r)), Wrap: true}
		if d.unified {
			d.state.Layout = editor.DiffUnified
		}
	}
	ui.Row(c).FillWidth().Padding(0, windowInset, 8, windowInset).Gap(12).Children(func() {
		for _, f := range []*flow.Flow{l, r} {
			ui.Row(c).Grow(1).Gap(6).AlignItems(ui.Center).Padding(6, 10).Radius(6).Background(p.surface).Children(func() {
				ui.Text(c, "#"+f.ID).FontSize(11).TextColor(p.muted)
				ui.Text(c, f.MethodName()).FontSize(10).FontWeight(650).TextColor(p.pillText)
				ui.Text(c, f.URL()).FontSize(11).TextColor(p.link).SingleLine().Grow(1)
			})
		}
	})
	added, deleted := d.state.Stats()
	ui.Row(c).FillWidth().Padding(0, windowInset, 6, windowInset).Gap(10).Children(func() {
		ui.Text(c, fmt.Sprintf("+%d", added)).FontWeight(600).TextColor(p.green)
		ui.Text(c, fmt.Sprintf("−%d", deleted)).FontWeight(600).TextColor(p.red)
		ui.Text(c, locales.ChangesCount(len(d.state.Hunks()))).TextColor(p.muted)
		ui.Spacer(c)
		if hasTool("opendiff") && ui.Button(c, locales.OpenInFileMerge()).Clicked() {
			a.externalDiff("filemerge", l, r)
		}
		if hasTool("ksdiff") && ui.Button(c, locales.OpenInKaleidoscope()).Clicked() {
			a.externalDiff("kaleidoscope", l, r)
		}
		if ui.Button(c, locales.SwapSides()).Clicked() {
			d.left, d.right, d.key = d.right, d.left, ""
		}
	})
	ui.Column(c).Grow(1).Margin(0, windowInset, windowInset, windowInset).Radius(8).Border(1, p.border).Clip().Children(func() {
		editor.DiffView(c.Key(d.key), d.state).Fill()
	})
}

func (a *App) diffPool(c *ui.Context) {
	p := a.pal
	d := &a.diff
	ui.Row(c).FillWidth().Padding(0, windowInset, 8, windowInset).Gap(6).AlignItems(ui.Center).Children(func() {
		ui.Text(c, locales.DiffPool()).FontSize(11).FontWeight(650).TextColor(p.muted)
		ui.ScrollHorizontal(c).Grow(1).Shrink(1).Gap(6).Children(func() {
			for _, id := range d.pool {
				f, ok := a.store.Lookup(id)
				if !ok {
					continue
				}
				side := ""
				switch id {
				case d.left:
					side = "L"
				case d.right:
					side = "R"
				}
				b := ui.ButtonBase(c.Key(id)).Label("#"+f.ID).Padding(3, 8).Radius(5).Tooltip(f.MethodName() + " " + f.URL() + "\n" + locales.DiffPoolClickHint())
				switch {
				case side != "":
					b.Background(p.accent.Alpha(0.15))
				case b.Hovered():
					b.Background(p.hover)
				default:
					b.Background(p.surface)
				}
				b.Children(func() {
					ui.Row(c).Gap(4).AlignItems(ui.Center).Children(func() {
						if side != "" {
							ui.Text(c, side).FontSize(10).FontWeight(700).TextColor(p.accent)
						}
						ui.Text(c, "#"+f.ID+" "+shorten(f.Host()+f.URLPath(), 40)).FontSize(11).TextColor(p.text2).SingleLine()
					})
				})
				if b.Clicked() {
					if b.ClickModifiers()&ui.Cmd != 0 {
						d.left = id
					} else {
						d.right = id
					}
					d.key = ""
				}
			}
		})
		if ui.Button(c, locales.ClearPool()).Clicked() {
			d.pool = nil
		}
	})
}
