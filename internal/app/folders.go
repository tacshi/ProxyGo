package app

import (
	"path/filepath"
	"slices"
	"strings"

	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/codegen"
	"proxygo/internal/flow"
	"proxygo/internal/saved"
	"proxygo/internal/store"
	"proxygo/locales"
)

type folderSheet struct {
	open   bool
	path   string
	rename string
	flows  []*flow.Flow
	err    string
}

func (a *App) saveToFolder(fs []*flow.Flow) {
	if len(fs) == 0 {
		return
	}
	path := a.folderSave.path
	a.folderSave = folderSheet{open: true, path: path, flows: fs}
}

func (a *App) folderSheetView(c *ui.Context) {
	s := &a.folderSave
	if !s.open {
		return
	}
	p := a.pal
	if s.rename != "" {
		a.renameFolderView(c, s)
		return
	}
	ui.Modal(c, &s.open, func() {
		ui.Column(c).Width(sheetWidth(c, 420)).Gap(10).Children(func() {
			ui.Text(c, locales.SaveToFolder()).FontSize(15).FontWeight(650)
			ui.Text(c, locales.KeepFlowsOnDisk(len(s.flows))).TextColor(p.muted).Wrap()
			var names []string
			for _, f := range a.folders.Folders() {
				names = append(names, f.Path)
			}
			in := ui.Autocomplete(c, &s.path, names).Placeholder(locales.FolderAsAPIErrors()).Label(locales.ColumnFolder()).AutoFocus()
			if s.err != "" {
				ui.Text(c, s.err).FontSize(11).TextColor(p.red)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					s.open = false
				}
				if ui.PrimaryButton(c, locales.Save()).Disabled(s.path == "").Clicked() || s.path != "" && (in.Submitted() || c.Shortcut(ui.Cmd, ui.KeyEnter)) {
					path, err := saved.Clean(s.path)
					if err != nil {
						s.err = err.Error()
						return
					}
					flows, icons := s.flows, a.iconStrings()
					s.open = false
					go func() {
						n, err := a.folders.Add(path, flows, icons)
						a.do(func() {
							if err != nil {
								a.toast(locales.CannotSave(err.Error()))
								return
							}
							a.toast(locales.SavedToFolder(path, n))
						})
					}()
				}
			})
		})
	})
}

func (a *App) renameFolderView(c *ui.Context, s *folderSheet) {
	p := a.pal
	ui.Modal(c, &s.open, func() {
		ui.Column(c).Width(sheetWidth(c, 420)).Gap(10).Children(func() {
			ui.Text(c, locales.RenameName(s.rename)).FontSize(15).FontWeight(650)
			ui.Text(c, locales.NameItParentNameToMove()).TextColor(p.muted).Wrap()
			in := ui.TextInput(c, &s.path).Placeholder(locales.ColumnFolder()).Label(locales.ColumnFolder()).AutoFocus()
			if s.err != "" {
				ui.Text(c, s.err).FontSize(11).TextColor(p.red)
			}
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, locales.Cancel()).Clicked() {
					s.open = false
				}
				ready := s.path != "" && s.path != s.rename
				if ui.PrimaryButton(c, locales.Rename()).Disabled(!ready).Clicked() || ready && in.Submitted() {
					if err := a.folders.Rename(s.rename, s.path); err != nil {
						s.err = err.Error()
						return
					}
					s.open = false
				}
			})
		})
	})
}

func (a *App) importFolder(path string) {
	go func() {
		b, err := a.folders.Open(path)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotOpen(path, err.Error()))
				return
			}
			a.loadIcons(b.Icons)
			a.store.Append(b.Flows)
			a.toast(locales.ImportedFlowsFrom(len(b.Flows), path))
		})
	}()
}

func (a *App) exportFolder(path string) {
	go func() {
		b, err := a.folders.Open(path)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotOpen(path, err.Error()))
				return
			}
			a.exportFlows("har", b.Flows, filepath.Base(path))
		})
	}()
}

func (a *App) deleteFolder(f saved.Folder) {
	parent := a.win
	n, subs := 0, 0
	for _, x := range a.folders.Folders() {
		if x.Path == f.Path || strings.HasPrefix(x.Path, f.Path+"/") {
			n += x.Count
			if x.Path != f.Path {
				subs++
			}
		}
	}
	var detail string
	switch {
	case n == 0 && subs == 0:
		detail = locales.ItIsEmpty()
	case subs > 0:
		detail = locales.FolderFlowsAndSubfoldersDeleted(n, subs)
	default:
		detail = locales.FolderFlowsDeleted(n)
	}
	go func() {
		ok, err := confirmDelete(parent, locales.DeleteTheFolder(f.Path), detail)
		if err != nil || !ok {
			return
		}
		err = a.folders.Delete(f.Path)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotDelete(f.Path, err.Error()))
			}
		})
	}()
}

func (a *App) openFolder(path string) {
	go func() {
		b, err := a.folders.Open(path)
		a.do(func() {
			if err != nil {
				a.toast(locales.CannotOpen(path, err.Error()))
				return
			}
			a.loadIcons(b.Icons)
			a.openSessionWindow(path, a.folders.File(path), b.Flows)
		})
	}()
}

func (a *App) copyMarkdown(fs []*flow.Flow) {
	if len(fs) == 0 {
		return
	}
	a.copy(codegen.Markdown(fs), locales.CopiedAs("Markdown"))
}

func (a *App) filterBy(cond store.Condition) {
	if a.section == "overview" {
		a.section = "all"
	}
	a.conditions = slices.DeleteFunc(slices.Clone(a.conditions), func(c store.Condition) bool { return !c.Active() })
	a.conditions = append(a.conditions, cond)
	a.matchAny = false
	a.advanced = true
}
