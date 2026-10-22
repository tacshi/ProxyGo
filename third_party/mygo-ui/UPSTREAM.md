# MyGo native UI

Based on `github.com/egoist/mygo/ui` at v0.6.2, under the included MIT license, as module `github.com/egoist/mygo/proxygoui` (a path under MyGo's, so that it may import MyGo's internal packages). The framework and CLI are pinned to MyGo v0.6.2 too. Upstream's `ui/editor` and `ui/markdown` (with its `parser`) are copied unchanged as `editor` and `markdown`, except that they import this package and its packages in place of `ui`'s. Upstream's `ui/chart`, `ui/richtext` and `ui/shader` packages, and the tests, are not copied.

As upstream does, the public API (`api_gen.go`) is generated from the private renderer API (`core*` functions and exported methods of `node` and `context`): run `go generate .` here after changing it. `internal/uigen` is upstream's generator, changed only to run from this directory.

ProxyGo's changes:

- A `Table`'s list keeps room at its end for the sideways scroll bar's track (`table.go`). The track takes presses even while the bar is hidden, which left half of the last row unclickable once the table was scrolled to its end. Reported upstream as [egoist/mygo#622](https://github.com/egoist/mygo/issues/622); drop this change once it is fixed there.
- A `Table`'s last column, when it shares the room the others leave, has no resizing edge (`table.go`): it ends where the table does, and its line there read as a stray divider beside the pane's splitter. Reported upstream as [egoist/mygo#625](https://github.com/egoist/mygo/issues/625); drop this change once it is fixed there.
- `uiPackage` (`diagnostics.go`) names this package, so that warnings point at ProxyGo's code rather than at this package's.

Not here, as it needs MyGo's native menus rather than this package: the Highlight menus' color dots are put on the native items by ProxyGo itself (`internal/app/menudots_darwin.go`), until MyGo's menu items take images ([egoist/mygo#486](https://github.com/egoist/mygo/issues/486)).

To move to a newer MyGo: copy its `ui` the same way, apply the changes above again (search for `ProxyGo:`), and bump the version in this module's `go.mod` and ProxyGo's.
