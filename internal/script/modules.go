package script

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dop251/goja"
)

//go:embed addons/*.js
var builtinAddons embed.FS

const (
	UsersDir   = "users"
	AddonsDir  = "addons"
	LibsDir    = "libs"
	PackageDir = "node_modules"
)

var nodeBuiltins = map[string]bool{
	"assert": true, "buffer": true, "child_process": true, "cluster": true, "crypto": true, "dgram": true,
	"dns": true, "events": true, "fs": true, "http": true, "http2": true, "https": true, "net": true,
	"os": true, "path": true, "process": true, "querystring": true, "readline": true, "stream": true,
	"string_decoder": true, "timers": true, "tls": true, "tty": true, "url": true, "util": true,
	"v8": true, "vm": true, "worker_threads": true, "zlib": true,
}

func (e *Engine) SetRoot(root string) {
	e.mu.Lock()
	e.root = root
	e.mu.Unlock()
	if root == "" {
		return
	}
	for _, d := range []string{UsersDir, AddonsDir, LibsDir} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o750)
	}
}

func (e *Engine) Root() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.root
}

type source struct {
	key  string
	dir  string
	code []byte
	mod  time.Time
}

var esm = regexp.MustCompile(`(?m)^\s*(import\s+[\w{*"']|export\s+(default|const|let|var|function|class|async|\{|\*))`)

type compiledModule struct {
	mod  time.Time
	prog *goja.Program
	json bool
}

var errOutside = errors.New("outside the scripts folder")

func (e *Engine) resolve(name, from string) (*source, error) {
	root := e.Root()
	if nodeBuiltins[strings.TrimPrefix(name, "node:")] || strings.HasPrefix(name, "node:") {
		return nil, fmt.Errorf("Node.js's own module %q is not available in ProxyGo scripts", name) //nolint:staticcheck // Node.js is a proper name and starts the message.
	}
	if strings.HasSuffix(name, ".node") {
		return nil, fmt.Errorf("native add-ons, as %q, are not supported in ProxyGo scripts", name)
	}
	switch {
	case strings.HasPrefix(name, "@addons/"):
		rest := strings.TrimPrefix(name, "@addons/")
		if root != "" {
			if s, err := e.file(filepath.Join(root, AddonsDir), rest, root); err == nil {
				return s, nil
			}
		}
		b, err := builtinAddons.ReadFile(path.Join("addons", withJS(path.Clean("/" + rest)[1:])))
		if err != nil {
			return nil, fmt.Errorf("no addon %q", rest)
		}
		return &source{key: "builtin:" + rest, dir: "builtin:", code: b}, nil
	case strings.HasPrefix(name, "@users/"), strings.HasPrefix(name, "@libs/"):
		dir := UsersDir
		if strings.HasPrefix(name, "@libs/") {
			dir = LibsDir
		}
		if root == "" {
			return nil, errors.New("scripts have no folder to require from")
		}
		_, rest, _ := strings.Cut(name, "/")
		return e.file(filepath.Join(root, dir), rest, root)
	case strings.HasPrefix(name, "@"):
		return e.pkg(name, root)
	case strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../"):
		if from == "builtin:" {
			b, err := builtinAddons.ReadFile(path.Join("addons", withJS(path.Clean("/" + name)[1:])))
			if err != nil {
				return nil, fmt.Errorf("no addon %q", name)
			}
			return &source{key: "builtin:" + name, dir: "builtin:", code: b}, nil
		}
		if from == "" {
			if root == "" {
				return nil, errors.New("scripts have no folder to require from")
			}
			from = filepath.Join(root, UsersDir)
		}
		return e.file(from, name, root)
	}
	return e.pkg(name, root)
}

func withJS(p string) string {
	if path.Ext(p) == "" {
		return p + ".js"
	}
	return p
}

func (e *Engine) file(dir, rel, root string) (*source, error) {
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if !inside(p, root) {
		return nil, fmt.Errorf("%q is %w", rel, errOutside)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("cannot find %q", rel)
	}
	defer func() { _ = r.Close() }()
	for _, c := range []string{p, p + ".js", p + ".json", filepath.Join(p, "index.js")} {
		name, _ := filepath.Rel(root, c)
		fi, err := r.Stat(name)
		if errors.Is(err, fs.ErrNotExist) || err == nil && fi.IsDir() {
			continue
		}
		var b []byte
		if err == nil {
			b, err = r.ReadFile(name)
		}
		if err != nil {
			return nil, fmt.Errorf("cannot read %q: %w", rel, err)
		}
		return &source{key: c, dir: filepath.Dir(c), code: b, mod: fi.ModTime()}, nil
	}
	return nil, fmt.Errorf("cannot find %q", rel)
}

func (e *Engine) pkg(name, root string) (*source, error) {
	if root == "" {
		return nil, fmt.Errorf("cannot find module %q", name)
	}
	modules := filepath.Join(root, PackageDir)
	parts := strings.SplitN(name, "/", 3)
	pkgName, sub := parts[0], ""
	if strings.HasPrefix(name, "@") && len(parts) >= 2 {
		pkgName = parts[0] + "/" + parts[1]
		if len(parts) == 3 {
			sub = parts[2]
		}
	} else if len(parts) >= 2 {
		sub = strings.Join(parts[1:], "/")
	}
	dir := filepath.Join(modules, filepath.FromSlash(pkgName))
	if !inside(dir, modules) {
		return nil, fmt.Errorf("%q is %w", name, errOutside)
	}
	if sub != "" {
		return e.file(dir, sub, root)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("cannot find module %q: install it with npm install in %s", name, root)
	}
	defer func() { _ = r.Close() }()
	pkgDir, _ := filepath.Rel(root, dir)
	main := "index.js"
	if b, err := r.ReadFile(filepath.Join(pkgDir, "package.json")); err == nil {
		var pj struct {
			Main string `json:"main"`
			Type string `json:"type"`
		}
		if json.Unmarshal(b, &pj) != nil {
			return nil, fmt.Errorf("%s's package.json is not valid", name)
		}
		if pj.Main != "" {
			main = pj.Main
		}
		if pj.Type == "module" && !strings.HasSuffix(main, ".cjs") {
			return nil, fmt.Errorf("%s is an ES module, which require() cannot load in ProxyGo scripts", name)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("cannot read %s's package.json: %w", name, err)
	} else if _, err := r.Stat(pkgDir); err != nil {
		return nil, fmt.Errorf("cannot find module %q: install it with npm install in %s", name, root)
	}
	return e.file(dir, main, root)
}

func inside(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (e *Engine) requireFunc(vm *goja.Runtime) func(from string) func(goja.FunctionCall) goja.Value {
	cache := map[string]goja.Value{}
	var newRequire func(from string) func(goja.FunctionCall) goja.Value
	newRequire = func(from string) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			name := call.Argument(0).String()
			src, err := e.resolve(name, from)
			if err != nil {
				panic(vm.NewGoError(fmt.Errorf("could not require %q: %w", name, err)))
			}
			if v, ok := cache[src.key]; ok {
				return v
			}
			prog, isJSON, err := e.compileModule(src)
			if err != nil {
				panic(vm.NewGoError(fmt.Errorf("could not require %q: %w", name, err)))
			}
			if isJSON {
				parsed := jsonValue(vm, src.code)
				cache[src.key] = parsed
				return parsed
			}
			module := vm.NewObject()
			exports := vm.NewObject()
			_ = module.Set("exports", exports)
			cache[src.key] = exports
			fn, err := vm.RunProgram(prog)
			if err != nil {
				delete(cache, src.key)
				panic(err)
			}
			wrapper, _ := goja.AssertFunction(fn)
			if _, err := wrapper(goja.Undefined(), exports, vm.ToValue(newRequire(src.dir)), module, vm.ToValue(src.key), vm.ToValue(src.dir)); err != nil {
				delete(cache, src.key)
				panic(err)
			}
			out := module.Get("exports")
			cache[src.key] = out
			return out
		}
	}
	return newRequire
}

func jsonValue(vm *goja.Runtime, b []byte) goja.Value {
	parse, _ := goja.AssertFunction(vm.Get("JSON").ToObject(vm).Get("parse"))
	v, err := parse(goja.Undefined(), vm.ToValue(string(b)))
	if err != nil {
		panic(err)
	}
	return v
}

func (e *Engine) compileModule(src *source) (*goja.Program, bool, error) {
	isJSON := strings.HasSuffix(src.key, ".json")
	e.mu.Lock()
	if e.modules == nil {
		e.modules = map[string]compiledModule{}
	}
	c, ok := e.modules[src.key]
	e.mu.Unlock()
	if ok && c.mod.Equal(src.mod) {
		return c.prog, c.json, nil
	}
	var prog *goja.Program
	if !isJSON {
		code := "(function (exports, require, module, __filename, __dirname) {" + string(src.code) + "\n})"
		var err error
		prog, err = goja.Compile(src.key, code, false)
		if err != nil {
			if esm.Match(src.code) {
				return nil, false, errors.New("ES modules (import and export) are not supported by require() in ProxyGo scripts")
			}
			return nil, false, err
		}
	}
	e.mu.Lock()
	if len(e.modules) > 200 {
		clear(e.modules)
	}
	e.modules[src.key] = compiledModule{mod: src.mod, prog: prog, json: isJSON}
	e.mu.Unlock()
	return prog, isJSON, nil
}

func Addons() []string {
	entries, _ := fs.ReadDir(builtinAddons, "addons")
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
