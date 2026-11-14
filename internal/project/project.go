// Package project finds the lockfiles under a folder and reads them into
// packages kho can check. It only reads files. It never runs a project's
// tools, because those run the project's own scripts and plugins.
package project

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

// Tunables, package vars so tests can shrink them.
var (
	MaxDepth     = 4
	MaxLockfiles = 50
	Budget       = 3 * time.Second
)

type Scan struct {
	// Root is the absolute folder the scan used: the start folder, or the
	// git root when nothing was found below the start.
	Root string `json:"root"`
	// Projects holds one entry per folder with lockfiles or flagged
	// manifests, sorted by Dir.
	Projects []Project `json:"projects,omitempty"`
	// Capped says why the scan stopped early, or is "".
	Capped string `json:"capped,omitempty"`
	// Shallow names up to five folders at the depth limit whose subfolders
	// were not read, relative to Root and slash separated.
	Shallow []string `json:"shallow,omitempty"`
}

type Project struct {
	// Dir is relative to Root and slash separated, "" for Root itself.
	Dir       string     `json:"dir"`
	Lockfiles []Lockfile `json:"lockfiles"`
}

type Lockfile struct {
	// Path is relative to Root and slash separated.
	Path string `json:"path"`
	// Manager is npm, composer, go, uv, poetry, pip or cargo. It becomes
	// each package's Source.
	Manager  string             `json:"manager"`
	Packages []provider.Package `json:"packages,omitempty"`
	// Missing is set when only a manifest exists, and says what to do.
	Missing string `json:"missing,omitempty"`
	// Err is a read or parse failure, shown to the person.
	Err string `json:"error,omitempty"`
}

// Find walks down from start for lockfiles. When it finds nothing and start
// sits below the root of a git repo, it walks the repo from its root. The
// error is only for a start folder that can't be read.
func Find(ctx context.Context, start string) (Scan, error) {
	root, err := filepath.Abs(start)
	if err != nil {
		return Scan{}, err
	}
	if _, err := os.ReadDir(root); err != nil {
		return Scan{}, err
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	s := Scan{Root: root}
	s.Projects, s.Capped, s.Shallow = walk(ctx, root)
	if len(s.Projects) == 0 && s.Capped == "" {
		// A home folder kept in git for its dotfiles is not a project to walk.
		home, _ := os.UserHomeDir()
		if top := gitRoot(root); top != "" && top != root && top != home {
			s.Root = top
			s.Projects, s.Capped, s.Shallow = walk(ctx, top)
		}
	}
	if err := parent.Err(); err != nil {
		return Scan{}, err
	}
	return s, nil
}

// gitRoot is the nearest folder at or above dir that holds .git, or "".
// It never looks above the home folder.
func gitRoot(dir string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for !aboveHome(dir, home) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func aboveHome(dir, home string) bool {
	rel, err := filepath.Rel(dir, home)
	rel = filepath.ToSlash(rel)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../")
}

var skipped = map[string]bool{
	"node_modules": true, "vendor": true, ".venv": true, "venv": true, "target": true,
	"dist": true, "build": true, "testdata": true, "fixtures": true,
	// The OS keeps its own data here: caches, app support, containers, never a
	// project. Reading it costs more than the rest of a home folder together.
	"Library": true,
}

type folder struct {
	rel   string
	depth int
	// locked holds the ecosystems with a lockfile in a folder above.
	locked map[string]bool
}

// walk goes breadth first, so when a cap stops it the folders nearest the
// root are the ones read. shallow names the first few folders at MaxDepth
// that had folders below them, so a person knows what went unread.
func walk(ctx context.Context, root string) (projects []Project, capped string, shallow []string) {
	var found []Lockfile
	read := 0
	queue := []folder{{}}
scan:
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		if ctx.Err() != nil {
			capped = "stopped after " + Budget.String()
			break
		}
		dir := filepath.Join(root, filepath.FromSlash(f.rel))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		files := map[string]bool{}
		var dirs []string
		for _, e := range entries {
			switch {
			case !e.IsDir():
				files[e.Name()] = true
			case e.Name() == "requirements":
				// pip projects keep their requirements files here, as part of
				// the project above.
				sub, _ := os.ReadDir(filepath.Join(dir, e.Name()))
				for _, s := range sub {
					if !s.IsDir() {
						files["requirements/"+s.Name()] = true
					}
				}
			case !skipped[e.Name()] && !strings.HasPrefix(e.Name(), ".") && clean(e.Name()) == e.Name():
				dirs = append(dirs, e.Name())
			}
		}
		here, locked := detect(dir, f.rel, files, f.locked)
		for _, lf := range here {
			if lf.Missing != "" {
				found = append(found, lf)
				continue
			}
			if read == MaxLockfiles {
				capped = fmt.Sprintf("stopped after %d lockfiles", MaxLockfiles)
				break scan
			}
			if ctx.Err() != nil {
				capped = "stopped after " + Budget.String()
				break scan
			}
			read++
			found = append(found, readLockfile(root, lf.Path, lf.Manager))
		}
		switch {
		case f.depth < MaxDepth:
			for _, d := range dirs {
				queue = append(queue, folder{rel: path.Join(f.rel, d), depth: f.depth + 1, locked: locked})
			}
		case len(dirs) > 0 && len(shallow) < 5:
			shallow = append(shallow, f.rel)
		}
	}
	return group(found), capped, shallow
}

// detect lists the lockfiles in one folder, plus notes for manifests that
// have none. A manifest is not flagged when a folder above holds that
// ecosystem's lockfile, as in npm and Cargo workspaces.
func detect(dir, rel string, files, above map[string]bool) ([]Lockfile, map[string]bool) {
	var out []Lockfile
	add := func(file, manager, missing string) {
		out = append(out, Lockfile{Path: path.Join(rel, file), Manager: manager, Missing: missing})
	}
	noLock := func(cmd string) string { return "no lockfile, versions unknown. Run " + cmd + " to create one" }
	locked := maps.Clone(above)
	if locked == nil {
		locked = map[string]bool{}
	}

	npmLock := firstOf(files, "package-lock.json", "npm-shrinkwrap.json")
	otherLock := firstOf(files, "pnpm-lock.yaml", "yarn.lock", "bun.lock")
	switch {
	case npmLock != "":
		add(npmLock, "npm", "")
	case files["package.json"] && !above["npm"] && npmDeclares(dir):
		if otherLock != "" {
			add("package.json", "npm", otherLock+" isn't read yet")
		} else {
			add("package.json", "npm", noLock("npm install"))
		}
	}
	locked["npm"] = locked["npm"] || npmLock != "" || otherLock != ""

	switch {
	case files["composer.lock"]:
		add("composer.lock", "composer", "")
		locked["composer"] = true
	case files["composer.json"] && !above["composer"]:
		add("composer.json", "composer", noLock("composer install"))
	}

	if files["go.mod"] {
		add("go.mod", "go", "")
	}

	var reqs []string
	for name := range files {
		if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") && clean(name) == name {
			reqs = append(reqs, name)
		}
	}
	switch {
	case files["uv.lock"] || files["poetry.lock"]:
		// requirements files beside these are usually exported from them.
		if files["uv.lock"] {
			add("uv.lock", "uv", "")
		}
		if files["poetry.lock"] {
			add("poetry.lock", "poetry", "")
		}
		locked["python"] = true
	case len(reqs) > 0:
		for _, r := range reqs {
			add(r, "pip", "")
		}
		locked["python"] = true
	case files["pyproject.toml"] && !above["python"]:
		if m := pyprojectManager(dir); m != "" {
			add("pyproject.toml", m, noLock(m+" lock"))
		}
	}

	switch {
	case files["Cargo.lock"]:
		add("Cargo.lock", "cargo", "")
		locked["cargo"] = true
	case files["Cargo.toml"] && !above["cargo"]:
		add("Cargo.toml", "cargo", noLock("cargo generate-lockfile"))
	}
	return out, locked
}

func firstOf(files map[string]bool, names ...string) string {
	for _, n := range names {
		if files[n] {
			return n
		}
	}
	return ""
}

func group(lfs []Lockfile) []Project {
	slices.SortFunc(lfs, func(a, b Lockfile) int {
		return cmp.Or(strings.Compare(projectOf(a), projectOf(b)), strings.Compare(a.Manager, b.Manager), strings.Compare(a.Path, b.Path))
	})
	var out []Project
	for _, lf := range lfs {
		d := projectOf(lf)
		if len(out) == 0 || out[len(out)-1].Dir != d {
			out = append(out, Project{Dir: d})
		}
		out[len(out)-1].Lockfiles = append(out[len(out)-1].Lockfiles, lf)
	}
	return out
}

func dirOf(p string) string {
	if d := path.Dir(p); d != "." {
		return d
	}
	return ""
}

// projectOf is the folder a lockfile belongs to. Requirements files kept in
// a requirements folder belong to the project above it.
func projectOf(lf Lockfile) string {
	d := dirOf(lf.Path)
	if lf.Manager == "pip" && path.Base(d) == "requirements" {
		return dirOf(d)
	}
	return d
}

var readers = map[string]func(dir, name string) ([]provider.Package, error){
	"npm":      readNpm,
	"composer": readComposer,
	"go":       readGoMod,
	"uv":       readUv,
	"poetry":   readPoetry,
	"pip":      readRequirements,
	"cargo":    readCargo,
}

func readLockfile(root, rel, manager string) Lockfile {
	lf := Lockfile{Path: rel, Manager: manager}
	pkgs, err := readers[manager](filepath.Join(root, filepath.FromSlash(path.Dir(rel))), path.Base(rel))
	if err != nil {
		lf.Err = clean(err.Error())
		return lf
	}
	if len(pkgs) > MaxPackages {
		pkgs = pkgs[:MaxPackages]
		lf.Err = fmt.Sprintf("read the first %d packages only", MaxPackages)
	}
	for i := range pkgs {
		pkgs[i].Source = manager
		pkgs[i].Lockfile = rel
		pkgs[i].Name, pkgs[i].Version = clean(pkgs[i].Name), clean(pkgs[i].Version)
		for j := range pkgs[i].Via {
			pkgs[i].Via[j] = clean(pkgs[i].Via[j])
		}
	}
	lf.Packages = tidy(pkgs)
	return lf
}

// tidy sorts packages by name and version, and folds copies of one version
// into the one that matters most: direct, then prod, then the shortest chain.
// npm can install the same version at several places in node_modules.
func tidy(pkgs []provider.Package) []provider.Package {
	slices.SortFunc(pkgs, func(a, b provider.Package) int {
		if c := cmp.Or(strings.Compare(a.Name, b.Name), vuln.Compare(a.Version, b.Version),
			cmp.Compare(boolRank(a.Dependency), boolRank(b.Dependency)), cmp.Compare(boolRank(a.Dev), boolRank(b.Dev)),
			cmp.Compare(reach(a), reach(b)), strings.Compare(a.Path, b.Path), strings.Compare(a.Entry, b.Entry)); c != 0 {
			return c
		}
		return slices.Compare(a.Via, b.Via)
	})
	var out []provider.Package
	for _, p := range pkgs {
		if n := len(out); n > 0 && out[n-1].Name == p.Name && out[n-1].Version == p.Version {
			out[n-1].Dev = out[n-1].Dev && p.Dev
			continue
		}
		out = append(out, p)
	}
	return out
}

func reach(p provider.Package) int {
	if p.Dependency && p.Via == nil {
		return math.MaxInt
	}
	return len(p.Via)
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// trace finds how each node is pulled in. via holds the shortest chain of
// names from a root down to the node's parent. Chains from prod roots win, so
// a prod package is never shown as coming in through a dev tool. devOnly says
// a node is reachable from dev roots alone.
func trace[K comparable](prod, dev []K, children func(K) []K, name func(K) string) (via map[K][]string, devOnly func(K) bool) {
	fromProd := chains(prod, children, name)
	fromDev := chains(dev, children, name)
	via = maps.Clone(fromDev)
	maps.Copy(via, fromProd)
	return via, func(k K) bool {
		_, p := fromProd[k]
		_, d := fromDev[k]
		return d && !p
	}
}

func chains[K comparable](roots []K, children func(K) []K, name func(K) string) map[K][]string {
	found := map[K]chain{}
	var queue []K
	for _, r := range roots {
		if _, seen := found[r]; !seen {
			found[r] = chain{}
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range children(n) {
			if _, seen := found[c]; !seen {
				found[c] = found[n].with(name(n))
				queue = append(queue, c)
			}
		}
	}
	via := make(map[K][]string, len(found))
	for k, c := range found {
		via[k] = c.list()
	}
	return via
}

const chainHead, chainTail = 5, 4

// chain is a path from a direct package, kept to its first and last few
// links, so a lockfile where each package requires the next can't make
// every path a copy of the one before.
type chain struct {
	head, tail []string
	n          int
}

func (c chain) with(name string) chain {
	if len(c.head) < chainHead {
		return chain{head: append(slices.Clip(c.head), name), n: c.n + 1}
	}
	tail := append(slices.Clip(c.tail), name)
	if len(tail) > chainTail {
		tail = tail[len(tail)-chainTail:]
	}
	return chain{head: c.head, tail: tail, n: c.n + 1}
}

func (c chain) list() []string {
	if c.n == 0 {
		return nil
	}
	out := slices.Clone(c.head)
	if c.n > len(c.head)+len(c.tail) {
		out = append(out, "…")
	}
	return append(out, c.tail...)
}

func readJSON(file string, v any) error {
	data, err := readFile(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// FixCommand is what a person runs in the project's folder to move p to
// version, or "" when kho can't say. For pip it is an edit to make, not a
// command. Every part comes from a lockfile anyone could have written, so a
// command is only built from names and versions that a shell reads as
// plain words, and that the tool can't take for a flag.
func FixCommand(p provider.Package, version string) string {
	plain := func(s string) bool { return shellSafe.MatchString(s) && !strings.HasPrefix(s, "-") }
	for _, part := range []string{p.Name, p.Version, version, path.Base(p.Lockfile), p.Path, p.Entry} {
		if part != "" && part != "." && !plain(part) {
			return ""
		}
	}
	if p.Source == "go" && !plain(p.Origin) {
		return ""
	}
	switch p.Source {
	case "npm":
		// readNpm sets Path to the workspace member and Entry to the alias.
		name, spec := p.Name, p.Name+"@"+version
		if p.Entry != "" {
			name, spec = p.Entry, p.Entry+"@npm:"+p.Name+"@"+version
		}
		in := ""
		if p.Path != "" {
			in = " -w " + p.Path
		}
		switch {
		case p.Dependency:
			return "npm update " + name + in
		case p.Dev:
			return "npm install -D " + spec + in
		}
		return "npm install " + spec + in
	case "composer":
		switch {
		case p.Dependency:
			return "composer update " + p.Name
		case p.Dev:
			return "composer require --dev " + p.Name + ":^" + strings.TrimPrefix(version, "v")
		}
		return "composer require " + p.Name + ":^" + strings.TrimPrefix(version, "v")
	case "go":
		// OSV writes Go versions without the v that go get needs.
		return "go get " + p.Origin + "@v" + strings.TrimPrefix(version, "v")
	case "uv":
		// A direct requirement may pin a version that --upgrade-package
		// can't move past.
		if !p.Dependency {
			return `uv add "` + p.Name + ">=" + version + `"`
		}
		return "uv lock --upgrade-package " + p.Name
	case "poetry":
		if !p.Dependency {
			return "poetry add " + p.Name + "@^" + version
		}
		return "poetry update " + p.Name
	case "pip":
		file := path.Base(p.Lockfile)
		if path.Base(path.Dir(p.Lockfile)) == "requirements" {
			file = "requirements/" + file
		}
		return "pin " + p.Name + "==" + version + " in " + file
	case "cargo":
		// cargo add rewrites the requirement, so it also crosses a major
		// version. Naming the locked version picks the right one when two
		// are locked.
		if !p.Dependency {
			return "cargo add " + p.Name + "@" + version
		}
		return "cargo update -p " + p.Name + "@" + p.Version + " --precise " + version
	}
	return ""
}
