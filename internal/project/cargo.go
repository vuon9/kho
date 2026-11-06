package project

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/vuon9/kho/internal/provider"
)

// readCargo reads Cargo.lock. Crates with no source are the workspace's own
// (members and path dependencies): what they depend on is direct. Cargo.lock
// doesn't say which of those are dev dependencies, so each own crate's
// manifest decides, per locked version.
func readCargo(dir, name string) ([]provider.Package, error) {
	var lock struct {
		Package []struct {
			Name         string
			Version      string
			Source       string
			Dependencies []string
		}
	}
	if _, err := decodeTOML(filepath.Join(dir, name), &lock); err != nil {
		return nil, err
	}
	reqs, err := cargoRequirements(dir)
	if err != nil {
		return nil, err
	}
	pkgs := lock.Package
	byName := map[string][]int{}
	for i, p := range pkgs {
		byName[p.Name] = append(byName[p.Name], i)
	}
	// deps reads entries like "rand" or, when two versions are locked,
	// "getrandom 0.2.17".
	deps := func(i int) []int {
		var out []int
		for _, ref := range pkgs[i].Dependencies {
			f := strings.Fields(ref)
			if len(f) == 0 {
				continue
			}
			for _, j := range byName[f[0]] {
				if len(f) == 1 || pkgs[j].Version == f[1] {
					out = append(out, j)
				}
			}
		}
		return out
	}
	own := func(i int) bool { return pkgs[i].Source == "" }

	var prod, dev []int
	direct := map[int]bool{}
	for i := range pkgs {
		if !own(i) {
			continue
		}
		for _, j := range deps(i) {
			direct[j] = true
			if cargoDevEdge(reqs[pkgs[i].Name][pkgs[j].Name], pkgs[j].Version) {
				dev = append(dev, j)
			} else {
				prod = append(prod, j)
			}
		}
	}
	// The workspace's own crates list their dev dependencies too, so the walk
	// stops at them: their dependencies are already roots.
	children := func(i int) []int {
		if own(i) {
			return nil
		}
		return deps(i)
	}
	via, isDevOnly := trace(prod, dev, children, func(i int) string { return pkgs[i].Name })

	var out []provider.Package
	for i, p := range pkgs {
		if !strings.HasPrefix(p.Source, "registry+") && !strings.HasPrefix(p.Source, "sparse+") {
			continue
		}
		pkg := provider.Package{Name: p.Name, Version: p.Version, Dependency: !direct[i], Dev: isDevOnly(i)}
		if pkg.Dependency {
			pkg.Via = via[i]
		}
		out = append(out, pkg)
	}
	return out, nil
}

type cargoTables struct {
	Dependencies      map[string]any
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
}

type cargoManifest struct {
	Package struct{ Name string }
	cargoTables
	Target    map[string]cargoTables
	Workspace struct {
		Members      []string
		Dependencies map[string]any
	}
}

type cargoReq struct {
	version string
	dev     bool
}

// cargoRequirements reads Cargo.toml and its workspace members' manifests,
// and lists each crate's requirements by the name of the crate they pick.
// Only the root lists members, since Cargo has no nested workspaces.
func cargoRequirements(dir string) (map[string]map[string][]cargoReq, error) {
	var root cargoManifest
	if _, err := decodeTOML(filepath.Join(dir, "Cargo.toml"), &root); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("Cargo.toml: %w", err)
	}
	out := map[string]map[string][]cargoReq{}
	if root.Package.Name != "" {
		out[root.Package.Name] = root.requirements(root.Workspace.Dependencies)
	}
	// Members can name the root again (".") or one folder two ways, and a
	// hostile manifest can list a pattern a million times.
	seen := map[string]bool{"Cargo.toml": true}
	for i, pattern := range root.Workspace.Members {
		if i+len(seen) > MaxPackages {
			break
		}
		matches, _ := filepath.Glob(filepath.Join(dir, pattern, "Cargo.toml"))
		for _, match := range matches {
			rel, err := filepath.Rel(dir, match)
			if err != nil || seen[rel] || !filepath.IsLocal(rel) {
				continue
			}
			seen[rel] = true
			var m cargoManifest
			if _, err := decodeTOML(match, &m); err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.ToSlash(rel), err)
			}
			if m.Package.Name != "" {
				out[m.Package.Name] = m.requirements(root.Workspace.Dependencies)
			}
		}
	}
	return out, nil
}

// requirements lists m's requirements by the crate each one picks, which is
// not the key for a rename (tmp = { package = "tempfile" }), also when the
// rename comes from the workspace (tmp = { workspace = true }).
func (m cargoManifest) requirements(shared map[string]any) map[string][]cargoReq {
	out := map[string][]cargoReq{}
	add := func(table map[string]any, dev bool) {
		for key, v := range table {
			if spec, _ := v.(map[string]any); spec["workspace"] == true {
				v = shared[key]
			}
			name, version := key, ""
			switch spec := v.(type) {
			case string:
				version = spec
			case map[string]any:
				if p, ok := spec["package"].(string); ok {
					name = p
				}
				version, _ = spec["version"].(string)
			}
			out[name] = append(out[name], cargoReq{version, dev})
		}
	}
	for _, t := range append([]cargoTables{m.cargoTables}, slices.Collect(maps.Values(m.Target))...) {
		add(t.Dependencies, false)
		add(t.BuildDependencies, false)
		add(t.DevDependencies, true)
	}
	return out
}

// cargoDevEdge says an own crate pulls version in only as a dev dependency:
// a dev requirement can pick it and no other requirement can. Anything less
// certain counts as prod, so a crate that could ship is never marked dev.
func cargoDevEdge(reqs []cargoReq, version string) bool {
	dev := false
	for _, r := range reqs {
		if cargoMatches(r.version, version) {
			if !r.dev {
				return false
			}
			dev = true
		}
	}
	return dev
}

// cargoMatches says whether the Cargo requirement req, such as "0.7",
// "^1.2", "~1.2.3", "=0.4.1" or ">=1, <3", can pick version. It says yes to
// what it can't read, and errs wide where it simplifies, as for pre-releases.
func cargoMatches(req, version string) bool {
	if i := strings.IndexAny(version, "-+"); i >= 0 {
		version = version[:i]
	}
	got := cargoParts(version)
	if len(got) != 3 {
		return true
	}
	v := [3]int(got)
	for _, c := range strings.Split(req, ",") {
		c = strings.TrimSpace(c)
		num := strings.TrimLeft(c, "^~=<> ")
		n := cargoParts(num)
		if len(n) == 0 {
			continue
		}
		var lo [3]int
		copy(lo[:], n)
		at := slices.Compare(v[:], lo[:])
		// below says v is under lo with part i raised by one: ^0.7 ends at
		// 0.8.0, ~1.2 at 1.3.0.
		below := func(i int) bool {
			var hi [3]int
			copy(hi[:i], lo[:i])
			hi[i] = lo[i] + 1
			return slices.Compare(v[:], hi[:]) < 0
		}
		var ok bool
		switch strings.ReplaceAll(c[:len(c)-len(num)], " ", "") {
		case "", "^":
			i := slices.IndexFunc(n, func(x int) bool { return x != 0 })
			if i < 0 {
				i = len(n) - 1
			}
			ok = at >= 0 && below(i)
		case "~":
			ok = at >= 0 && below(min(1, len(n)-1))
		case "=":
			ok = at >= 0 && below(len(n)-1)
		case ">=", ">":
			ok = at >= 0
		case "<":
			ok = at < 0
		case "<=":
			ok = below(len(n) - 1)
		default:
			ok = true
		}
		if !ok {
			return false
		}
	}
	return true
}

// cargoParts reads the numbers at the start of a version: 1.2.3, 0.7 or the
// 1 of 1.*.
func cargoParts(s string) []int {
	var out []int
	for _, p := range strings.SplitN(s, ".", 3) {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			break
		}
		out = append(out, n)
	}
	return out
}
