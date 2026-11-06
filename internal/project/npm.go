package project

import (
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vuon9/kho/internal/provider"
)

type npmEntry struct {
	Name                 string
	Version              string
	Dev                  bool
	Link                 bool
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]string
}

// npmV1 is a lockfileVersion 1 entry, which nests its dependencies.
type npmV1 struct {
	Version      string
	Dev          bool
	Requires     map[string]string
	Dependencies map[string]npmV1
}

// readNpm reads package-lock.json. Keys of "packages" are install paths:
// "" is the project, "packages/web" a workspace member, and anything under
// node_modules an installed package.
func readNpm(dir, name string) ([]provider.Package, error) {
	var lock struct {
		Packages     map[string]npmEntry
		Dependencies map[string]npmV1
	}
	if err := readJSON(filepath.Join(dir, name), &lock); err != nil {
		return nil, err
	}
	entries := lock.Packages
	if entries == nil && len(lock.Dependencies) > 0 {
		entries = map[string]npmEntry{}
		flattenV1("", lock.Dependencies, entries)
		var manifest npmEntry
		if err := readJSON(filepath.Join(dir, "package.json"), &manifest); err != nil {
			return nil, fmt.Errorf("package.json: %w", err)
		}
		entries[""] = manifest
	}

	installed := func(k string) bool { return strings.Contains(k, "node_modules/") }
	has := func(k string) bool { _, ok := entries[k]; return ok }
	// resolve finds the copy of dep that the package at from loads, the way
	// Node does: its own node_modules first, then each folder above.
	resolve := func(from, dep string) string {
		for d := from; ; d = path.Dir(d) {
			if d == "." {
				d = ""
			}
			if k := path.Join(d, "node_modules", dep); has(k) {
				return k
			}
			if d == "" {
				return ""
			}
		}
	}
	resolveAll := func(from string, deps ...map[string]string) []string {
		var out []string
		for _, m := range deps {
			for _, d := range slices.Sorted(maps.Keys(m)) {
				if k := resolve(from, d); k != "" {
					out = append(out, k)
				}
			}
		}
		return out
	}

	direct := map[string]bool{}
	var prod, dev []string
	for _, k := range slices.Sorted(maps.Keys(entries)) {
		if installed(k) {
			continue
		}
		e := entries[k]
		for _, d := range resolveAll(k, e.Dependencies, e.DevDependencies, e.OptionalDependencies, e.PeerDependencies) {
			if direct[d] {
				continue
			}
			direct[d] = true
			if entries[d].Dev {
				dev = append(dev, d)
			} else {
				prod = append(prod, d)
			}
		}
	}
	children := func(k string) []string {
		e := entries[k]
		return resolveAll(k, e.Dependencies, e.OptionalDependencies, e.PeerDependencies)
	}
	pkgName := func(k string) string {
		if n := entries[k].Name; n != "" {
			return n
		}
		return k[strings.LastIndex(k, "node_modules/")+len("node_modules/"):]
	}
	via, _ := trace(prod, dev, children, pkgName)

	var pkgs []provider.Package
	for k, e := range entries {
		if !installed(k) || e.Link || e.Version == "" {
			continue
		}
		p := provider.Package{Name: pkgName(k), Version: e.Version, Dependency: !direct[k], Dev: e.Dev}
		if p.Dependency {
			p.Via = via[k]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func flattenV1(prefix string, deps map[string]npmV1, out map[string]npmEntry) {
	for name, d := range deps {
		k := prefix + "node_modules/" + name
		out[k] = npmEntry{Version: d.Version, Dev: d.Dev, Dependencies: d.Requires}
		flattenV1(k+"/", d.Dependencies, out)
	}
}

// npmDeclares says whether package.json lists a dependency. Many hold only
// scripts or settings, and a missing lockfile note there would be noise.
func npmDeclares(dir string) bool {
	var m npmEntry
	if readJSON(filepath.Join(dir, "package.json"), &m) != nil {
		return true
	}
	return len(m.Dependencies)+len(m.DevDependencies)+len(m.OptionalDependencies)+len(m.PeerDependencies) > 0
}
