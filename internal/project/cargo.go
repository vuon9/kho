package project

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/vuon9/kho/internal/provider"
)

// readCargo reads Cargo.lock. Crates with no source are the workspace's own
// (members and path dependencies): what they depend on is direct. Cargo.lock
// doesn't mark dev dependencies, so those come from the manifests.
func readCargo(dir, name string) ([]provider.Package, error) {
	var lock struct {
		Package []struct {
			Name         string
			Version      string
			Source       string
			Dependencies []string
		}
	}
	if _, err := toml.DecodeFile(filepath.Join(dir, name), &lock); err != nil {
		return nil, err
	}
	devOnly, err := cargoDevOnly(dir)
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
			if devOnly[pkgs[j].Name] {
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

type cargoManifest struct {
	Dependencies      map[string]any
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
	Workspace         struct{ Members []string }
}

// cargoDevOnly names the crates that Cargo.toml and the workspace members'
// manifests list only under dev-dependencies.
func cargoDevOnly(dir string) (map[string]bool, error) {
	files := []string{"Cargo.toml"}
	prod, dev := map[string]bool{}, map[string]bool{}
	for i := 0; i < len(files); i++ {
		var m cargoManifest
		if _, err := toml.DecodeFile(filepath.Join(dir, files[i]), &m); err != nil {
			if i == 0 && errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			return nil, fmt.Errorf("%s: %w", files[i], err)
		}
		for _, pattern := range m.Workspace.Members {
			matches, _ := filepath.Glob(filepath.Join(dir, pattern, "Cargo.toml"))
			for _, match := range matches {
				rel, _ := filepath.Rel(dir, match)
				files = append(files, filepath.ToSlash(rel))
			}
		}
		for _, n := range crateNames(m.Dependencies, m.BuildDependencies) {
			prod[n] = true
		}
		for _, n := range crateNames(m.DevDependencies) {
			dev[n] = true
		}
	}
	out := map[string]bool{}
	for n := range dev {
		if !prod[n] {
			out[n] = true
		}
	}
	return out, nil
}

// crateNames reads dependency tables, where a key can be a rename:
// tmp = { package = "tempfile" }.
func crateNames(tables ...map[string]any) []string {
	var out []string
	for _, t := range tables {
		for key, v := range t {
			if spec, ok := v.(map[string]any); ok {
				if p, ok := spec["package"].(string); ok {
					key = p
				}
			}
			out = append(out, key)
		}
	}
	return out
}
