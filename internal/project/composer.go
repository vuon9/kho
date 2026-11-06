package project

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vuon9/kho/internal/provider"
)

type composerPkg struct {
	Name    string
	Version string
	Require map[string]string
}

// readComposer reads composer.lock. Versions stay as written, often with a
// leading v: OSV lists Packagist versions that way and matches both forms.
// Platform requirements such as php and ext-json never match a locked
// package, so they drop out of the graph on their own.
func readComposer(dir, name string) ([]provider.Package, error) {
	var lock struct {
		Packages    []composerPkg
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := readJSON(filepath.Join(dir, name), &lock); err != nil {
		return nil, err
	}
	var manifest struct {
		Require    map[string]string
		RequireDev map[string]string `json:"require-dev"`
	}
	err := readJSON(filepath.Join(dir, "composer.json"), &manifest)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("composer.json: %w", err)
	}
	noManifest := err != nil

	all := slices.Concat(lock.Packages, lock.PackagesDev)
	byName := map[string]int{}
	for i, p := range all {
		byName[strings.ToLower(p.Name)] = i
	}
	isDev := func(i int) bool { return i >= len(lock.Packages) }
	known := func(require map[string]string) []int {
		var out []int
		for _, n := range slices.Sorted(maps.Keys(require)) {
			if i, ok := byName[strings.ToLower(n)]; ok {
				out = append(out, i)
			}
		}
		return out
	}

	var prod, dev []int
	if noManifest {
		for i := range all {
			if isDev(i) {
				dev = append(dev, i)
			} else {
				prod = append(prod, i)
			}
		}
	} else {
		prod, dev = known(manifest.Require), known(manifest.RequireDev)
	}
	direct := map[int]bool{}
	for _, i := range slices.Concat(prod, dev) {
		direct[i] = true
	}
	via, _ := trace(prod, dev, func(i int) []int { return known(all[i].Require) }, func(i int) string { return all[i].Name })

	var pkgs []provider.Package
	for i, p := range all {
		pkg := provider.Package{Name: p.Name, Version: p.Version, Dependency: !direct[i], Dev: isDev(i)}
		if pkg.Dependency {
			pkg.Via = via[i]
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}
