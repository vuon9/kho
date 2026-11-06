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

type uvDep struct {
	Name    string
	Version string
	Extra   []string
}

type uvPkg struct {
	Name    string
	Version string
	Source  struct {
		Virtual, Editable, Git, Path, Directory string
	}
	Dependencies         []uvDep
	OptionalDependencies map[string][]uvDep `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvDep `toml:"dev-dependencies"`
}

// readUv reads uv.lock. The project and workspace members have a virtual or
// editable source: what they depend on is direct, and their dependency
// groups are direct and dev.
func readUv(dir, name string) ([]provider.Package, error) {
	var lock struct{ Package []uvPkg }
	if _, err := decodeTOML(filepath.Join(dir, name), &lock); err != nil {
		return nil, err
	}
	pkgs := lock.Package
	byName := map[string][]int{}
	for i, p := range pkgs {
		byName[p.Name] = append(byName[p.Name], i)
	}
	// A name can be locked at two versions for different platforms, and then
	// each reference names its version.
	find := func(deps []uvDep) []int {
		var out []int
		for _, d := range deps {
			for _, i := range byName[d.Name] {
				if d.Version == "" || d.Version == pkgs[i].Version {
					out = append(out, i)
				}
			}
		}
		return out
	}
	inGroups := func(groups map[string][]uvDep) []uvDep {
		var out []uvDep
		for _, g := range slices.Sorted(maps.Keys(groups)) {
			out = append(out, groups[g]...)
		}
		return out
	}

	children := make([][]int, len(pkgs))
	for i, p := range pkgs {
		children[i] = find(p.Dependencies)
	}
	// Asking for flask[async] pulls in flask's async extra as well.
	for _, p := range pkgs {
		for _, d := range slices.Concat(p.Dependencies, inGroups(p.OptionalDependencies), inGroups(p.DevDependencies)) {
			for _, t := range find([]uvDep{d}) {
				for _, e := range d.Extra {
					children[t] = append(children[t], find(pkgs[t].OptionalDependencies[e])...)
				}
			}
		}
	}

	local := func(i int) bool { return pkgs[i].Source.Virtual != "" || pkgs[i].Source.Editable != "" }
	var prod, dev []int
	for i, p := range pkgs {
		if local(i) {
			prod = append(prod, find(slices.Concat(p.Dependencies, inGroups(p.OptionalDependencies)))...)
			dev = append(dev, find(inGroups(p.DevDependencies))...)
		}
	}
	direct := map[int]bool{}
	for _, i := range slices.Concat(prod, dev) {
		direct[i] = true
	}
	via, devOnly := trace(prod, dev, func(i int) []int { return children[i] }, func(i int) string { return pkgs[i].Name })

	var out []provider.Package
	for i, p := range pkgs {
		s := p.Source
		if local(i) || s.Git != "" || s.Path != "" || s.Directory != "" {
			continue
		}
		pkg := provider.Package{Name: p.Name, Version: p.Version, Dependency: !direct[i], Dev: devOnly(i)}
		if pkg.Dependency {
			pkg.Via = via[i]
		}
		out = append(out, pkg)
	}
	return out, nil
}

type poetryPkg struct {
	Name         string
	Version      string
	Category     string
	Groups       []string
	Dependencies map[string]any
	Source       struct{ Type string }
}

// dev reads the newer groups list, or the older category.
func (p poetryPkg) dev() bool {
	if len(p.Groups) > 0 {
		return !slices.Contains(p.Groups, "main")
	}
	return p.Category == "dev"
}

// readPoetry reads poetry.lock, with direct dependencies from pyproject.toml
// beside it. Dependency keys are written as the package spells its name
// ("MarkupSafe" for markupsafe), so names are matched normalized.
func readPoetry(dir, name string) ([]provider.Package, error) {
	var lock struct{ Package []poetryPkg }
	if _, err := decodeTOML(filepath.Join(dir, name), &lock); err != nil {
		return nil, err
	}
	manifest, err := readPyproject(dir)
	if err != nil {
		return nil, err
	}
	var declared map[string]bool
	if manifest != nil {
		declared = manifest.names()
	}
	pkgs := lock.Package
	byName := map[string][]int{}
	for i, p := range pkgs {
		n := provider.NormalizePyPI(p.Name)
		byName[n] = append(byName[n], i)
	}

	direct := map[int]bool{}
	var prod, dev []int
	for i, p := range pkgs {
		if manifest != nil && !declared[provider.NormalizePyPI(p.Name)] {
			continue
		}
		direct[i] = true
		if p.dev() {
			dev = append(dev, i)
		} else {
			prod = append(prod, i)
		}
	}
	children := func(i int) []int {
		var out []int
		for _, d := range slices.Sorted(maps.Keys(pkgs[i].Dependencies)) {
			out = append(out, byName[provider.NormalizePyPI(d)]...)
		}
		return out
	}
	via, _ := trace(prod, dev, children, func(i int) string { return pkgs[i].Name })

	var out []provider.Package
	for i, p := range pkgs {
		switch p.Source.Type {
		case "git", "directory", "file":
			continue
		}
		pkg := provider.Package{Name: p.Name, Version: p.Version, Dependency: !direct[i], Dev: p.dev()}
		if pkg.Dependency {
			pkg.Via = via[i]
		}
		out = append(out, pkg)
	}
	return out, nil
}

type pyproject struct {
	Project struct {
		Dependencies         []string
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	}
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	BuildSystem      struct {
		BuildBackend string `toml:"build-backend"`
	} `toml:"build-system"`
	Tool struct {
		Poetry *struct {
			Dependencies    map[string]any
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct{ Dependencies map[string]any }
		}
	}
}

// readPyproject reads pyproject.toml, or returns nil when there is none.
func readPyproject(dir string) (*pyproject, error) {
	var p pyproject
	if _, err := decodeTOML(filepath.Join(dir, "pyproject.toml"), &p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("pyproject.toml: %w", err)
	}
	return &p, nil
}

// names are the normalized names of every dependency the project declares,
// in the PEP 621 and PEP 735 tables and in Poetry's own.
func (p *pyproject) names() map[string]bool {
	out := map[string]bool{}
	for _, s := range p.Project.Dependencies {
		out[provider.NormalizePyPI(requirementName(s))] = true
	}
	for _, deps := range p.Project.OptionalDependencies {
		for _, s := range deps {
			out[provider.NormalizePyPI(requirementName(s))] = true
		}
	}
	for _, deps := range p.DependencyGroups {
		for _, d := range deps {
			if s, ok := d.(string); ok {
				out[provider.NormalizePyPI(requirementName(s))] = true
			}
		}
	}
	if poetry := p.Tool.Poetry; poetry != nil {
		tables := []map[string]any{poetry.Dependencies, poetry.DevDependencies}
		for _, g := range poetry.Group {
			tables = append(tables, g.Dependencies)
		}
		for _, t := range tables {
			for n := range t {
				out[provider.NormalizePyPI(n)] = true
			}
		}
		delete(out, "python")
	}
	return out
}

// requirementName is the name at the start of a PEP 508 requirement such as
// "flask[async]>=3" or "requests (==2.31.0)".
func requirementName(s string) string {
	s = strings.TrimSpace(s)
	end := strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.')
	})
	if end < 0 {
		return s
	}
	return s[:end]
}

// pyprojectManager names the tool to lock a pyproject.toml with, or "" when
// it declares no dependencies. Many hold only tool settings, such as ruff's.
func pyprojectManager(dir string) string {
	p, err := readPyproject(dir)
	switch {
	case err != nil:
		return "uv"
	case p == nil || len(p.names()) == 0:
		return ""
	case p.Tool.Poetry != nil || strings.Contains(p.BuildSystem.BuildBackend, "poetry"):
		return "poetry"
	}
	return "uv"
}

// readRequirements reads the lines of a requirements file pinned with ==.
// Ranges, editable installs and included files are left out, since they name
// no single version.
func readRequirements(dir, name string) ([]provider.Package, error) {
	data, err := readFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	lower := strings.ToLower(name)
	dev := strings.Contains(lower, "dev") || strings.Contains(lower, "test")
	var pkgs []provider.Package
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, ";")
		line, _, _ = strings.Cut(line, " --")
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), `\`))
		if strings.HasPrefix(line, "-") {
			continue
		}
		n, v, ok := strings.Cut(line, "==")
		n, _, _ = strings.Cut(n, "[")
		n, v = strings.TrimSpace(n), strings.TrimSpace(strings.TrimPrefix(v, "="))
		if !ok || n == "" || v == "" || strings.ContainsAny(v, "*,<>!~ ") {
			continue
		}
		pkgs = append(pkgs, provider.Package{Name: n, Version: v, Dev: dev})
	}
	return pkgs, nil
}
