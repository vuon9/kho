package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type Pipx struct{}

func (Pipx) Name() string    { return "pipx" }
func (Pipx) Missing() string { return notOnPath("pipx") }

func (Pipx) List(ctx context.Context) ([]Package, error) {
	out, err := run(ctx, "pipx", "list", "--json")
	if err != nil {
		return nil, err
	}
	return parsePipx(out)
}

func (Pipx) Latest(ctx context.Context, pkgs []Package) ([]Package, error) {
	return fillLatest(ctx, pkgs, func(ctx context.Context, p Package) (string, error) { return pypiLatest(ctx, p.Name) }), nil
}

func parsePipx(data []byte) ([]Package, error) {
	var ls struct {
		Venvs map[string]struct {
			Metadata struct {
				MainPackage struct {
					Package        string   `json:"package"`
					PackageVersion string   `json:"package_version"`
					Pinned         bool     `json:"pinned"`
					Apps           []string `json:"apps"`
				} `json:"main_package"`
				PythonVersion string `json:"python_version"`
			} `json:"metadata"`
		} `json:"venvs"`
	}
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("pipx list: %w", err)
	}
	var pkgs []Package
	for _, v := range ls.Venvs {
		m := v.Metadata.MainPackage
		pkgs = append(pkgs, Package{
			Source:  "pipx",
			Name:    m.Package,
			Version: m.PackageVersion,
			Pinned:  m.Pinned,
			Origin:  "pypi.org",
			Desc:    "apps: " + strings.Join(m.Apps, ", ") + " · " + v.Metadata.PythonVersion,
		})
	}
	sortByName(pkgs)
	return pkgs, nil
}

type Uv struct{}

func (Uv) Name() string    { return "uv" }
func (Uv) Missing() string { return notOnPath("uv") }

func (Uv) List(ctx context.Context) ([]Package, error) {
	out, err := run(ctx, "uv", "tool", "list")
	if err != nil {
		return nil, err
	}
	return parseUvList(string(out)), nil
}

func (Uv) Latest(ctx context.Context, pkgs []Package) ([]Package, error) {
	return fillLatest(ctx, pkgs, func(ctx context.Context, p Package) (string, error) { return pypiLatest(ctx, p.Name) }), nil
}

// parseUvList reads `uv tool list`, where each tool is a "name vX.Y" line
// followed by "- app" lines for its executables.
func parseUvList(out string) []Package {
	var pkgs []Package
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] == "-" || !strings.HasPrefix(f[1], "v") {
			continue
		}
		pkgs = append(pkgs, Package{Source: "uv", Name: f[0], Version: strings.TrimPrefix(f[1], "v"), Origin: "pypi.org"})
	}
	return pkgs
}

func (Pipx) Deps(ctx context.Context, p Package) ([]Dep, error) {
	out, err := run(ctx, "pipx", "runpip", p.Name, "list", "--format=json")
	if err != nil {
		return nil, err
	}
	return parsePipList(p.Name, out)
}

func (Pipx) Versions(ctx context.Context, p Package) ([]Release, error) {
	return pypiVersions(ctx, p.Name)
}

func (Uv) Deps(ctx context.Context, p Package) ([]Dep, error) {
	dir, err := run(ctx, "uv", "tool", "dir")
	if err != nil {
		return nil, err
	}
	python := filepath.Join(strings.TrimSpace(string(dir)), p.Name, "bin", "python")
	out, err := run(ctx, "uv", "pip", "list", "--python", python, "--format", "json")
	if err != nil {
		return nil, err
	}
	return parsePipList(p.Name, out)
}

func (Uv) Versions(ctx context.Context, p Package) ([]Release, error) {
	return pypiVersions(ctx, p.Name)
}

// parsePipList reads everything installed in a tool's own environment, which
// is the tool's full dependency tree. pip itself is tooling, not a dependency.
func parsePipList(self string, data []byte) ([]Dep, error) {
	var list []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("pip list: %w", err)
	}
	var deps []Dep
	for _, d := range list {
		if !strings.EqualFold(d.Name, self) && d.Name != "pip" {
			deps = append(deps, Dep{Name: d.Name, Version: d.Version})
		}
	}
	return deps, nil
}

func pypiVersions(ctx context.Context, name string) ([]Release, error) {
	var r pypiProject
	if err := getJSON(ctx, pypiSite+"/pypi/"+name+"/json", nil, &r); err != nil {
		return nil, err
	}
	rels, repo := r.releases(name)
	return withNotes(ctx, repo, rels), nil
}

type pypiProject struct {
	Info struct {
		ProjectURLs map[string]string `json:"project_urls"`
		HomePage    string            `json:"home_page"`
	} `json:"info"`
	Releases map[string][]struct {
		UploadTime time.Time `json:"upload_time_iso_8601"`
		Yanked     bool      `json:"yanked"`
	} `json:"releases"`
}

func (r pypiProject) releases(name string) ([]Release, string) {
	var rels []Release
	for v, files := range r.Releases {
		if len(files) == 0 || files[0].Yanked {
			continue
		}
		rels = append(rels, Release{Version: v, Date: files[0].UploadTime, URL: pypiSite + "/project/" + name + "/" + v + "/"})
	}
	newestFirst(rels)
	urls := []string{r.Info.HomePage}
	for _, k := range slices.Sorted(maps.Keys(r.Info.ProjectURLs)) {
		urls = append(urls, r.Info.ProjectURLs[k])
	}
	return rels, githubRepo(urls...)
}
