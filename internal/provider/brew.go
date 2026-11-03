package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

type Brew struct{}

func (Brew) Name() string    { return "brew" }
func (Brew) Available() bool { return onPath("brew") }

func (Brew) List(ctx context.Context) ([]Package, error) {
	out, err := run(ctx, "brew", "info", "--json=v2", "--installed")
	if err != nil {
		return nil, err
	}
	return parseBrew(out)
}

// brew info already knows the latest version from its local API cache.
func (Brew) Latest(_ context.Context, pkgs []Package) ([]Package, error) { return pkgs, nil }

type brewInfo struct {
	Formulae []struct {
		Name      string `json:"name"`
		Tap       string `json:"tap"`
		Desc      string `json:"desc"`
		Homepage  string `json:"homepage"`
		Pinned    bool   `json:"pinned"`
		Outdated  bool   `json:"outdated"`
		LinkedKeg string `json:"linked_keg"`
		Revision  int    `json:"revision"`
		Versions  struct {
			Stable string `json:"stable"`
		} `json:"versions"`
		URLs struct {
			Stable struct {
				URL string `json:"url"`
			} `json:"stable"`
		} `json:"urls"`
		Installed []struct {
			Version             string `json:"version"`
			InstalledOnRequest  bool   `json:"installed_on_request"`
			RuntimeDependencies []struct {
				FullName         string `json:"full_name"`
				PkgVersion       string `json:"pkg_version"`
				DeclaredDirectly bool   `json:"declared_directly"`
			} `json:"runtime_dependencies"`
		} `json:"installed"`
	} `json:"formulae"`
	Casks []struct {
		Token       string `json:"token"`
		Tap         string `json:"tap"`
		Desc        string `json:"desc"`
		Homepage    string `json:"homepage"`
		Version     string `json:"version"`
		Installed   string `json:"installed"`
		Outdated    bool   `json:"outdated"`
		AutoUpdates bool   `json:"auto_updates"`
	} `json:"casks"`
}

func parseBrew(data []byte) ([]Package, error) {
	var info brewInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("brew info: %w", err)
	}
	var pkgs []Package
	for _, f := range info.Formulae {
		if len(f.Installed) == 0 {
			continue
		}
		p := Package{
			Source:     "brew",
			Name:       f.Name,
			Version:    f.LinkedKeg,
			Latest:     f.Versions.Stable,
			Outdated:   f.Outdated,
			Pinned:     f.Pinned,
			Dependency: true,
			Origin:     f.Tap,
			Desc:       f.Desc,
			Homepage:   f.Homepage,
			Repo:       githubRepo(f.URLs.Stable.URL, f.Homepage),
		}
		if f.Revision > 0 {
			p.Latest = fmt.Sprintf("%s_%d", p.Latest, f.Revision)
		}
		for _, in := range f.Installed {
			if in.InstalledOnRequest {
				p.Dependency = false
			}
			if len(f.Installed) > 1 {
				p.Versions = append(p.Versions, in.Version)
			}
		}
		if p.Version == "" {
			p.Version = f.Installed[len(f.Installed)-1].Version
		}
		for _, in := range f.Installed {
			if in.Version != p.Version {
				continue
			}
			for _, d := range in.RuntimeDependencies {
				p.Deps = append(p.Deps, Dep{Name: d.FullName, Version: d.PkgVersion, Direct: d.DeclaredDirectly})
			}
		}
		pkgs = append(pkgs, p)
	}
	for _, c := range info.Casks {
		p := Package{
			Source:   "cask",
			Name:     c.Token,
			Version:  c.Installed,
			Latest:   c.Version,
			Outdated: c.Outdated,
			Origin:   c.Tap,
			Desc:     c.Desc,
			Homepage: c.Homepage,
			Repo:     githubRepo(c.Homepage),
		}
		if c.AutoUpdates {
			p.Note = "updates itself"
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func (Brew) Deps(_ context.Context, p Package) ([]Dep, error) { return p.Deps, nil }

// Homebrew keeps no version history, so the GitHub releases of the formula's
// source repo stand in for it. Without a repo, the known versions remain.
func (Brew) Versions(ctx context.Context, p Package) ([]Release, error) {
	if p.Repo != "" {
		if rels, err := githubReleases(ctx, p.Repo); err == nil && len(rels) > 0 {
			return rels, nil
		}
	}
	rels := []Release{{Version: p.Latest, URL: p.Homepage}}
	for _, v := range slices.Backward(p.Versions) {
		if v != p.Latest {
			rels = append(rels, Release{Version: v, URL: p.Homepage})
		}
	}
	if len(p.Versions) == 0 && p.Version != p.Latest {
		rels = append(rels, Release{Version: p.Version, URL: p.Homepage})
	}
	return rels, nil
}
