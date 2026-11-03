package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type Mise struct{}

func (Mise) Name() string    { return "mise" }
func (Mise) Available() bool { return onPath("mise") }

func (Mise) List(ctx context.Context) ([]Package, error) {
	out, err := run(ctx, "mise", "ls", "--json")
	if err != nil {
		return nil, err
	}
	return parseMiseList(out)
}

// mise only reports tools that a config file asks for, so a tool that is
// installed but not configured keeps an unknown latest.
func (Mise) Latest(ctx context.Context, pkgs []Package) ([]Package, error) {
	out, err := run(ctx, "mise", "outdated", "--json")
	if err != nil {
		return pkgs, err
	}
	latest, err := parseMiseOutdated(out)
	if err != nil {
		return pkgs, err
	}
	for i := range pkgs {
		if v, ok := latest[pkgs[i].Name]; ok {
			pkgs[i].Latest = v
			markOutdated(&pkgs[i])
		}
	}
	return pkgs, nil
}

func parseMiseList(data []byte) ([]Package, error) {
	var ls map[string][]struct {
		Version     string `json:"version"`
		InstallPath string `json:"install_path"`
		Installed   bool   `json:"installed"`
		Active      bool   `json:"active"`
	}
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("mise ls: %w", err)
	}
	var pkgs []Package
	for tool, versions := range ls {
		p := Package{Source: "mise", Name: tool}
		for _, v := range versions {
			if !v.Installed {
				continue
			}
			p.Versions = append(p.Versions, v.Version)
			if v.Active || p.Version == "" {
				p.Version, p.Path = v.Version, v.InstallPath
			}
		}
		if p.Version == "" {
			continue
		}
		if len(p.Versions) == 1 {
			p.Versions = nil
		}
		pkgs = append(pkgs, p)
	}
	sortByName(pkgs)
	return pkgs, nil
}

func parseMiseOutdated(data []byte) (map[string]string, error) {
	var out map[string]struct {
		Latest string `json:"latest"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("mise outdated: %w", err)
	}
	latest := make(map[string]string, len(out))
	for tool, o := range out {
		latest[tool] = o.Latest
	}
	return latest, nil
}

func (Mise) Deps(context.Context, Package) ([]Dep, error) { return nil, nil }

func (Mise) Versions(ctx context.Context, p Package) ([]Release, error) {
	out, err := run(ctx, "mise", "ls-remote", p.Name)
	if err != nil {
		return nil, err
	}
	var rels []Release
	for _, v := range slices.Backward(strings.Fields(string(out))) {
		rels = append(rels, Release{Version: v})
	}
	return rels, nil
}
