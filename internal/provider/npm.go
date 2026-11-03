package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Npm struct{}

func (Npm) Name() string    { return "npm" }
func (Npm) Available() bool { return onPath("npm") }

func (Npm) List(ctx context.Context) ([]Package, error) {
	out, err := run(ctx, "npm", "ls", "-g", "--json", "--depth=1")
	if err != nil {
		return nil, err
	}
	return parseNpmList(out)
}

func (Npm) Latest(ctx context.Context, pkgs []Package) ([]Package, error) {
	out, err := run(ctx, "npm", "outdated", "-g", "--json")
	if err != nil {
		return pkgs, err
	}
	latest, err := parseNpmOutdated(out)
	if err != nil {
		return pkgs, err
	}
	for i := range pkgs {
		pkgs[i].Latest = pkgs[i].Version
		if v, ok := latest[pkgs[i].Name]; ok {
			pkgs[i].Latest = v
		}
		markOutdated(&pkgs[i])
	}
	return pkgs, nil
}

func parseNpmList(data []byte) ([]Package, error) {
	type node struct {
		Version      string          `json:"version"`
		Dependencies map[string]node `json:"dependencies"`
	}
	var ls node
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("npm ls: %w", err)
	}
	var pkgs []Package
	for name, d := range ls.Dependencies {
		p := Package{Source: "npm", Name: name, Version: d.Version, Origin: "npmjs.com"}
		for dep, n := range d.Dependencies {
			p.Deps = append(p.Deps, Dep{Name: dep, Version: n.Version, Direct: true})
		}
		slices.SortFunc(p.Deps, func(a, b Dep) int { return strings.Compare(a.Name, b.Name) })
		pkgs = append(pkgs, p)
	}
	sortByName(pkgs)
	return pkgs, nil
}

func parseNpmOutdated(data []byte) (map[string]string, error) {
	var out map[string]struct {
		Latest string `json:"latest"`
	}
	if len(data) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("npm outdated: %w", err)
	}
	latest := make(map[string]string, len(out))
	for name, o := range out {
		latest[name] = o.Latest
	}
	return latest, nil
}

func (Npm) Deps(_ context.Context, p Package) ([]Dep, error) { return p.Deps, nil }

func (Npm) Versions(ctx context.Context, p Package) ([]Release, error) {
	out, err := run(ctx, "npm", "view", p.Name, "time", "repository", "--json")
	if err != nil {
		return nil, err
	}
	rels, repo, err := parseNpmView(p.Name, out)
	if err != nil {
		return nil, err
	}
	return withNotes(ctx, repo, rels), nil
}

func parseNpmView(name string, data []byte) ([]Release, string, error) {
	var view struct {
		Time       map[string]time.Time `json:"time"`
		Repository any                  `json:"repository"`
	}
	if err := json.Unmarshal(data, &view); err != nil {
		return nil, "", fmt.Errorf("npm view: %w", err)
	}
	var rels []Release
	for v, t := range view.Time {
		if v != "created" && v != "modified" {
			rels = append(rels, Release{Version: v, Date: t, URL: "https://www.npmjs.com/package/" + name + "/v/" + v})
		}
	}
	newestFirst(rels)
	// repository is either {"url": "..."} or a shorthand like "github:owner/name".
	repo := ""
	switch r := view.Repository.(type) {
	case map[string]any:
		u, _ := r["url"].(string)
		repo = githubRepo(u)
	case string:
		repo = githubRepo(strings.Replace(r, "github:", "github.com/", 1))
	}
	return rels, repo, nil
}
