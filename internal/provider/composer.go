package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Composer struct{}

func (Composer) Name() string    { return "composer" }
func (Composer) Missing() string { return notOnPath("composer") }

func (Composer) List(ctx context.Context) ([]Package, error) {
	flat, err := composerShow(ctx)
	if err != nil || flat == nil {
		return nil, err
	}
	tree, err := composerShow(ctx, "--tree")
	if err != nil || tree == nil {
		return nil, err
	}
	return parseComposer(flat, tree)
}

// composerShow returns nil when there is no global composer.json, which
// Composer writes on the first global require.
func composerShow(ctx context.Context, args ...string) ([]byte, error) {
	out, err := run(ctx, "composer", slices.Concat([]string{"global", "show"}, args, []string{"--format=json", "--no-plugins", "--no-scripts"})...)
	if err != nil && strings.Contains(err.Error(), "could not find a composer.json") {
		return nil, nil
	}
	return out, err
}

func (Composer) Latest(ctx context.Context, pkgs []Package) ([]Package, error) {
	// With nothing required, outdated prints [] instead of an object, or fails
	// when there is no global composer.json.
	if len(pkgs) == 0 {
		return pkgs, nil
	}
	out, err := run(ctx, "composer", "global", "outdated", "--direct", "--format=json", "--no-plugins", "--no-scripts")
	if err != nil {
		return pkgs, err
	}
	latest, err := parseComposerOutdated(out)
	if err != nil {
		return pkgs, err
	}
	for i := range pkgs {
		if pkgs[i].Dependency {
			continue
		}
		pkgs[i].Latest = pkgs[i].Version
		if v, ok := latest[pkgs[i].Name]; ok {
			pkgs[i].Latest = v
		}
		markOutdated(&pkgs[i])
	}
	return pkgs, nil
}

type composerRequire struct {
	Name     string            `json:"name"`
	Requires []composerRequire `json:"requires"`
}

// parseComposer takes every installed package from the flat `composer show`
// and only the graph from `--tree`, which names no installed versions before
// Composer 2.11.
func parseComposer(flat, tree []byte) ([]Package, error) {
	// With nothing required, Composer prints [] instead of an object.
	if string(bytes.TrimSpace(flat)) == "[]" {
		return nil, nil
	}
	var show struct {
		Installed []struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
		} `json:"installed"`
	}
	if err := json.Unmarshal(flat, &show); err != nil {
		return nil, fmt.Errorf("composer show: %w", err)
	}
	var graph struct {
		Installed []composerRequire `json:"installed"`
	}
	if err := json.Unmarshal(tree, &graph); err != nil {
		return nil, fmt.Errorf("composer show --tree: %w", err)
	}
	version := map[string]string{}
	for _, p := range show.Installed {
		version[p.Name] = p.Version
	}
	type step struct {
		req composerRequire
		via []string
	}
	var queue []step
	direct := map[string][]Dep{}
	for _, d := range graph.Installed {
		var deps []Dep
		for _, r := range d.Requires {
			if composerPackage(r.Name) {
				deps = append(deps, Dep{Name: r.Name, Version: version[r.Name], Direct: true})
				queue = append(queue, step{r, []string{d.Name}})
			}
		}
		direct[d.Name] = deps
	}
	// Breadth first, so the first chain to reach a package is the shortest.
	via := map[string][]string{}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		_, isDirect := direct[s.req.Name]
		_, reached := via[s.req.Name]
		if isDirect || reached {
			continue
		}
		via[s.req.Name] = s.via
		for _, r := range s.req.Requires {
			if composerPackage(r.Name) {
				queue = append(queue, step{r, append(slices.Clone(s.via), s.req.Name)})
			}
		}
	}
	var pkgs []Package
	for _, p := range show.Installed {
		deps, isDirect := direct[p.Name]
		pkgs = append(pkgs, Package{Source: "composer", Name: p.Name, Version: p.Version, Dependency: !isDirect,
			Origin: "packagist.org", Desc: p.Description, Deps: deps, Via: via[p.Name]})
	}
	sortByName(pkgs)
	return pkgs, nil
}

// composerPackage tells a package from a platform requirement such as php,
// ext-json or composer-plugin-api, which has no vendor.
func composerPackage(name string) bool { return strings.Contains(name, "/") }

func parseComposerOutdated(data []byte) (map[string]string, error) {
	var out struct {
		Installed []struct {
			Name   string `json:"name"`
			Latest string `json:"latest"`
		} `json:"installed"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("composer outdated: %w", err)
	}
	latest := make(map[string]string, len(out.Installed))
	for _, o := range out.Installed {
		latest[o.Name] = o.Latest
	}
	return latest, nil
}

func (Composer) Deps(_ context.Context, p Package) ([]Dep, error) { return p.Deps, nil }

func (Composer) Versions(ctx context.Context, p Package) ([]Release, error) {
	var raw json.RawMessage
	if err := getJSON(ctx, "https://repo.packagist.org/p2/"+p.Name+".json", nil, &raw); err != nil {
		return nil, err
	}
	rels, repo, err := parsePackagist(p.Name, raw)
	if err != nil {
		return nil, err
	}
	return withNotes(ctx, repo, rels), nil
}

func parsePackagist(name string, data []byte) ([]Release, string, error) {
	var meta struct {
		Packages map[string][]struct {
			Version  string  `json:"version"`
			Time     *string `json:"time"`
			Homepage string  `json:"homepage"`
			// source is an object, or "__unset" in a later version.
			Source any `json:"source"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, "", fmt.Errorf("packagist: %w", err)
	}
	versions := meta.Packages[name]
	var rels []Release
	var date time.Time
	for _, v := range versions {
		// Packagist leaves out a field that equals the one in the version
		// before, and "__unset" (which parses as no date) removes it.
		if v.Time != nil {
			t, _ := time.Parse(time.RFC3339, *v.Time)
			date = t.UTC()
		}
		rels = append(rels, Release{Version: v.Version, Date: date, URL: "https://packagist.org/packages/" + name + "#" + v.Version})
	}
	newestFirst(rels)
	if len(versions) == 0 {
		return rels, "", nil
	}
	src, _ := versions[0].Source.(map[string]any)
	url, _ := src["url"].(string)
	return rels, githubRepo(url, versions[0].Homepage), nil
}
