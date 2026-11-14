package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Npm struct{}

func (Npm) Name() string    { return "npm" }
func (Npm) Missing() string { return notOnPath("npm") }

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

// Search finds packages by keyword through the npm CLI, which reads the
// registry's search endpoint.
func (Npm) Search(ctx context.Context, query string, limit int) ([]Package, error) {
	limit = searchLimit(limit)
	out, err := run(ctx, "npm", "search", "--json", "--searchlimit="+itoa(limit), query)
	if err != nil {
		return nil, err
	}
	return parseNpmSearch(out, limit)
}

func parseNpmSearch(data []byte, limit int) ([]Package, error) {
	var rows []struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
		Links       struct {
			Homepage   string `json:"homepage"`
			Repository string `json:"repository"`
		} `json:"links"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("npm search: %w", err)
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	var pkgs []Package
	for _, r := range rows {
		pkgs = append(pkgs, Package{Source: "npm", Name: r.Name, Latest: r.Version, Desc: r.Description,
			Homepage: r.Links.Homepage, Repo: githubRepo(r.Links.Repository), Origin: "npmjs.com"})
	}
	return pkgs, nil
}

// Find looks one package up in the npm registry, which works for a package the
// machine does not have.
func (Npm) Find(ctx context.Context, source, name string) (Package, error) {
	if source != "" && source != "npm" {
		return Package{}, fmt.Errorf("npm doesn't serve the %s source", source)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Package{}, fmt.Errorf("no npm package name given")
	}
	var doc struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Homepage    string `json:"homepage"`
		Repository  any    `json:"repository"`
		DistTags    struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
	}
	if err := getJSON(ctx, npmRegistry+"/"+segments(name), nil, &doc); err != nil {
		return Package{}, fmt.Errorf("no npm package named %s", name)
	}
	if doc.DistTags.Latest == "" {
		return Package{}, fmt.Errorf("npm has no published version of %s", name)
	}
	if doc.Name == "" {
		doc.Name = name
	}
	return Package{Source: "npm", Name: doc.Name, Latest: doc.DistTags.Latest, Desc: doc.Description,
		Homepage: doc.Homepage, Repo: githubRepo(repositoryURL(doc.Repository)), Origin: "npmjs.com"}, nil
}

// repositoryURL reads npm's repository field, which is a URL or an object with
// a url, and drops the git+ prefix.
func repositoryURL(v any) string {
	switch r := v.(type) {
	case string:
		return strings.TrimPrefix(r, "git+")
	case map[string]any:
		u, _ := r["url"].(string)
		return strings.TrimPrefix(u, "git+")
	}
	return ""
}

// itoa is local because npm's JSON flags take a bare number.
func itoa(n int) string { return strconv.Itoa(n) }
