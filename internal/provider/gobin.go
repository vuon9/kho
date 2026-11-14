package provider

import (
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

type GoBin struct{}

func (GoBin) Name() string { return "go" }

func (GoBin) Missing() string {
	if _, err := os.Stat(goBinDir()); err != nil {
		return "no Go binary directory"
	}
	return ""
}

func goBinDir() string {
	if d := os.Getenv("GOBIN"); d != "" {
		return d
	}
	if d := os.Getenv("GOPATH"); d != "" {
		return filepath.Join(filepath.SplitList(d)[0], "bin")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "go", "bin")
}

// majorProbe reports whether a module path serves a version. Tests swap it.
var majorProbe = func(ctx context.Context, path, version string) bool {
	url := goProxy + "/" + escapeModule(path) + "/@v/" + escapeModule(version) + ".info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// MajorModule is the module path of a higher major that serves version, when a
// Go tool outgrows v1. Every major keeps its own path, so the module an
// installed binary reports never lists the releases above it: a tool installed
// from v1 looks like it has no newer version while its whole v2 line lives at
// /v2.
func MajorModule(ctx context.Context, origin, version string) string {
	if origin == "" || version == "" {
		return ""
	}
	from := 2
	base := origin
	if i := strings.LastIndexByte(origin, '/'); i >= 0 {
		if n, err := strconv.Atoi(strings.TrimPrefix(origin[i+1:], "v")); err == nil && n >= 2 {
			base, from = origin[:i], n+1
		}
	}
	for n := from; n <= from+2; n++ {
		path := base + "/v" + strconv.Itoa(n)
		if majorProbe(ctx, path, version) {
			return path
		}
	}
	return ""
}

func (GoBin) List(context.Context) ([]Package, error) {
	dir := goBinDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		bi, err := buildinfo.ReadFile(path)
		if err != nil {
			continue
		}
		p := Package{
			Source:  "go",
			Name:    e.Name(),
			Version: bi.Main.Version,
			Origin:  bi.Main.Path,
			Desc:    bi.Path + " · built with " + bi.GoVersion,
			Path:    path,
			Repo:    githubRepo(bi.Main.Path),
			Entry:   bi.Path,
		}
		for _, d := range bi.Deps {
			p.Deps = append(p.Deps, Dep{Name: d.Path, Version: d.Version})
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func (GoBin) Latest(ctx context.Context, pkgs []Package) ([]Package, error) {
	return fillLatest(ctx, pkgs, func(ctx context.Context, p Package) (string, error) {
		if p.Version == "(devel)" || p.Version == "" {
			return "", errors.New("local build")
		}
		return goProxyLatest(ctx, p.Origin)
	}), nil
}

func (GoBin) Deps(_ context.Context, p Package) ([]Dep, error) { return p.Deps, nil }

func (GoBin) Versions(ctx context.Context, p Package) ([]Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, goProxy+"/"+escapeModule(p.Origin)+"/@v/list", nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go proxy: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	versions := strings.Fields(string(body))
	slices.SortFunc(versions, func(a, b string) int { return semver.Compare(b, a) })
	var rels []Release
	for _, v := range versions {
		rels = append(rels, Release{Version: v, URL: "https://pkg.go.dev/" + p.Origin + "@" + v})
	}
	return withNotes(ctx, p.Repo, rels), nil
}

// Find resolves an exact Go package path through the module proxy. The proxy
// knows module paths, so a path inside a module can still fail here; the
// install command is the final check for those.
func (GoBin) Find(ctx context.Context, source, name string) (Package, error) {
	if source != "" && source != "go" {
		return Package{}, fmt.Errorf("go doesn't serve the %s source", source)
	}
	path := strings.TrimSpace(name)
	if path == "" || strings.ContainsAny(path, " \t") {
		return Package{}, fmt.Errorf("a Go install needs a package or module path")
	}
	var r struct {
		Version string `json:"Version"`
		Origin  struct {
			URL string `json:"URL"`
		} `json:"Origin"`
	}
	if err := getJSON(ctx, goProxy+"/"+escapeModule(path)+"/@latest", nil, &r); err != nil {
		return Package{}, fmt.Errorf("no Go module at %s", path)
	}
	if r.Version == "" {
		return Package{}, fmt.Errorf("no Go module at %s", path)
	}
	return Package{Source: "go", Name: goBinName(path), Latest: r.Version, Origin: path, Entry: path,
		Repo: githubRepo(r.Origin.URL, path)}, nil
}

// goBinName is the last path segment, or the one before a major version suffix:
// example.com/tool/v2 installs a binary named tool.
func goBinName(path string) string {
	parts := strings.Split(path, "/")
	base := parts[len(parts)-1]
	if isMajorSegment(base) && len(parts) > 1 {
		base = parts[len(parts)-2]
	}
	return base
}

func isMajorSegment(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
