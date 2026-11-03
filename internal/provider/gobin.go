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
	"strings"

	"golang.org/x/mod/semver"
)

type GoBin struct{}

func (GoBin) Name() string { return "go" }

func (GoBin) Available() bool {
	_, err := os.Stat(goBinDir())
	return err == nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://proxy.golang.org/"+escapeModule(p.Origin)+"/@v/list", nil)
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
