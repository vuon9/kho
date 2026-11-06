package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// latestURL is where a package's registry says its newest version, by OSV
// ecosystem, or "" when kho doesn't know one.
func latestURL(p Package) string {
	switch Ecosystem(p) {
	case "npm":
		return "https://registry.npmjs.org/-/package/" + p.Name + "/dist-tags"
	case "PyPI":
		return "https://pypi.org/pypi/" + NormalizePyPI(p.Name) + "/json"
	case "Go":
		return "https://proxy.golang.org/" + escapeModule(p.Origin) + "/@latest"
	case "crates.io":
		return "https://crates.io/api/v1/crates/" + url.PathEscape(p.Name)
	case "Packagist":
		return "https://repo.packagist.org/p2/" + p.Name + ".json"
	}
	return ""
}

// RegistryLatest asks a package's registry for its newest version. Project
// packages use it, since kho never runs a project's own tools.
func RegistryLatest(ctx context.Context, p Package) (string, error) {
	u := latestURL(p)
	if u == "" {
		return "", fmt.Errorf("no registry for %s", p.Source)
	}
	switch Ecosystem(p) {
	case "npm":
		var tags struct{ Latest string }
		err := getJSON(ctx, u, nil, &tags)
		return tags.Latest, err
	case "PyPI":
		return pypiLatest(ctx, NormalizePyPI(p.Name))
	case "Go":
		return goProxyLatest(ctx, p.Origin)
	case "crates.io":
		// crates.io refuses requests that don't say who is asking.
		var c struct {
			Crate struct {
				MaxStableVersion string `json:"max_stable_version"`
			} `json:"crate"`
		}
		err := getJSON(ctx, u, http.Header{"User-Agent": {"kho (https://github.com/vuon9/kho)"}}, &c)
		return c.Crate.MaxStableVersion, err
	case "Packagist":
		var raw json.RawMessage
		if err := getJSON(ctx, u, nil, &raw); err != nil {
			return "", err
		}
		rels, _, err := parsePackagist(p.Name, raw)
		return newestStable(rels), err
	}
	return "", nil
}

// newestStable is the newest release that isn't a preview like 3.0.0-beta1,
// from a list that is newest first.
func newestStable(rels []Release) string {
	for _, r := range rels {
		if !strings.ContainsAny(r.Version, "-@") && !strings.Contains(strings.ToLower(r.Version), "dev") {
			return r.Version
		}
	}
	return ""
}

// FillLatest looks up the newest version of every direct package in pkgs.
// Transitive ones are left alone: a project can have a thousand, and the
// direct ones are what a person upgrades.
func FillLatest(ctx context.Context, pkgs []Package) []Package {
	var direct []Package
	var at []int
	for i, p := range pkgs {
		if !p.Dependency {
			direct, at = append(direct, p), append(at, i)
		}
	}
	direct = fillLatest(ctx, direct, RegistryLatest)
	for j, i := range at {
		pkgs[i] = direct[j]
	}
	return pkgs
}
