package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/vuon9/kho/internal/vuln"
)

// latestURL is where a package's registry says its newest version, by OSV
// ecosystem, or "" when kho doesn't know one.
func latestURL(p Package) string {
	switch Ecosystem(p) {
	case "npm":
		return "https://registry.npmjs.org/-/package/" + segments(p.Name) + "/dist-tags"
	case "PyPI":
		return "https://pypi.org/pypi/" + url.PathEscape(NormalizePyPI(p.Name)) + "/json"
	case "Go":
		// Module paths have a fixed alphabet, and the proxy needs its "!".
		if m := escapeModule(p.Origin); goModule.MatchString(m) && !strings.Contains("/"+m+"/", "/../") {
			return "https://proxy.golang.org/" + m + "/@latest"
		}
	case "crates.io":
		return "https://crates.io/api/v1/crates/" + url.PathEscape(p.Name)
	case "Packagist":
		return packagistURL(p.Name)
	}
	return ""
}

var goModule = regexp.MustCompile(`^[a-z0-9._~!/-]+$`)

// segments escapes each part of a slash separated name, so a name read from
// a project's lockfile, such as "../x?y", stays one name in a registry URL.
func segments(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
		if p == "." || p == ".." {
			parts[i] = strings.Repeat("%2E", len(p))
		}
	}
	return strings.Join(parts, "/")
}

func packagistURL(name string) string {
	return "https://repo.packagist.org/p2/" + segments(name) + ".json"
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

// newestStable is the highest release that isn't a preview like
// 3.0.0-beta1. It goes by version, not date, since a backport to an older
// line is often published after the newest release.
func newestStable(rels []Release) string {
	best := ""
	for _, r := range rels {
		if strings.ContainsAny(r.Version, "-@") || strings.Contains(strings.ToLower(r.Version), "dev") {
			continue
		}
		if best == "" || vuln.Compare(TagVersion(r.Version), TagVersion(best)) > 0 {
			best = r.Version
		}
	}
	return best
}

// MaxLatest caps the registry lookups one project can cause.
var MaxLatest = 200

// FillLatest looks up the newest version of every direct package in pkgs,
// up to MaxLatest. Transitive ones are left alone: a project can have a
// thousand, and the direct ones are what a person upgrades.
func FillLatest(ctx context.Context, pkgs []Package) []Package {
	var direct []Package
	var at []int
	for i, p := range pkgs {
		if p.Dependency {
			continue
		}
		if len(direct) == MaxLatest {
			pkgs[i].Note = fmt.Sprintf("latest not looked up: kho asks about %d direct packages at most", MaxLatest)
			continue
		}
		direct, at = append(direct, p), append(at, i)
	}
	direct = fillLatest(ctx, direct, RegistryLatest)
	for j, i := range at {
		pkgs[i] = direct[j]
	}
	return pkgs
}

// RegistryVersions lists a project package's published versions straight
// from its registry, newest first. npm's are read from the registry's own
// document rather than `npm view`, which would load the project's .npmrc.
func RegistryVersions(ctx context.Context, p Package) ([]Release, error) {
	if latestURL(p) == "" {
		return nil, fmt.Errorf("kho has no version list for %s packages yet", p.Source)
	}
	switch Ecosystem(p) {
	case "npm":
		var raw json.RawMessage
		if err := getJSON(ctx, "https://registry.npmjs.org/"+segments(p.Name), nil, &raw); err != nil {
			return nil, err
		}
		rels, repo, err := parseNpmView(p.Name, raw)
		if err != nil {
			return nil, err
		}
		return withNotes(ctx, repo, rels), nil
	case "PyPI":
		return pypiVersions(ctx, NormalizePyPI(p.Name))
	case "Go":
		return GoBin{}.Versions(ctx, p)
	case "Packagist":
		return Composer{}.Versions(ctx, p)
	}
	return nil, fmt.Errorf("kho has no version list for %s packages yet", p.Source)
}
