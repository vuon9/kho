package provider

import (
	"regexp"
	"strings"

	"github.com/vuon9/kho/internal/vuln"
)

// Ecosystem names the OSV database that covers the package, or "" when OSV
// has none, as for Homebrew formulae, mise tools and skills.
func Ecosystem(p Package) string {
	switch p.Source {
	case "npm":
		return vuln.NPM
	case "pipx", "uv", "poetry", "pip":
		return vuln.PyPI
	case "go":
		return vuln.Go
	case "composer":
		return vuln.Packagist
	case "cargo":
		return vuln.CratesIO
	}
	return ""
}

// OSVName is the package's name in its OSV ecosystem. Go binaries are known
// by their module path.
func OSVName(p Package) string {
	switch Ecosystem(p) {
	case vuln.Go:
		return p.Origin
	case vuln.PyPI:
		return NormalizePyPI(p.Name)
	}
	return p.Name
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

var brewRevision = regexp.MustCompile(`_\d+$`)

// BrewVersion is an installed formula version without the revision brew
// appends, as in 4.0.0_1. Homebrew's scan reports the upstream form.
func BrewVersion(v string) string {
	return brewRevision.ReplaceAllString(v, "")
}

// BrewQuery is the cache key for the formula Homebrew's own scan assessed.
// OSV has no ecosystem for brew, so this query stays away from vuln.Scan.
func BrewQuery(p Package) (vuln.Query, bool) {
	if p.Source != "brew" {
		return vuln.Query{}, false
	}
	return vuln.Query{Ecosystem: vuln.Homebrew, Name: p.Name, Version: BrewVersion(p.Version)}, true
}

// BrewQueries are the cache keys for the installed Homebrew formulae.
func BrewQueries(pkgs []Package) []vuln.Query {
	var qs []vuln.Query
	for _, p := range pkgs {
		if q, ok := BrewQuery(p); ok {
			qs = append(qs, q)
		}
	}
	return qs
}

// Coverage says why kho has no advisories for p when a source does not cover
// it at all, or "" when it does.
func Coverage(p Package) string {
	if p.Source == "cask" {
		return "Homebrew scans formulae, not casks"
	}
	return ""
}

// NormalizePyPI is a Python package's standard name (PEP 503), the form OSV
// and PyPI index it under: "Foo_Bar" becomes "foo-bar".
func NormalizePyPI(name string) string {
	return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
}

// Released says whether v is a published version OSV can know about. A Go
// module built from a local checkout has "(devel)" or no version at all.
func Released(v string) bool {
	return v != "" && v != "(devel)"
}

// Query is the OSV query for the installed version, if there is one to ask.
func Query(p Package) (vuln.Query, bool) {
	eco := Ecosystem(p)
	if eco == "" || !Released(p.Version) || eco == vuln.Packagist && composerBranch(p.Version) {
		return vuln.Query{}, false
	}
	return vuln.Query{Ecosystem: eco, Name: OSVName(p), Version: p.Version}, true
}

// DepQuery is the OSV query for one of p's dependencies, if kho asks about
// it. kho asks about the ones known without extra work: npm's direct
// dependencies and every module built into a Go binary. Composer lists its
// dependencies as packages of their own, which are asked about directly.
func DepQuery(p Package, d Dep) (vuln.Query, bool) {
	if p.Source != "npm" && p.Source != "go" || !Released(d.Version) {
		return vuln.Query{}, false
	}
	return vuln.Query{Ecosystem: Ecosystem(p), Name: d.Name, Version: d.Version}, true
}

func DepQueries(p Package) []vuln.Query {
	var qs []vuln.Query
	for _, d := range p.Deps {
		if q, ok := DepQuery(p, d); ok {
			qs = append(qs, q)
		}
	}
	return qs
}

// composerBranch is a Composer version that names a branch, like dev-main
// or 2.x-dev, rather than a release OSV could know about.
func composerBranch(v string) bool {
	return strings.HasPrefix(v, "dev-") || strings.HasSuffix(v, "-dev")
}
