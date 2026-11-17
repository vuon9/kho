package provider

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/vuon9/kho/internal/vuln"
)

type Brew struct{}

func (Brew) Name() string    { return "brew" }
func (Brew) Missing() string { return notOnPath("brew") }

func (Brew) List(ctx context.Context) ([]Package, error) {
	out, err := run(ctx, "brew", "info", "--json=v2", "--installed")
	if err != nil {
		return nil, err
	}
	return parseBrew(out)
}

// brew info already knows the latest version from its local API cache.
func (Brew) Latest(_ context.Context, pkgs []Package) ([]Package, error) { return pkgs, nil }

type brewInstalled struct {
	Version             string    `json:"version"`
	InstalledOnRequest  bool      `json:"installed_on_request"`
	RuntimeDependencies []brewDep `json:"runtime_dependencies"`
}

type brewDep struct {
	FullName         string `json:"full_name"`
	PkgVersion       string `json:"pkg_version"`
	DeclaredDirectly bool   `json:"declared_directly"`
}

type brewFormula struct {
	Name      string `json:"name"`
	FullName  string `json:"full_name"`
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
	Installed []brewInstalled `json:"installed"`
}

type brewCask struct {
	Token       string `json:"token"`
	FullToken   string `json:"full_token"`
	Tap         string `json:"tap"`
	Desc        string `json:"desc"`
	Homepage    string `json:"homepage"`
	Version     string `json:"version"`
	Installed   string `json:"installed"`
	Outdated    bool   `json:"outdated"`
	AutoUpdates bool   `json:"auto_updates"`
}

type brewInfo struct {
	Formulae []brewFormula `json:"formulae"`
	Casks    []brewCask    `json:"casks"`
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

var ErrBrewVulnsUnsupported = errors.New("brew vulns needs Homebrew 6.0.11 or later")

// Homebrew resolves each formula's source repository and revision before it
// asks OSV, and knows which findings its own patches already fix, so kho does
// not have to guess an ecosystem for brew.
func ScanBrewVulns(ctx context.Context) (vuln.BrewResult, error) {
	return scanBrewVulns(ctx)
}

// ScanBrewFormula checks one formula, installed or not. Homebrew assesses the
// version it would install.
func ScanBrewFormula(ctx context.Context, name string) (vuln.BrewResult, error) {
	return scanBrewVulns(ctx, "--", name)
}

func scanBrewVulns(ctx context.Context, args ...string) (vuln.BrewResult, error) {
	out, err := run(ctx, "brew", append([]string{"vulns", "--json"}, args...)...)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unknown command") {
			return vuln.BrewResult{}, ErrBrewVulnsUnsupported
		}
		return vuln.BrewResult{}, err
	}
	report, err := decodeBrewVulns(out)
	if err != nil {
		return vuln.BrewResult{}, err
	}
	return report.result(brewReleaseFixes(ctx, report, brewNewest(ctx, report))), nil
}

// brewNewest asks brew info, locally, for the newest version of each formula
// whose fix Homebrew named only by commit. A release past it is one Homebrew
// can't install, so it is never searched.
func brewNewest(ctx context.Context, r brewVulnsReport) map[string]string {
	var names []string
	for _, f := range r.Findings {
		for _, v := range f.Vulnerabilities {
			if len(brewShas(v.FixedVersions)) > 0 {
				names = append(names, f.Formula)
				break
			}
		}
	}
	newest := map[string]string{}
	if len(names) == 0 {
		return newest
	}
	out, err := run(ctx, "brew", append([]string{"info", "--json=v2", "--formula"}, names...)...)
	if err != nil {
		return newest
	}
	info, err := parseBrewCatalog(out)
	if err != nil {
		return newest
	}
	for _, f := range info.Formulae {
		newest[f.FullName] = f.Versions.Stable
		newest[f.Name] = f.Versions.Stable
	}
	return newest
}

// Homebrew exits non-zero for findings, for an incomplete scan, and for a
// failed one, so the JSON decides what happened and the exit status is not read.
func ParseBrewVulns(data []byte) (vuln.BrewResult, error) {
	report, err := decodeBrewVulns(data)
	if err != nil {
		return vuln.BrewResult{}, err
	}
	return report.result(nil), nil
}

type brewVulnsReport struct {
	Findings            []brewFinding     `json:"findings"`
	SkippedFormulae     []string          `json:"skipped_formulae"`
	Checked             int               `json:"checked"`
	Complete            bool              `json:"complete"`
	OutdatedWithoutSBOM []string          `json:"outdated_without_sbom"`
	Unscanned           map[string]string `json:"unscanned_formulae"`
}

type brewFinding struct {
	Formula         string     `json:"formula"`
	Version         string     `json:"version"`
	Tag             string     `json:"tag"`
	RepoURL         string     `json:"repo_url"`
	Vulnerabilities []brewVuln `json:"vulnerabilities"`
}

func decodeBrewVulns(data []byte) (brewVulnsReport, error) {
	var r brewVulnsReport
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("brew vulns: %w", err)
	}
	return r, nil
}

// released maps brewFixKey to the first release that holds a fix Homebrew
// named only by commit.
func (r brewVulnsReport) result(released map[string]string) vuln.BrewResult {
	result := vuln.BrewResult{Checked: r.Checked, Complete: r.Complete}
	for _, name := range r.SkippedFormulae {
		result.Skipped = append(result.Skipped, brewShortName(name))
	}
	for _, name := range r.OutdatedWithoutSBOM {
		result.OutdatedWithoutSBOM = append(result.OutdatedWithoutSBOM, brewShortName(name))
	}
	if len(r.Unscanned) > 0 {
		result.Unscanned = r.Unscanned
	}
	for _, f := range r.Findings {
		name := brewShortName(f.Formula)
		finding := vuln.BrewFinding{Formula: name, Version: f.Version}
		for _, v := range f.Vulnerabilities {
			finding.Advisories = append(finding.Advisories, v.advisory(name, f.Version, released[brewFixKey(f, v)]))
		}
		result.Findings = append(result.Findings, finding)
	}
	return result
}

func brewFixKey(f brewFinding, v brewVuln) string { return f.Formula + "\x00" + v.ID }

// brewShortName turns Homebrew's full name for a tap's formula, tap/name, into
// the name `brew info` lists it under.
func brewShortName(full string) string { return full[strings.LastIndex(full, "/")+1:] }

type brewVuln struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	Summary       string   `json:"summary"`
	Aliases       []string `json:"aliases"`
	FixedVersions []string `json:"fixed_versions"`
}

// A fixed version Homebrew names wins, then the release that holds a fix
// commit, then the range the summary spells out; the summary still says where
// the span starts. Without any of them the finding says only that the
// installed version is affected.
func (v brewVuln) advisory(formula, version, released string) vuln.Advisory {
	a := vuln.Advisory{
		ID:       v.ID,
		Severity: strings.ToUpper(v.Severity),
		Summary:  v.Summary,
		Package:  formula,
		Versions: []string{version},
	}
	if len(v.Aliases) > 0 {
		a.Aliases = v.Aliases
	}
	span := summaryRanges(v.Summary, version)
	fixed := cmp.Or(brewFixed(v.FixedVersions, version), released)
	switch {
	case fixed != "" && len(span) > 0:
		a.Ranges = []vuln.Range{{Introduced: span[0].Introduced}, {Fixed: fixed}}
	case fixed != "":
		a.Ranges = []vuln.Range{{Introduced: "0"}, {Fixed: fixed}}
	default:
		a.Ranges = span
	}
	return a
}

// Commit SHAs cannot be compared with a formula version, so they are left
// out; a tag that carries its project's name is read as the version it names.
func brewFixed(fixed []string, version string) string {
	best := ""
	for _, f := range fixed {
		if brewSHA.MatchString(f) {
			continue
		}
		v := vuln.Clean(f)
		if !brewVersion(v) || vuln.Compare(v, version) <= 0 {
			continue
		}
		if best == "" || vuln.Compare(v, best) < 0 {
			best = v
		}
	}
	return best
}

func brewShas(fixed []string) []string {
	var shas []string
	for _, f := range fixed {
		if brewSHA.MatchString(f) {
			shas = append(shas, f)
		}
	}
	return shas
}

var (
	summaryThrough = regexp.MustCompile(`(?i)\bv?(\d+(?:\.\d+)+)\s+(?:through|to)\s+v?(\d+(?:\.\d+)+)`)
	summaryBefore  = regexp.MustCompile(`(?i)\b(?:before|prior to|<)\s*v?(\d+(?:\.\d+)+)`)
)

// OSV summaries often spell out the span ("fzf 0.36.0 through 0.74.5",
// "before 2.4.1"). A span that does not hold the installed version is a misread
// and is dropped.
func summaryRanges(summary, version string) []vuln.Range {
	var ranges []vuln.Range
	if m := summaryThrough.FindStringSubmatch(summary); m != nil {
		ranges = []vuln.Range{{Introduced: m[1]}, {LastAffected: m[2]}}
	} else if m := summaryBefore.FindStringSubmatch(summary); m != nil {
		ranges = []vuln.Range{{Introduced: "0"}, {Fixed: m[1]}}
	}
	if ranges == nil || !(vuln.Advisory{Ranges: ranges}).Affects(BrewVersion(version)) {
		return nil
	}
	return ranges
}

// Tests swap both.
var (
	brewReleases = githubReleases
	brewTagHas   = githubTagHas
)

// Best effort: a repo off GitHub or a failed lookup leaves no release.
func brewReleaseFixes(ctx context.Context, r brewVulnsReport, newest map[string]string) map[string]string {
	type job struct {
		repo, key, version, newest string
		shas                       []string
	}
	var jobs []job
	var repos []string
	for _, f := range r.Findings {
		repo, version, top := githubRepo(f.RepoURL), BrewVersion(f.Version), BrewVersion(newest[f.Formula])
		if repo == "" || top == "" || vuln.Compare(top, version) <= 0 {
			continue
		}
		for _, v := range f.Vulnerabilities {
			if shas := brewShas(v.FixedVersions); len(shas) > 0 && brewFixed(v.FixedVersions, f.Version) == "" {
				jobs = append(jobs, job{repo, brewFixKey(f, v), version, top, shas})
				if !slices.Contains(repos, repo) {
					repos = append(repos, repo)
				}
			}
		}
	}
	var mu sync.Mutex
	var g errgroup.Group
	g.SetLimit(brewLookups)
	releases := map[string][]Release{}
	for _, repo := range repos {
		g.Go(func() error {
			rels, _ := brewReleases(ctx, repo)
			mu.Lock()
			releases[repo] = rels
			mu.Unlock()
			return nil
		})
	}
	g.Wait()
	out := map[string]string{}
	for _, j := range jobs {
		g.Go(func() error {
			if fixed := firstReleaseWith(ctx, j.repo, releases[j.repo], j.version, j.newest, j.shas); fixed != "" {
				mu.Lock()
				out[j.key] = fixed
				mu.Unlock()
			}
			return nil
		})
	}
	g.Wait()
	return out
}

const brewLookups = 8

// A release that holds a commit keeps holding it in every later release, so
// a binary search over the newer releases asks GitHub a few times, not once
// per release.
func firstReleaseWith(ctx context.Context, repo string, rels []Release, version, newest string, shas []string) string {
	var newer []string
	for _, r := range rels {
		if v := vuln.Clean(r.Version); brewVersion(v) && vuln.Compare(v, version) > 0 && vuln.Compare(v, newest) <= 0 {
			newer = append(newer, r.Version)
		}
	}
	if len(newer) == 0 {
		return ""
	}
	slices.SortFunc(newer, func(a, b string) int { return vuln.Compare(vuln.Clean(a), vuln.Clean(b)) })
	has := func(tag string) bool {
		for _, sha := range shas {
			if ok, err := brewTagHas(ctx, repo, sha, tag); err == nil && ok {
				return true
			}
		}
		return false
	}
	lo, hi := 0, len(newer)-1
	if !has(newer[hi]) {
		return ""
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if has(newer[mid]) {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return vuln.Clean(newer[lo])
}

// GitHub's compare says "ahead" or "identical" when the tag holds the commit.
func githubTagHas(ctx context.Context, repo, sha, tag string) (bool, error) {
	var r struct {
		Status string `json:"status"`
	}
	if err := githubGet(ctx, "repos/"+repo+"/compare/"+sha+"..."+url.PathEscape(tag)+"?per_page=1", &r); err != nil {
		return false, err
	}
	return r.Status == "ahead" || r.Status == "identical", nil
}

var brewSHA = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

func brewVersion(v string) bool {
	return v != "" && v[0] >= '0' && v[0] <= '9' && !brewSHA.MatchString(v)
}

func (Brew) Deps(_ context.Context, p Package) ([]Dep, error) { return p.Deps, nil }

// Homebrew keeps no version history, so the GitHub releases of the formula's
// source repo stand in for it.
func (Brew) Versions(ctx context.Context, p Package) ([]Release, error) {
	if p.Repo != "" {
		if rels, err := githubReleases(ctx, p.Repo); err == nil && len(rels) > 0 {
			return rels, nil
		}
	}
	var rels []Release
	if p.Latest != "" {
		rels = append(rels, Release{Version: p.Latest, URL: p.Homepage})
	}
	for _, v := range slices.Backward(p.Versions) {
		if v != p.Latest && v != "" {
			rels = append(rels, Release{Version: v, URL: p.Homepage})
		}
	}
	if len(p.Versions) == 0 && p.Version != "" && p.Version != p.Latest {
		rels = append(rels, Release{Version: p.Version, URL: p.Homepage})
	}
	return rels, nil
}

const brewNoResults = "no formulae or casks found"

// Homebrew has no JSON search, so the names come from `brew search` and
// `brew info --json=v2` fills them in.
func (Brew) Search(ctx context.Context, query string, limit int) ([]Package, error) {
	limit = searchLimit(limit)
	var mu sync.Mutex
	var wg sync.WaitGroup
	names := map[string][]string{}
	errs := map[string]error{}
	for _, source := range []string{"brew", "cask"} {
		wg.Go(func() {
			found, err := brewSearchNames(ctx, source, query, limit)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[source] = err
				return
			}
			names[source] = found
		})
	}
	wg.Wait()
	if len(names["brew"]) == 0 && len(names["cask"]) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs["brew"], errs["cask"])
	}
	var pkgs []Package
	for _, source := range []string{"brew", "cask"} {
		if len(names[source]) == 0 {
			continue
		}
		got, err := brewLookup(ctx, source, names[source])
		if err != nil {
			// A failed info pass leaves the names worth showing.
			for _, name := range names[source] {
				pkgs = append(pkgs, Package{Source: source, Name: name})
			}
			continue
		}
		pkgs = append(pkgs, got...)
	}
	return pkgs, nil
}

func (Brew) Find(ctx context.Context, source, name string) (Package, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Package{}, fmt.Errorf("no Homebrew package name given")
	}
	switch source {
	case "":
		if p, err := brewFindOne(ctx, "brew", name); err == nil {
			return p, nil
		}
		return brewFindOne(ctx, "cask", name)
	case "brew", "cask":
		return brewFindOne(ctx, source, name)
	}
	return Package{}, fmt.Errorf("Homebrew doesn't serve the %s source", source)
}

func brewFindOne(ctx context.Context, source, name string) (Package, error) {
	pkgs, err := brewLookup(ctx, source, []string{name})
	if err != nil {
		return Package{}, fmt.Errorf("brew info %s: %w", name, err)
	}
	for _, p := range pkgs {
		if p.Name != name {
			continue
		}
		if p.Latest == "" {
			return Package{}, fmt.Errorf("Homebrew has no %s named %s", source, name)
		}
		return p, nil
	}
	return Package{}, fmt.Errorf("Homebrew has no %s named %s", source, name)
}

func brewSearchNames(ctx context.Context, source, query string, limit int) ([]string, error) {
	flag := "--formula"
	if source == "cask" {
		flag = "--cask"
	}
	out, err := run(ctx, "brew", "search", flag, "--", query)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), brewNoResults) {
			return nil, nil
		}
		return nil, err
	}
	names := parseBrewSearch(out)
	if len(names) > limit {
		names = names[:limit]
	}
	return names, nil
}

func parseBrewSearch(out []byte) []string {
	var names []string
	for line := range strings.Lines(string(out)) {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "==>") || strings.HasPrefix(name, "Error:") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// brew info works whether or not the machine has the names.
func brewLookup(ctx context.Context, source string, names []string) ([]Package, error) {
	args := []string{"info", "--json=v2"}
	if source == "cask" {
		args = append(args, "--cask")
	} else {
		args = append(args, "--formula")
	}
	args = append(args, names...)
	out, err := run(ctx, "brew", args...)
	if err != nil {
		return nil, err
	}
	info, err := parseBrewCatalog(out)
	if err != nil {
		return nil, err
	}
	// A tap's package comes back under its short name, while search printed
	// tap/name. The row keeps the printed name, so installing it taps the repo.
	byName := map[string]Package{}
	for _, f := range info.Formulae {
		byName[f.Name] = brewFormulaPackage(f)
		byName[f.FullName] = brewFormulaPackage(f)
	}
	for _, c := range info.Casks {
		byName[c.Token] = brewCaskPackage(c)
		byName[c.FullToken] = brewCaskPackage(c)
	}
	pkgs := make([]Package, 0, len(names))
	for _, name := range names {
		if p, ok := byName[name]; ok {
			p.Name = name
			pkgs = append(pkgs, p)
			continue
		}
		pkgs = append(pkgs, Package{Source: source, Name: name})
	}
	return pkgs, nil
}

func brewFormulaPackage(f brewFormula) Package {
	return Package{Source: "brew", Name: f.Name, Latest: f.Versions.Stable, Desc: f.Desc,
		Homepage: f.Homepage, Origin: f.Tap, Repo: githubRepo(f.URLs.Stable.URL, f.Homepage)}
}

func brewCaskPackage(c brewCask) Package {
	return Package{Source: "cask", Name: c.Token, Latest: c.Version, Desc: c.Desc,
		Homepage: c.Homepage, Origin: c.Tap, Repo: githubRepo(c.Homepage)}
}

func parseBrewCatalog(data []byte) (brewInfo, error) {
	var info brewInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return brewInfo{}, fmt.Errorf("brew info: %w", err)
	}
	return info, nil
}
