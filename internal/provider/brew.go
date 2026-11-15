package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

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

// brewInstalled is one installed keg of a formula.
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

// ErrBrewVulnsUnsupported says the brew on PATH predates the built-in vulns
// command, which Homebrew added in 6.0.11.
var ErrBrewVulnsUnsupported = errors.New("brew vulns needs Homebrew 6.0.11 or later")

// ScanBrewVulns runs Homebrew's own scan over the installed formulae.
// Homebrew resolves each formula's source repository and revision before it
// asks OSV, and knows which findings its own patches already fix, so kho does
// not have to guess an ecosystem for brew.
func ScanBrewVulns(ctx context.Context) (vuln.BrewResult, error) {
	out, err := run(ctx, "brew", "vulns", "--json")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unknown command") {
			return vuln.BrewResult{}, ErrBrewVulnsUnsupported
		}
		return vuln.BrewResult{}, err
	}
	return ParseBrewVulns(out)
}

// ParseBrewVulns reads `brew vulns --json`. Homebrew exits non-zero for
// findings, for an incomplete scan, and for a failed one, so the JSON decides
// what happened and the exit status is not read here.
func ParseBrewVulns(data []byte) (vuln.BrewResult, error) {
	var raw struct {
		Findings []struct {
			Formula         string     `json:"formula"`
			Version         string     `json:"version"`
			Vulnerabilities []brewVuln `json:"vulnerabilities"`
		} `json:"findings"`
		SkippedFormulae     []string          `json:"skipped_formulae"`
		Checked             int               `json:"checked"`
		Complete            bool              `json:"complete"`
		OutdatedWithoutSBOM []string          `json:"outdated_without_sbom"`
		Unscanned           map[string]string `json:"unscanned_formulae"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return vuln.BrewResult{}, fmt.Errorf("brew vulns: %w", err)
	}
	result := vuln.BrewResult{Checked: raw.Checked, Complete: raw.Complete}
	if len(raw.SkippedFormulae) > 0 {
		result.Skipped = raw.SkippedFormulae
	}
	if len(raw.OutdatedWithoutSBOM) > 0 {
		result.OutdatedWithoutSBOM = raw.OutdatedWithoutSBOM
	}
	if len(raw.Unscanned) > 0 {
		result.Unscanned = raw.Unscanned
	}
	for _, f := range raw.Findings {
		finding := vuln.BrewFinding{Formula: f.Formula, Version: f.Version}
		for _, v := range f.Vulnerabilities {
			finding.Advisories = append(finding.Advisories, v.advisory(f.Formula, f.Version))
		}
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// brewVuln is one entry of a finding's vulnerabilities or patched lists.
type brewVuln struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	Summary       string   `json:"summary"`
	Aliases       []string `json:"aliases"`
	FixedVersions []string `json:"fixed_versions"`
}

func (v brewVuln) advisory(formula, version string) vuln.Advisory {
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
	if fixed := brewFixed(v.FixedVersions, version); fixed != "" {
		a.Ranges = []vuln.Range{{Introduced: "0"}, {Fixed: fixed}}
	}
	return a
}

// brewFixed is the lowest released version above the scanned one. Homebrew
// also lists commit SHAs for patches, and tags that carry their project's
// name; neither can be compared with a formula version, so they are left out
// and the finding keeps no fixed version.
func brewFixed(fixed []string, version string) string {
	best := ""
	for _, f := range fixed {
		v := strings.TrimPrefix(f, "v")
		if !brewVersion(v) || vuln.Compare(v, version) <= 0 {
			continue
		}
		if best == "" || vuln.Compare(v, best) < 0 {
			best = v
		}
	}
	return best
}

var brewSHA = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

func brewVersion(v string) bool {
	return v != "" && v[0] >= '0' && v[0] <= '9' && !brewSHA.MatchString(v)
}

func (Brew) Deps(_ context.Context, p Package) ([]Dep, error) { return p.Deps, nil }

// Homebrew keeps no version history, so the GitHub releases of the formula's
// source repo stand in for it. Without a repo, the known versions remain.
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
	// A package the machine does not have has no installed version to add.
	if len(p.Versions) == 0 && p.Version != "" && p.Version != p.Latest {
		rels = append(rels, Release{Version: p.Version, URL: p.Homepage})
	}
	return rels, nil
}

// brewNoResults is how Homebrew reports a search that matched nothing.
const brewNoResults = "no formulae or casks found"

// Search finds formulae and casks by keyword. Homebrew has no JSON search, so
// the names come from `brew search` and `brew info --json=v2` fills them in.
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
	if len(names["brew"]) == 0 && len(names["cask"]) == 0 && len(errs) == 2 {
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

// Find looks up one formula or cask by its exact name. An empty source tries
// the formula first, then the cask.
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
	out, err := run(ctx, "brew", "search", flag, query)
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

// parseBrewSearch reads the names `brew search` prints, one per line.
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

// brewLookup asks brew info about names, which works whether or not the
// machine has them.
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
	byName := map[string]Package{}
	for _, f := range info.Formulae {
		byName[f.Name] = brewFormulaPackage(f)
	}
	for _, c := range info.Casks {
		byName[c.Token] = brewCaskPackage(c)
	}
	pkgs := make([]Package, 0, len(names))
	for _, name := range names {
		if p, ok := byName[name]; ok {
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

// parseBrewCatalog reads brew info --json=v2 for packages the machine may not
// have. Installed versions are ignored; latest and metadata are what matter.
func parseBrewCatalog(data []byte) (brewInfo, error) {
	var info brewInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return brewInfo{}, fmt.Errorf("brew info: %w", err)
	}
	return info, nil
}
