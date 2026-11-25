package provider

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/vuon9/kho/internal/vuln"
)

func TestParseBrewVulns(t *testing.T) {
	tests := []struct {
		id   string
		json string
		want vuln.BrewResult
	}{
		{
			id: "a tap's formula goes by the name brew info lists it under",
			json: `{"findings":[{"formula":"acme/tools/anvil","version":"1.2.3","vulnerabilities":[
					{"id":"CVE-0000-0006","severity":"HIGH","summary":"Anvil trusts a header","aliases":[],"fixed_versions":[]}],"patched":[]}],
				"skipped_formulae":["acme/tools/bramble"],"checked":3,"complete":false,
				"outdated_without_sbom":["acme/tools/cog"],"unscanned_formulae":{}}`,
			want: vuln.BrewResult{Checked: 3, Skipped: []string{"bramble"}, OutdatedWithoutSBOM: []string{"cog"},
				Findings: []vuln.BrewFinding{{Formula: "anvil", Version: "1.2.3", Advisories: []vuln.Advisory{
					{ID: "CVE-0000-0006", Severity: "HIGH", Summary: "Anvil trusts a header", Package: "anvil", Versions: []string{"1.2.3"}},
				}}}},
		},
		{
			id: "a released fix becomes the fixed version",
			json: `{"findings":[{"formula":"anvil","version":"1.2.3","tag":"v1.2.3","repo_url":"https://github.com/example/anvil",
				"vulnerabilities":[{"id":"CVE-0000-0001","severity":"HIGH","summary":"Anvil runs a command twice",
					"aliases":["GHSA-test"],"fixed_versions":["v1.2.10","v1.2.4"]}],"patched":[]}],
				"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`,
			want: vuln.BrewResult{Checked: 1, Complete: true, Findings: []vuln.BrewFinding{{
				Formula: "anvil", Version: "1.2.3", Advisories: []vuln.Advisory{{
					ID: "CVE-0000-0001", Aliases: []string{"GHSA-test"}, Severity: "HIGH",
					Summary: "Anvil runs a command twice", Package: "anvil", Versions: []string{"1.2.3"},
					Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "1.2.4"}},
				}},
			}}},
		},
		{
			id: "a commit SHA is not a fixed version, but a tag named for its project is",
			json: `{"findings":[{"formula":"anvil","version":"1.2.3","vulnerabilities":[
				{"id":"CVE-0000-0002","severity":"UNKNOWN","summary":"Anvil reads past the file","aliases":[],
					"fixed_versions":["2dae3024897e1898d389835151f4e9606227721d"]},
				{"id":"CVE-0000-0003","severity":"LOW","summary":"Anvil logs a secret","aliases":[],
					"fixed_versions":["anvil-9.9.9"]},
				{"id":"CVE-0000-0004","severity":"MEDIUM","summary":"Anvil writes early","aliases":[],
					"fixed_versions":["1.2.0"]}],"patched":[]}],
				"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`,
			want: vuln.BrewResult{Checked: 1, Complete: true, Findings: []vuln.BrewFinding{{
				Formula: "anvil", Version: "1.2.3", Advisories: []vuln.Advisory{
					{ID: "CVE-0000-0002", Severity: "UNKNOWN", Summary: "Anvil reads past the file", Package: "anvil", Versions: []string{"1.2.3"}},
					{ID: "CVE-0000-0003", Severity: "LOW", Summary: "Anvil logs a secret", Package: "anvil", Versions: []string{"1.2.3"},
						Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "9.9.9"}}},
					{ID: "CVE-0000-0004", Severity: "MEDIUM", Summary: "Anvil writes early", Package: "anvil", Versions: []string{"1.2.3"}},
				},
			}}},
		},
		{
			id: "a summary that spells out the span becomes its range",
			json: `{"findings":[{"formula":"anvil","version":"1.2.3_1","vulnerabilities":[
				{"id":"CVE-0000-0007","severity":"HIGH","summary":"anvil 1.0.0 through 1.2.3 runs a hook","aliases":[],"fixed_versions":[]},
				{"id":"CVE-0000-0008","severity":"LOW","summary":"Anvil before 1.3.0 leaks a path","aliases":[],"fixed_versions":[]},
				{"id":"CVE-0000-0009","severity":"LOW","summary":"Anvil 0.1 through 0.9 misreads a file","aliases":[],"fixed_versions":[]},
				{"id":"CVE-0000-0010","severity":"LOW","summary":"anvil 1.1.0 through 1.2.3 drops a header","aliases":[],"fixed_versions":["v1.2.4"]}],"patched":[]}],
				"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`,
			want: vuln.BrewResult{Checked: 1, Complete: true, Findings: []vuln.BrewFinding{{
				Formula: "anvil", Version: "1.2.3_1", Advisories: []vuln.Advisory{
					{ID: "CVE-0000-0007", Severity: "HIGH", Summary: "anvil 1.0.0 through 1.2.3 runs a hook", Package: "anvil", Versions: []string{"1.2.3_1"},
						Ranges: []vuln.Range{{Introduced: "1.0.0"}, {LastAffected: "1.2.3"}}},
					{ID: "CVE-0000-0008", Severity: "LOW", Summary: "Anvil before 1.3.0 leaks a path", Package: "anvil", Versions: []string{"1.2.3_1"},
						Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "1.3.0"}}},
					{ID: "CVE-0000-0009", Severity: "LOW", Summary: "Anvil 0.1 through 0.9 misreads a file", Package: "anvil", Versions: []string{"1.2.3_1"}},
					{ID: "CVE-0000-0010", Severity: "LOW", Summary: "anvil 1.1.0 through 1.2.3 drops a header", Package: "anvil", Versions: []string{"1.2.3_1"},
						Ranges: []vuln.Range{{Introduced: "1.1.0"}, {Fixed: "1.2.4"}}},
				},
			}}},
		},
		{
			id: "a patched finding is not an open one",
			json: `{"findings":[{"formula":"anvil","version":"1.2.3","vulnerabilities":[],
				"patched":[{"id":"CVE-0000-0005","severity":"HIGH","summary":"Anvil loads a plugin","aliases":[],"fixed_versions":[]}]}],
				"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`,
			want: vuln.BrewResult{Checked: 1, Complete: true, Findings: []vuln.BrewFinding{{Formula: "anvil", Version: "1.2.3"}}},
		},
		{
			id: "coverage gaps are kept",
			json: `{"findings":[],"skipped_formulae":["bramble"],"checked":4,"complete":false,
				"outdated_without_sbom":["cog"],"unscanned_formulae":{"dial":"untrusted_tap","ember":"resolution_error"}}`,
			want: vuln.BrewResult{Checked: 4, Skipped: []string{"bramble"}, OutdatedWithoutSBOM: []string{"cog"},
				Unscanned: map[string]string{"dial": "untrusted_tap", "ember": "resolution_error"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := ParseBrewVulns([]byte(tt.json))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestFirstReleaseWith(t *testing.T) {
	rels := []Release{{Version: "anvil-1.4.0"}, {Version: "anvil-1.2.4"}, {Version: "anvil-1.3.0"}, {Version: "anvil-1.2.3"}, {Version: "nightly"}}
	// holds says which tags hold which commits, the way GitHub's compare would.
	holds := map[string][]string{"anvil-1.3.0": {"aaaaaaa"}, "anvil-1.4.0": {"aaaaaaa", "bbbbbbb"}}
	tests := []struct {
		id     string
		shas   []string
		newest string
		want   string
	}{
		{"the first newer release that holds the commit", []string{"aaaaaaa"}, "1.4.0", "1.3.0"},
		{"any of several commits, as with a backport", []string{"ccccccc", "bbbbbbb"}, "1.4.0", "1.4.0"},
		{"no newer release holds it yet", []string{"ddddddd"}, "1.4.0", ""},
		{"a release past Homebrew's newest is not one it can install", []string{"bbbbbbb"}, "1.3.0", ""},
	}
	old := brewTagHas
	t.Cleanup(func() { brewTagHas = old })
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			asked := 0
			brewTagHas = func(_ context.Context, repo, sha, tag string) (bool, error) {
				asked++
				return slices.Contains(holds[tag], sha), nil
			}
			if got := firstReleaseWith(context.Background(), "acme/anvil", rels, "1.2.3", tt.newest, tt.shas); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if asked > 3*len(tt.shas) {
				t.Errorf("asked GitHub %d times for %d commits", asked, len(tt.shas))
			}
		})
	}
}

func TestBrewReleaseFixesFillsTheFix(t *testing.T) {
	oldRels, oldHas := brewReleases, brewTagHas
	t.Cleanup(func() { brewReleases, brewTagHas = oldRels, oldHas })
	brewReleases = func(_ context.Context, repo string) ([]Release, error) {
		return []Release{{Version: "v0.75.0"}, {Version: "v0.74.5"}}, nil
	}
	brewTagHas = func(_ context.Context, repo, sha, tag string) (bool, error) {
		return repo == "acme/finder" && tag == "v0.75.0", nil
	}
	report, err := decodeBrewVulns([]byte(`{"findings":[{"formula":"finder","version":"0.74.5","tag":"v0.74.5",
		"repo_url":"https://github.com/acme/finder","vulnerabilities":[{"id":"CVE-0000-0011","severity":"HIGH",
		"summary":"finder hangs","aliases":[],"fixed_versions":["b412a450538e5f4a1d7057732e75d945dafa18a6"]}],"patched":[]}],
		"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := report.result(brewReleaseFixes(context.Background(), report, map[string]string{"finder": "0.75.0"}), nil).Findings[0].Advisories[0]
	if got.FixedAfter("0.74.5") != "0.75.0" || got.Affects("v0.75.0") || !got.Affects("v0.74.5") {
		t.Errorf("advisory %+v, want it fixed in 0.75.0", got)
	}
}

// Homebrew only looks for a newer release that carries a fix it could name only
// by commit. A fix that already reached the installed version itself has no
// newer release to carry it, so the finding would never clear.
func TestBrewVulnsClearsAFixTheInstalledTagHolds(t *testing.T) {
	oldRels, oldHas := brewReleases, brewTagHas
	t.Cleanup(func() { brewReleases, brewTagHas = oldRels, oldHas })
	// A repo with no releases: the installed ref has to be found by trying it.
	brewReleases = func(_ context.Context, _ string) ([]Release, error) {
		return nil, nil
	}
	const held, missing = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	brewTagHas = func(_ context.Context, _, sha, tag string) (bool, error) {
		if tag != "v1.2.3" {
			return false, errors.New("compare: 404 Not Found")
		}
		return sha == held, nil
	}
	report, err := decodeBrewVulns([]byte(`{"findings":[{"formula":"anvil","version":"1.2.3","tag":"1.2.3",` +
		`"repo_url":"https://github.com/example/anvil","vulnerabilities":[` +
		`{"id":"CVE-0000-0021","severity":"UNKNOWN","summary":"Anvil reads past the plane","aliases":[],"fixed_versions":["` + held + `"]},` +
		`{"id":"CVE-0000-0022","severity":"UNKNOWN","summary":"Anvil writes early","aliases":[],"fixed_versions":["` + missing + `"]}],"patched":[]}],` +
		`"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := report.result(nil, brewAlreadyFixed(context.Background(), report)).Findings
	if len(got) != 1 {
		t.Fatalf("got %d findings, want the one formula still carrying a live advisory", len(got))
	}
	advs := got[0].Advisories
	if len(advs) != 1 || advs[0].ID != "CVE-0000-0022" {
		t.Errorf("advisories %+v, want only CVE-0000-0022 (1.2.3 holds the fix for 0021)", advs)
	}
}

// Without a ref to ask about, the finding stands: a lookup kho cannot finish
// never clears an advisory.
func TestBrewVulnsKeepsAFindingWhenTheInstalledRefIsUnknown(t *testing.T) {
	oldRels, oldHas := brewReleases, brewTagHas
	t.Cleanup(func() { brewReleases, brewTagHas = oldRels, oldHas })
	brewReleases = func(_ context.Context, _ string) ([]Release, error) { return nil, nil }
	brewTagHas = func(_ context.Context, _, _, _ string) (bool, error) {
		return false, errors.New("compare: 404 Not Found")
	}
	report, err := decodeBrewVulns([]byte(`{"findings":[{"formula":"anvil","version":"1.2.3","tag":"1.2.3",` +
		`"repo_url":"https://github.com/example/anvil","vulnerabilities":[` +
		`{"id":"CVE-0000-0031","severity":"HIGH","summary":"Anvil trusts a header","aliases":[],"fixed_versions":["3333333333333333333333333333333333333333"]}],"patched":[]}],` +
		`"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := report.result(nil, brewAlreadyFixed(context.Background(), report)).Findings[0].Advisories
	if len(got) != 1 || got[0].ID != "CVE-0000-0031" {
		t.Errorf("advisories %+v, want the finding kept", got)
	}
}

func TestParseBrewVulnsRejectsWhatIsNotJSON(t *testing.T) {
	if _, err := ParseBrewVulns([]byte("Warning: metadata is stale\n")); err == nil {
		t.Error("plain text from a failed scan must be an error, not an empty scan")
	}
}

func TestBrewQuery(t *testing.T) {
	tests := []struct {
		id   string
		p    Package
		want vuln.Query
		ok   bool
	}{
		{"a formula version drops the revision brew appends", Package{Source: "brew", Name: "anvil", Version: "4.0.0_1"},
			vuln.Query{Ecosystem: vuln.Homebrew, Name: "anvil", Version: "4.0.0"}, true},
		{"a formula with no revision keeps its version", Package{Source: "brew", Name: "anvil", Version: "1.2.3"},
			vuln.Query{Ecosystem: vuln.Homebrew, Name: "anvil", Version: "1.2.3"}, true},
		{"a cask is not scanned by Homebrew", Package{Source: "cask", Name: "focusbar", Version: "2.0.3"}, vuln.Query{}, false},
		{"an npm package is not a formula", Package{Source: "npm", Name: "diffkit", Version: "0.23.0"}, vuln.Query{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, ok := BrewQuery(tt.p)
			if got != tt.want || ok != tt.ok {
				t.Errorf("got %+v %v, want %+v %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}
