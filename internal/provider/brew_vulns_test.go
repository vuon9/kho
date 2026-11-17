package provider

import (
	"reflect"
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
			id: "a released fix becomes the fixed version",
			json: `{"findings":[{"formula":"anvil","version":"1.2.3","tag":"v1.2.3","repo_url":"https://github.com/example/anvil",
				"vulnerabilities":[{"id":"CVE-0000-0001","severity":"HIGH","summary":"Anvil runs a command twice",
					"aliases":["GHSA-test"],"fixed_versions":["v1.2.10","v1.2.4"]}],"patched":[]}],
				"skipped_formulae":[],"checked":1,"complete":true,"outdated_without_sbom":[],"unscanned_formulae":{}}`,
			want: vuln.BrewResult{Checked: 1, Complete: true, Findings: []vuln.BrewFinding{{
				Formula: "anvil", Version: "1.2.3", RepoURL: "https://github.com/example/anvil", Tag: "v1.2.3",
				Advisories: []vuln.Advisory{{
					ID: "CVE-0000-0001", Aliases: []string{"GHSA-test"}, Severity: "HIGH",
					Summary: "Anvil runs a command twice", Package: "anvil", Versions: []string{"1.2.3"},
					Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "1.2.4"}},
				}},
			}}},
		},
		{
			id: "a commit SHA or a project tag is not a fixed version",
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
					{ID: "CVE-0000-0002", Severity: "UNKNOWN", Summary: "Anvil reads past the file", Package: "anvil", Versions: []string{"1.2.3"},
						CommitFixes: []string{"2dae3024897e1898d389835151f4e9606227721d"}},
					{ID: "CVE-0000-0003", Severity: "LOW", Summary: "Anvil logs a secret", Package: "anvil", Versions: []string{"1.2.3"}},
					{ID: "CVE-0000-0004", Severity: "MEDIUM", Summary: "Anvil writes early", Package: "anvil", Versions: []string{"1.2.3"}},
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
