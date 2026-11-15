package vuln

import (
	"testing"
	"time"
)

func TestMergeBrew(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	anvil := Query{Ecosystem: Homebrew, Name: "anvil", Version: "1.2.3"}
	adv := Advisory{ID: "CVE-0000-0001", Severity: "HIGH", Summary: "Anvil runs a command twice",
		Package: "anvil", Versions: []string{"1.2.3"}, Ranges: []Range{{Introduced: "0"}, {Fixed: "1.2.4"}}}
	scanned := func(findings []BrewFinding, result BrewResult, queries ...Query) *DB {
		db := NewDB()
		result.Findings = findings
		db.MergeBrew(result, queries, now)
		return db
	}
	tests := []struct {
		id       string
		db       func() *DB
		q        Query
		want     []Advisory
		skip     string
		complete bool
	}{
		{
			id: "a finding is served for the scanned formula version",
			db: func() *DB {
				return scanned([]BrewFinding{{Formula: "anvil", Version: "1.2.3", Advisories: []Advisory{adv}}},
					BrewResult{Checked: 1, Complete: true}, anvil)
			},
			q: anvil, want: []Advisory{adv}, complete: true,
		},
		{
			id: "a formula with no findings is marked checked and stays empty",
			db: func() *DB {
				db := scanned(nil, BrewResult{Checked: 1, Complete: true}, anvil)
				db.MergeBrew(BrewResult{Checked: 1, Complete: true}, []Query{anvil}, now)
				return db
			},
			q: anvil, complete: true,
		},
		{
			id: "a skipped formula keeps the reason and drops its finding",
			db: func() *DB {
				return scanned([]BrewFinding{{Formula: "anvil", Version: "1.2.3", Advisories: []Advisory{adv}}},
					BrewResult{Checked: 2, Skipped: []string{"anvil"}}, anvil)
			},
			q: anvil, skip: "Homebrew found no source it could match",
		},
		{
			id: "an outdated formula without an SBOM is left out",
			db: func() *DB {
				return scanned([]BrewFinding{{Formula: "anvil", Version: "1.2.3", Advisories: []Advisory{adv}}},
					BrewResult{Checked: 1, OutdatedWithoutSBOM: []string{"anvil"}}, anvil)
			},
			q: anvil, skip: "installed source unknown; Homebrew checked the current formula",
		},
		{
			id: "an untrusted tap is named",
			db: func() *DB {
				return scanned(nil, BrewResult{Checked: 1, Unscanned: map[string]string{"anvil": "untrusted_tap"}}, anvil)
			},
			q: anvil, skip: "from an untrusted tap",
		},
		{
			id: "a formula Homebrew checked at another version is not claimed",
			db: func() *DB {
				return scanned([]BrewFinding{{Formula: "anvil", Version: "1.2.2", Advisories: []Advisory{adv}}},
					BrewResult{Checked: 1, Complete: true}, anvil)
			},
			q: anvil, skip: "Homebrew checked version 1.2.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			db := tt.db()
			got := db.For(tt.q)
			if len(got) != len(tt.want) || (len(got) == 1 && got[0].ID != tt.want[0].ID) {
				t.Errorf("advisories %+v, want %+v", got, tt.want)
			}
			if db.BrewSkip(tt.q.Name) != tt.skip {
				t.Errorf("skip reason %q, want %q", db.BrewSkip(tt.q.Name), tt.skip)
			}
			if db.BrewScanned() != true {
				t.Error("a merge always counts as a scan")
			}
			if db.BrewComplete() != tt.complete {
				t.Errorf("complete %v, want %v", db.BrewComplete(), tt.complete)
			}
			if stale := db.Stale([]Query{tt.q}, now.Add(time.Hour)); len(stale) != 0 {
				t.Errorf("a checked formula went stale: %+v", stale)
			}
		})
	}
}

func TestMergeBrewKeepsOSVRecordsApart(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	const id = "CVE-0000-0009"
	osv := Query{Ecosystem: PyPI, Name: "bramble", Version: "2.0.0"}
	brew := Query{Ecosystem: Homebrew, Name: "anvil", Version: "1.2.3"}
	db := NewDB()
	db.Merge(map[string][]string{osv.Key(): {id}},
		map[string]Advisory{id: {ID: id, Summary: "OSV writeup", Details: "A longer writeup.", Severity: "HIGH"}}, now)
	db.MergeBrew(BrewResult{Checked: 1, Complete: true, Findings: []BrewFinding{{Formula: "anvil", Version: "1.2.3",
		Advisories: []Advisory{{ID: id, Summary: "Homebrew finding", Severity: "HIGH", Versions: []string{"1.2.3"}}}}}}, []Query{brew}, now)
	if got := db.For(osv); len(got) != 1 || got[0].Details != "A longer writeup." {
		t.Errorf("the OSV record changed: %+v", got)
	}
	if got := db.For(brew); len(got) != 1 || got[0].Summary != "Homebrew finding" {
		t.Errorf("the Homebrew record is not its own: %+v", got)
	}
}

func TestSetBrewUnsupported(t *testing.T) {
	db := NewDB()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	db.SetBrewUnsupported("brew vulns needs Homebrew 6.0.11 or later", now)
	if !db.BrewScanned() || db.BrewComplete() {
		t.Error("an unsupported scan is stored and never complete")
	}
	if got := db.BrewNote(); got != "brew vulns needs Homebrew 6.0.11 or later" {
		t.Errorf("note %q", got)
	}
	if got := db.Stale([]Query{{Ecosystem: Homebrew, Name: "anvil", Version: "1.2.3"}}, now); len(got) != 1 {
		t.Error("no formula was checked, so the next scan must ask again")
	}
}
