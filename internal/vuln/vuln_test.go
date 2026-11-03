package vuln

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestAffects(t *testing.T) {
	redos := Advisory{ID: "GHSA-test", Ranges: []Range{{Introduced: "0"}, {Fixed: "24.3.0"}}}
	twoSpans := Advisory{ID: "GO-1", Ranges: []Range{{Introduced: "0"}, {Fixed: "0.23.0"}, {Introduced: "0.24.0"}, {Fixed: "0.24.2"}}}
	lastAffected := Advisory{ID: "X", Ranges: []Range{{Introduced: "1.0"}, {LastAffected: "1.4"}}}
	listed := Advisory{ID: "Y", Versions: []string{"2.0.1"}}
	tests := []struct {
		id      string
		adv     Advisory
		version string
		want    bool
		fixed   string
	}{
		{"installed version before the fix", redos, "22.12.0", true, "24.3.0"},
		{"the fixed version itself", redos, "24.3.0", false, ""},
		{"a later release", redos, "26.10.1", false, ""},
		{"go tags keep their v", twoSpans, "v0.20.0", true, "0.23.0"},
		{"between two affected spans", twoSpans, "v0.23.5", false, "0.24.2"},
		{"inside the second span", twoSpans, "v0.24.1", true, "0.24.2"},
		{"last_affected includes itself", lastAffected, "1.4", true, ""},
		{"after last_affected", lastAffected, "1.10", false, ""},
		{"before introduced", lastAffected, "0.9", false, ""},
		{"explicit version list", listed, "2.0.1", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := tt.adv.Affects(tt.version); got != tt.want {
				t.Errorf("Affects(%s) = %v, want %v", tt.version, got, tt.want)
			}
			if got := tt.adv.FixedAfter(tt.version); got != tt.fixed {
				t.Errorf("FixedAfter(%s) = %q, want %q", tt.version, got, tt.fixed)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.10", "1.9", 1}, {"v1.2.0", "1.2.0", 0}, {"26.10.1", "26.5.1", 1}, {"0.2.89", "0.2.94", -1}, {"1.0", "1.0.1", -1},
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); (got > 0) != (tt.want > 0) || (got < 0) != (tt.want < 0) {
			t.Errorf("Compare(%s, %s) = %d, want sign of %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestAdvisoryFromOSV(t *testing.T) {
	var r osvRecord
	err := json.Unmarshal([]byte(`{"id":"GHSA-test-0001-0001","aliases":["CVE-0000-00001","PYSEC-0000-1"],
		"summary":"Bramble vulnerable to ReDoS","published":"2024-03-19T06:30:52Z","database_specific":{"severity":"MODERATE"},
		"affected":[{"package":{"name":"bramble","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"24.3.0"}]},
		{"type":"GIT","events":[{"introduced":"abc"}]}],"versions":["22.12.0"]}]}`), &r)
	if err != nil {
		t.Fatal(err)
	}
	want := Advisory{ID: "GHSA-test-0001-0001", Aliases: []string{"CVE-0000-00001", "PYSEC-0000-1"}, Summary: "Bramble vulnerable to ReDoS",
		Severity: "MODERATE", Published: time.Date(2024, 3, 19, 6, 30, 52, 0, time.UTC), Package: "bramble",
		Ranges: []Range{{Introduced: "0"}, {Fixed: "24.3.0"}}, Versions: []string{"22.12.0"}}
	if got := r.advisory(); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestSummaryFallsBackToTheFirstSentence(t *testing.T) {
	r := osvRecord{ID: "PYSEC-0000-2", Details: "Bramble is a formatter for code. Prior to 26.3.1 it wrote cache files to any path an option named. " +
		"An attacker who controls that option can write files anywhere the user can. Fixed in 26.3.1."}
	if got := r.advisory().Summary; got != "Bramble is a formatter for code. Prior to 26.3.1 it wrote cache files to any path an option named." {
		t.Errorf("summary %q", got)
	}
}

func TestDedupe(t *testing.T) {
	got := Dedupe([]Advisory{
		{ID: "PYSEC-0000-1", Aliases: []string{"CVE-0000-00001", "GHSA-test"}},
		{ID: "GHSA-low", Severity: "LOW"},
		{ID: "GHSA-test", Aliases: []string{"CVE-0000-00001", "PYSEC-0000-1"}, Severity: "MODERATE"},
		{ID: "GHSA-crit", Severity: "CRITICAL"},
	})
	var ids []string
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	if want := []string{"GHSA-crit", "GHSA-test", "GHSA-low"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("got %v, want %v", ids, want)
	}
}

func TestDB(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	fresh := Query{"PyPI", "bramble", "22.12.0"}
	old := Query{"npm", "diffkit", "0.23.0"}
	unseen := Query{"Go", "golang.org/x/net", "v0.20.0"}
	db := NewDB()
	db.Merge(map[string][]string{fresh.Key(): {"PYSEC-0000-1", "GHSA-test"}}, map[string]Advisory{
		"GHSA-test":    {ID: "GHSA-test", Aliases: []string{"PYSEC-0000-1"}, Severity: "MODERATE", Package: "bramble"},
		"PYSEC-0000-1": {ID: "PYSEC-0000-1", Aliases: []string{"GHSA-test"}, Package: "bramble"},
	}, now)
	db.Merge(map[string][]string{old.Key(): nil}, nil, now.Add(-13*time.Hour))

	path := filepath.Join(t.TempDir(), "kho", "security.json")
	if err := db.Save(path); err != nil {
		t.Fatal(err)
	}
	db = Load(path)
	if got := db.Stale([]Query{fresh, old, unseen}, now); !reflect.DeepEqual(got, []Query{old, unseen}) {
		t.Errorf("stale %v", got)
	}
	if got := db.For(fresh); len(got) != 1 || got[0].ID != "GHSA-test" {
		t.Errorf("For kept %+v, want only GHSA-test", got)
	}
	if db.HistoryFresh("PyPI", "bramble", now) {
		t.Error("history is fresh before it was fetched")
	}
	db.MergeHistory("PyPI", "bramble", []Advisory{{ID: "GHSA-new", Package: "bramble", Ranges: []Range{{Introduced: "26.0"}}}, db.Advisories["GHSA-test"]}, now)
	if got := db.Known("PyPI", "bramble"); len(got) != 2 || !db.HistoryFresh("PyPI", "bramble", now) {
		t.Errorf("Known found %d, want 2", len(got))
	}
}

func TestOldCacheIsDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security.json")
	os.WriteFile(path, []byte(`{"checked":{"PyPI/bramble@1.0":"2026-11-03T12:00:00Z"},"hits":{"PyPI/bramble@1.0":["X"]}}`), 0o644)
	if db := Load(path); len(db.Checked) != 0 || len(db.Hits) != 0 {
		t.Errorf("a cache without the current format was kept: %+v", db)
	}
}

func TestVerdict(t *testing.T) {
	a := SkillAudit{Gen: "safe", Socket: "safe", Snyk: "medium"}
	if a.Worst() != "medium" || Verdict(a.Worst()) != "Warn" || Verdict("safe") != "Pass" || Verdict("high") != "Fail" || Verdict("") != "--" {
		t.Errorf("worst %q verdict %q", a.Worst(), Verdict(a.Worst()))
	}
}
