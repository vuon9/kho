package vuln

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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

func TestSkillAuditCache(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	installed := map[string][]string{"someone/skills": {"pathmaker", "tidyup"}}
	high := map[string]SkillAudit{"someone/skills/pathmaker": {Gen: "safe", Socket: "high", Snyk: "low"}}
	none := map[string]SkillAudit{}
	down := errors.New("skills.sh: down")
	tests := []struct {
		id        string
		auditedAt map[string]time.Time
		got       map[string]SkillAudit
		err       error
		asked     map[string][]string
		audits    map[string]SkillAudit
		dueLater  map[string][]string
	}{
		{"a failed ask marks nothing fresh", nil, nil, down,
			installed, map[string]SkillAudit{}, installed},
		{"nothing asked, as with telemetry off, marks nothing fresh", nil, nil, nil,
			installed, map[string]SkillAudit{}, installed},
		{"a failed ask keeps the audits that came back", nil, high, down,
			installed, high, installed},
		{"an answer marks every asked skill fresh, even one it has no audit for", nil, high, nil,
			installed, high, map[string][]string{}},
		{"an empty answer marks every asked skill fresh", nil, none, nil,
			installed, map[string]SkillAudit{}, map[string][]string{}},
		{"a skill audited within MaxAge is not asked", map[string]time.Time{"someone/skills/tidyup": now.Add(-time.Hour)}, none, nil,
			map[string][]string{"someone/skills": {"pathmaker"}}, map[string]SkillAudit{}, map[string][]string{}},
		{"a skill audited longer than MaxAge ago is asked again", map[string]time.Time{"someone/skills/tidyup": now.Add(-13 * time.Hour)}, none, nil,
			installed, map[string]SkillAudit{}, map[string][]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			db := NewDB()
			maps.Copy(db.AuditedAt, tt.auditedAt)
			asked := db.StaleAudits(installed, now)
			db.MergeAudits(asked, tt.got, tt.err, now)
			dueLater := db.StaleAudits(installed, now.Add(time.Hour))
			if !reflect.DeepEqual(asked, tt.asked) || !reflect.DeepEqual(db.Audits, tt.audits) || !reflect.DeepEqual(dueLater, tt.dueLater) {
				t.Errorf("asked %v, kept %v, due an hour later %v\nwant  %v, %v, %v", asked, db.Audits, dueLater, tt.asked, tt.audits, tt.dueLater)
			}
		})
	}
}

// MergeAudits reads a nil answer as "nothing was asked", so the opt-outs must
// return nil. The context is already cancelled, so a regression fails here
// instead of reaching skills.sh.
func TestSkillAuditsAskNothingWhenTelemetryIsOff(t *testing.T) {
	for _, opt := range []string{"DISABLE_TELEMETRY", "DO_NOT_TRACK"} {
		t.Run(opt, func(t *testing.T) {
			t.Setenv(opt, "1")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if got, err := SkillAudits(ctx, map[string][]string{"someone/skills": {"pathmaker"}}); got != nil || err != nil {
				t.Errorf("got %v, %v, want nil, nil", got, err)
			}
		})
	}
}

func TestSaveLeavesNoHalfWrittenCache(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kho")
	path := filepath.Join(dir, "security.json")
	db := NewDB()
	if err := db.Save(path); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	before, err := reader.Stat()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	q := Query{"npm", "diffkit", "0.23.0"}
	db.Merge(map[string][]string{q.Key(): {"GHSA-test"}}, map[string]Advisory{"GHSA-test": {ID: "GHSA-test", Package: "diffkit"}}, now)
	for i := range 3 {
		if err := db.Save(path); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Error("Save wrote over the cache in place instead of renaming a new file onto it")
	}
	if got, err := io.ReadAll(reader); err != nil || !bytes.Equal(got, old) {
		t.Errorf("a kho that opened the cache before Save read %q (%v), want the old %q", got, err, old)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "security.json" {
		t.Errorf("kept %d files, want only the cache: %v", len(entries), entries)
	}
	if got := Load(path).For(q); len(got) != 1 || got[0].ID != "GHSA-test" {
		t.Errorf("the saved cache lost its hits: %+v", got)
	}
}

func TestOldCacheIsDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security.json")
	os.WriteFile(path, []byte(`{"checked":{"PyPI/bramble@1.0":"2026-11-03T12:00:00Z"},"hits":{"PyPI/bramble@1.0":["X"]}}`), 0o644)
	if db := Load(path); len(db.Checked) != 0 || len(db.Hits) != 0 {
		t.Errorf("a cache without the current format was kept: %+v", db)
	}
}

// A cache from an older build that still loads reads as clean wherever a
// field moved or changed kind, so the shape must never change under an old
// format.
func TestStoredShapeMatchesFormat(t *testing.T) {
	db := NewDB()
	fill(t, reflect.ValueOf(db).Elem())
	data, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	var got []string
	jsonPaths(v, "", &got)
	slices.Sort(got)
	if !slices.Equal(got, stored) {
		t.Errorf("the cache now stores\n\t%s\nbut stored in cache.go says\n\t%s\nbump format, set stored to the new paths and add the new format to formats",
			strings.Join(got, "\n\t"), strings.Join(stored, "\n\t"))
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(stored, "\n")))); formats[format] != sum {
		t.Errorf("formats[%d] is %q but stored's checksum is %q: when stored changes, bump format and add the new one to formats with this checksum, leaving the old lines as they are",
			format, formats[format], sum)
	}
}

// fill gives every field a value, so omitempty hides none of them, and every
// map one entry under "*". A kind it does not know fails the test, so a new
// field cannot slip past it.
func fill(t *testing.T, v reflect.Value) {
	switch {
	case v.Type() == reflect.TypeFor[time.Time]():
		v.Set(reflect.ValueOf(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)))
	case v.Kind() == reflect.Struct:
		for i := range v.NumField() {
			fill(t, v.Field(i))
		}
	case v.Kind() == reflect.Pointer:
		e := reflect.New(v.Type().Elem())
		fill(t, e.Elem())
		v.Set(e)
	case v.Kind() == reflect.Map:
		e := reflect.New(v.Type().Elem()).Elem()
		fill(t, e)
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(reflect.ValueOf("*"), e)
	case v.Kind() == reflect.Slice:
		e := reflect.New(v.Type().Elem()).Elem()
		fill(t, e)
		v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), e))
	case v.Kind() == reflect.String:
		v.SetString("x")
	case v.Kind() == reflect.Bool:
		v.SetBool(true)
	case v.CanInt():
		v.SetInt(1)
	case v.CanUint():
		v.SetUint(1)
	case v.CanFloat():
		v.SetFloat(1.5)
	default:
		t.Fatalf("fill does not know how to fill a %s", v.Type())
	}
}

// jsonPaths lists every leaf with the Go type JSON decodes it to, so a field
// that changes kind changes its path.
func jsonPaths(v any, path string, out *[]string) {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			jsonPaths(e, strings.TrimPrefix(path+"."+k, "."), out)
		}
	case []any:
		for _, e := range v {
			jsonPaths(e, path+"[]", out)
		}
	default:
		*out = append(*out, fmt.Sprintf("%s %T", path, v))
	}
}

func TestVerdict(t *testing.T) {
	a := SkillAudit{Gen: "safe", Socket: "safe", Snyk: "medium"}
	if a.Worst() != "medium" || Verdict(a.Worst()) != "Warn" || Verdict("safe") != "Pass" || Verdict("high") != "Fail" || Verdict("") != "--" {
		t.Errorf("worst %q verdict %q", a.Worst(), Verdict(a.Worst()))
	}
}
