package vuln

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"time"
)

type DB struct {
	Format     int                   `json:"format"`
	Checked    map[string]time.Time  `json:"checked"`
	Hits       map[string][]string   `json:"hits"`
	Advisories map[string]Advisory   `json:"advisories"`
	Audits     map[string]SkillAudit `json:"audits"`
	AuditedAt  map[string]time.Time  `json:"auditedAt"`
	// Keyed by "ecosystem/name".
	History   map[string][]string  `json:"history"`
	HistoryAt map[string]time.Time `json:"historyAt"`
	Brew      Brew                 `json:"brew"`
}

// New advisories appear daily.
const MaxAge = 12 * time.Hour

// Bump format whenever what kho stores changes, so an older cache is dropped, not misread.
const format = 4

// stored is format's JSON shape. formats keeps a checksum of stored per format: add a
// line for each new format, never edit an old one. TestStoredShapeMatchesFormat checks both.
var stored = []string{
	"advisories.*.aliases[] string",
	"advisories.*.details string",
	"advisories.*.id string",
	"advisories.*.package string",
	"advisories.*.published string",
	"advisories.*.ranges[].fixed string",
	"advisories.*.ranges[].introduced string",
	"advisories.*.ranges[].last_affected string",
	"advisories.*.severity string",
	"advisories.*.summary string",
	"advisories.*.versions[] string",
	"auditedAt.* string",
	"audits.*.analyzed string",
	"audits.*.gen string",
	"audits.*.snyk string",
	"audits.*.socket string",
	"audits.*.socketAlerts float64",
	"brew.at string",
	"brew.complete bool",
	"brew.note string",
	"brew.skipped.* string",
	"checked.* string",
	"format float64",
	"history.*[] string",
	"historyAt.* string",
	"hits.*[] string",
}

var formats = map[int]string{
	3: "21601456804166155faf4d9de5de86a90d6f46b0ca8f263fe6a214cf176ee11c",
	4: "ea4648fa7adbecb99299174bafb87274fbf1088eda90509b8c7fd62cab810df8",
}

func NewDB() *DB {
	return &DB{
		Format:     format,
		Checked:    map[string]time.Time{},
		Hits:       map[string][]string{},
		Advisories: map[string]Advisory{},
		Audits:     map[string]SkillAudit{},
		AuditedAt:  map[string]time.Time{},
		History:    map[string][]string{},
		HistoryAt:  map[string]time.Time{},
	}
}

func Path() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "kho", "security.json")
}

func Load(path string) *DB {
	db := NewDB()
	db.Format = 0
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, db)
	}
	if db.Format != format {
		return NewDB()
	}
	return db
}

func (db *DB) Save(path string) error {
	data, err := json.Marshal(db)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Write next to the cache and rename, so a second kho running at the same
	// time loads either the old file or the new one, never half of one.
	tmp, err := os.CreateTemp(dir, "security-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (db *DB) Stale(queries []Query, now time.Time) []Query {
	var stale []Query
	for _, q := range queries {
		if t, ok := db.Checked[q.Key()]; !ok || now.Sub(t) > MaxAge {
			stale = append(stale, q)
		}
	}
	return stale
}

func (db *DB) Merge(hits map[string][]string, advisories map[string]Advisory, now time.Time) {
	for k, ids := range hits {
		db.Hits[k] = ids
		db.Checked[k] = now
	}
	for id, a := range advisories {
		db.Advisories[id] = a
	}
}

func (db *DB) StaleAudits(bySource map[string][]string, now time.Time) map[string][]string {
	stale := map[string][]string{}
	for source, slugs := range bySource {
		for _, slug := range slugs {
			if t, ok := db.AuditedAt[AuditKey(source, slug)]; !ok || now.Sub(t) > MaxAge {
				stale[source] = append(stale[source], slug)
			}
		}
	}
	return stale
}

// An answer marks every asked skill fresh, even one skills.sh has no audit for. A failed
// ask marks none fresh, but the audits that came back still count. A nil answer means
// nothing was asked (telemetry off), so it marks none fresh either.
func (db *DB) MergeAudits(asked map[string][]string, audits map[string]SkillAudit, err error, now time.Time) {
	maps.Copy(db.Audits, audits)
	if err != nil || audits == nil {
		return
	}
	for source, slugs := range asked {
		for _, slug := range slugs {
			db.AuditedAt[AuditKey(source, slug)] = now
		}
	}
}

func (db *DB) For(q Query) []Advisory {
	var advs []Advisory
	for _, id := range db.Hits[q.Key()] {
		if a, ok := db.Advisories[id]; ok {
			advs = append(advs, a)
		}
	}
	return Dedupe(advs)
}

func historyKey(ecosystem, name string) string { return ecosystem + "/" + name }

func (db *DB) HistoryFresh(ecosystem, name string, now time.Time) bool {
	t, ok := db.HistoryAt[historyKey(ecosystem, name)]
	return ok && now.Sub(t) <= MaxAge
}

func (db *DB) MergeHistory(ecosystem, name string, advs []Advisory, now time.Time) {
	var ids []string
	for _, a := range advs {
		db.Advisories[a.ID] = a
		ids = append(ids, a.ID)
	}
	db.History[historyKey(ecosystem, name)] = ids
	db.HistoryAt[historyKey(ecosystem, name)] = now
}

func (db *DB) Known(ecosystem, name string) []Advisory {
	var advs []Advisory
	for _, id := range db.History[historyKey(ecosystem, name)] {
		if a, ok := db.Advisories[id]; ok {
			advs = append(advs, a)
		}
	}
	return Dedupe(advs)
}
