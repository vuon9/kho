package vuln

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DB is what kho knows about security, saved between runs so badges show
// at once and a scan only asks about what changed or went stale.
type DB struct {
	Format     int                   `json:"format"`
	Checked    map[string]time.Time  `json:"checked"`
	Hits       map[string][]string   `json:"hits"`
	Advisories map[string]Advisory   `json:"advisories"`
	Audits     map[string]SkillAudit `json:"audits"`
	AuditedAt  map[string]time.Time  `json:"auditedAt"`
	// History maps "ecosystem/name" to every advisory the package ever had.
	History   map[string][]string  `json:"history"`
	HistoryAt map[string]time.Time `json:"historyAt"`
}

// MaxAge is how long a result stays fresh. New advisories appear daily, so
// results older than this are asked for again.
const MaxAge = 12 * time.Hour

// format changes whenever what kho stores changes, so a cache from an older
// build is dropped instead of misread.
const format = 3

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

// Load reads the cache at path. A missing or unreadable cache is an empty one.
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

// Stale picks the queries with no result, or one older than MaxAge.
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

// For returns the advisories that affect q, without aliases, worst first.
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

// HistoryFresh reports whether the package's full advisory history is cached
// and younger than MaxAge.
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

// Known is the package's full advisory history, without aliases.
func (db *DB) Known(ecosystem, name string) []Advisory {
	var advs []Advisory
	for _, id := range db.History[historyKey(ecosystem, name)] {
		if a, ok := db.Advisories[id]; ok {
			advs = append(advs, a)
		}
	}
	return Dedupe(advs)
}
