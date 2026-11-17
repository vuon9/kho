package vuln

import "time"

// OSV has no such ecosystem, so a query with it must never go to OSV.
const Homebrew = "Homebrew"

type BrewResult struct {
	Checked             int
	Complete            bool
	Findings            []BrewFinding
	Skipped             []string
	OutdatedWithoutSBOM []string
	Unscanned           map[string]string
}

type BrewFinding struct {
	Formula    string
	Version    string
	Advisories []Advisory
}

type Brew struct {
	At       time.Time         `json:"at,omitzero"`
	Complete bool              `json:"complete"`
	Note     string            `json:"note,omitempty"`
	Skipped  map[string]string `json:"skipped,omitempty"`
}

// Every checked formula is marked fresh, even with no findings, so the next scan runs
// only for a new formula or a stale cache. Findings for a formula Homebrew could not
// check are dropped, because Homebrew assessed another version.
func (db *DB) MergeBrew(result BrewResult, checked []Query, now time.Time) {
	db.Brew = Brew{At: now, Complete: result.Complete, Skipped: map[string]string{}}
	for _, name := range result.Skipped {
		db.Brew.Skipped[name] = "Homebrew found no source it could match"
	}
	for _, name := range result.OutdatedWithoutSBOM {
		db.Brew.Skipped[name] = "installed source unknown; Homebrew checked the current formula"
	}
	for name, why := range result.Unscanned {
		switch why {
		case "untrusted_tap":
			db.Brew.Skipped[name] = "from an untrusted tap"
		case "resolution_error":
			db.Brew.Skipped[name] = "Homebrew could not resolve it"
		default:
			db.Brew.Skipped[name] = "Homebrew could not check it"
		}
	}
	byName := map[string]Query{}
	for _, q := range checked {
		byName[q.Name] = q
		db.Hits[q.Key()] = nil
		db.Checked[q.Key()] = now
	}
	for _, f := range result.Findings {
		q, ok := byName[f.Formula]
		if !ok {
			continue
		}
		if _, skipped := db.Brew.Skipped[f.Formula]; skipped {
			continue
		}
		if q.Version != f.Version {
			db.Brew.Skipped[f.Formula] = "Homebrew checked version " + f.Version
			continue
		}
		var ids []string
		for _, a := range f.Advisories {
			if !a.Affects(q.Version) {
				continue
			}
			key := brewKey(q.Name, a.ID)
			db.Advisories[key] = a
			ids = append(ids, key)
		}
		db.Hits[q.Key()] = ids
	}
	if len(db.Brew.Skipped) > 0 {
		db.Brew.Complete = false
	}
}

// One CVE can reach two formulae and an npm package, and each knows its own versions and fix.
func brewKey(formula, id string) string { return "brew/" + formula + "/" + id }

// So every formula says why instead of claiming it has no advisories.
func (db *DB) SetBrewUnsupported(note string, now time.Time) {
	db.Brew = Brew{At: now, Note: note}
}

func (db *DB) BrewScanned() bool { return !db.Brew.At.IsZero() }

func (db *DB) BrewComplete() bool { return db.Brew.Complete }

func (db *DB) BrewNote() string { return db.Brew.Note }

func (db *DB) BrewSkip(name string) string { return db.Brew.Skipped[name] }
