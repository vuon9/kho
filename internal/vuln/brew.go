package vuln

import "time"

// Homebrew is the ecosystem name kho uses in its cache for the scan Homebrew
// runs itself. OSV has no such ecosystem, so a query with it must never go to
// OSV.
const Homebrew = "Homebrew"

// BrewResult is what one `brew vulns --json` run reports: the open findings,
// and what Homebrew could not check.
type BrewResult struct {
	Checked             int
	Complete            bool
	Findings            []BrewFinding
	Skipped             []string
	OutdatedWithoutSBOM []string
	Unscanned           map[string]string
}

// BrewFinding is one formula Homebrew reported open advisories for.
type BrewFinding struct {
	Formula    string
	Version    string
	Advisories []Advisory
}

// Brew is what kho keeps from the last Homebrew scan, so a row can say when it
// was checked and why Homebrew left it out.
type Brew struct {
	At       time.Time         `json:"at,omitzero"`
	Complete bool              `json:"complete"`
	Note     string            `json:"note,omitempty"`
	Skipped  map[string]string `json:"skipped,omitempty"`
}

// MergeBrew stores a Homebrew scan. Every checked formula is marked fresh,
// including the ones with no findings, so the next scan runs only when a new
// formula appears or the cache goes stale. A formula Homebrew could not check
// keeps the reason, and findings for it are dropped because Homebrew assessed
// another version.
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
			db.Advisories[brewKey(a.ID)] = a
			ids = append(ids, brewKey(a.ID))
		}
		db.Hits[q.Key()] = ids
	}
	if len(db.Brew.Skipped) > 0 {
		db.Brew.Complete = false
	}
}

// brewKey keeps Homebrew's records apart from OSV's: one CVE can reach a
// formula and an npm package, and each source knows its own versions.
func brewKey(id string) string { return "brew/" + id }

// SetBrewUnsupported remembers that the brew on PATH cannot scan at all, so
// every formula says why instead of claiming it has no advisories.
func (db *DB) SetBrewUnsupported(note string, now time.Time) {
	db.Brew = Brew{At: now, Note: note}
}

// BrewScanned reports whether a Homebrew scan has ever been stored.
func (db *DB) BrewScanned() bool { return !db.Brew.At.IsZero() }

// BrewComplete reports whether Homebrew checked every installed formula.
func (db *DB) BrewComplete() bool { return db.Brew.Complete }

// BrewNote is why Homebrew could not scan at all, or "".
func (db *DB) BrewNote() string { return db.Brew.Note }

// BrewSkip is why Homebrew left one formula out, or "".
func (db *DB) BrewSkip(name string) string { return db.Brew.Skipped[name] }
