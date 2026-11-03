// Package vuln finds published security advisories for installed packages
// through OSV (osv.dev) and audits for agent skills through skills.sh, and
// keeps what it learns in a local cache.
package vuln

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

// Query names one installed package version in an OSV ecosystem.
type Query struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

func (q Query) Key() string {
	return q.Ecosystem + "/" + q.Name + "@" + q.Version
}

type Range struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Advisory struct {
	ID        string    `json:"id"`
	Aliases   []string  `json:"aliases,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Details   string    `json:"details,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	Published time.Time `json:"published,omitzero"`
	Package   string    `json:"package"`
	Ranges    []Range   `json:"ranges,omitempty"`
	Versions  []string  `json:"versions,omitempty"`
}

func (a Advisory) URL() string {
	return "https://osv.dev/vulnerability/" + a.ID
}

// Affects reports whether the advisory covers version. Ranges are read as
// OSV writes them: each event opens or closes the affected span in order.
func (a Advisory) Affects(version string) bool {
	if slices.Contains(a.Versions, version) || slices.Contains(a.Versions, strings.TrimPrefix(version, "v")) {
		return true
	}
	affected := false
	for _, r := range a.Ranges {
		switch {
		case r.Introduced != "":
			if r.Introduced == "0" || Compare(version, r.Introduced) >= 0 {
				affected = true
			}
		case r.Fixed != "":
			if Compare(version, r.Fixed) >= 0 {
				affected = false
			}
		case r.LastAffected != "":
			if Compare(version, r.LastAffected) > 0 {
				affected = false
			}
		}
	}
	return affected
}

// FixedAfter is the lowest fixed version above version, or "" when no fix
// has been published.
func (a Advisory) FixedAfter(version string) string {
	best := ""
	for _, r := range a.Ranges {
		if r.Fixed != "" && Compare(r.Fixed, version) > 0 && (best == "" || Compare(r.Fixed, best) < 0) {
			best = r.Fixed
		}
	}
	return best
}

// Rank orders severities from most to least urgent.
func Rank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MODERATE", "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

// Compare orders version strings so that 1.10 sorts after 1.9 and "v1.2"
// equals "1.2".
func Compare(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	for a != "" && b != "" {
		ra, rb := run(a), run(b)
		a, b = a[len(ra):], b[len(rb):]
		var c int
		if isDigit(ra[0]) && isDigit(rb[0]) {
			ra, rb = strings.TrimLeft(ra, "0"), strings.TrimLeft(rb, "0")
			c = cmp.Or(len(ra)-len(rb), strings.Compare(ra, rb))
		} else {
			c = strings.Compare(ra, rb)
		}
		if c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}

func run(s string) string {
	i := 1
	for i < len(s) && isDigit(s[i]) == isDigit(s[0]) {
		i++
	}
	return s[:i]
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Scan asks OSV which advisories affect each query, then fetches the
// details of every advisory not in known.
func Scan(ctx context.Context, queries []Query, known map[string]bool) (map[string][]string, map[string]Advisory, error) {
	hits := map[string][]string{}
	for chunk := range slices.Chunk(queries, 1000) {
		ids, err := queryBatch(ctx, chunk)
		if err != nil {
			return nil, nil, err
		}
		for i, q := range chunk {
			hits[q.Key()] = ids[i]
		}
	}
	var missing []string
	for _, ids := range hits {
		for _, id := range ids {
			if !known[id] && !slices.Contains(missing, id) {
				missing = append(missing, id)
			}
		}
	}
	fetched := make([]Advisory, len(missing))
	var g errgroup.Group
	g.SetLimit(8)
	for i, id := range missing {
		g.Go(func() error {
			a, err := fetchAdvisory(ctx, id)
			fetched[i] = a
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}
	advisories := map[string]Advisory{}
	for _, a := range fetched {
		advisories[a.ID] = a
	}
	return hits, advisories, nil
}

func post(ctx context.Context, url string, body, v any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	return do(req, v)
}

func get(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return do(req, v)
}

func do(req *http.Request, v any) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", req.URL.Host, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func queryBatch(ctx context.Context, queries []Query) ([][]string, error) {
	type pkg struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type query struct {
		Package pkg    `json:"package"`
		Version string `json:"version"`
	}
	body := struct {
		Queries []query `json:"queries"`
	}{}
	for _, q := range queries {
		body.Queries = append(body.Queries, query{pkg{q.Name, q.Ecosystem}, q.Version})
	}
	var resp struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := post(ctx, "https://api.osv.dev/v1/querybatch", body, &resp); err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	ids := make([][]string, len(queries))
	for i, r := range resp.Results {
		for _, v := range r.Vulns {
			ids[i] = append(ids[i], v.ID)
		}
	}
	return ids, nil
}

type osvRecord struct {
	ID               string    `json:"id"`
	Aliases          []string  `json:"aliases"`
	Summary          string    `json:"summary"`
	Details          string    `json:"details"`
	Published        time.Time `json:"published"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string  `json:"type"`
			Events []Range `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func fetchAdvisory(ctx context.Context, id string) (Advisory, error) {
	var r osvRecord
	if err := get(ctx, "https://api.osv.dev/v1/vulns/"+id, &r); err != nil {
		return Advisory{}, fmt.Errorf("osv %s: %w", id, err)
	}
	return r.advisory(), nil
}

func (r osvRecord) advisory() Advisory {
	a := Advisory{
		ID:        r.ID,
		Aliases:   r.Aliases,
		Summary:   r.Summary,
		Details:   r.Details,
		Severity:  strings.ToUpper(r.DatabaseSpecific.Severity),
		Published: r.Published,
	}
	for _, af := range r.Affected {
		a.Package = cmp.Or(a.Package, af.Package.Name)
		a.Versions = append(a.Versions, af.Versions...)
		for _, rg := range af.Ranges {
			if rg.Type != "GIT" {
				a.Ranges = append(a.Ranges, rg.Events...)
			}
		}
	}
	if a.Summary == "" {
		a.Summary = firstSentences(a.Details)
	}
	return a
}

// firstSentences stands in for a missing summary. Some databases leave it
// empty and put a whole paragraph in the details, often opening with what the
// project is, so it keeps whole sentences up to 160 characters.
func firstSentences(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) <= 160 {
		return s
	}
	if i := strings.LastIndex(s[:160], ". "); i > 0 {
		return s[:i+1]
	}
	return s[:159] + "…"
}

// Dedupe drops advisories that are aliases of one already kept, preferring
// GitHub's GHSA records, which carry a severity.
func Dedupe(advs []Advisory) []Advisory {
	slices.SortStableFunc(advs, func(a, b Advisory) int {
		return cmp.Or(
			boolRank(!strings.HasPrefix(a.ID, "GHSA-"))-boolRank(!strings.HasPrefix(b.ID, "GHSA-")),
			Rank(a.Severity)-Rank(b.Severity),
		)
	})
	seen := map[string]bool{}
	var out []Advisory
	for _, a := range advs {
		if seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		for _, alias := range a.Aliases {
			seen[alias] = true
		}
		out = append(out, a)
	}
	slices.SortStableFunc(out, func(a, b Advisory) int { return Rank(a.Severity) - Rank(b.Severity) })
	return out
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SkillAudit is what skills.sh reports for one skill: a risk level from each
// of three auditors, and Socket's alert count.
type SkillAudit struct {
	Gen          string    `json:"gen,omitempty"`
	Socket       string    `json:"socket,omitempty"`
	SocketAlerts int       `json:"socketAlerts,omitempty"`
	Snyk         string    `json:"snyk,omitempty"`
	Analyzed     time.Time `json:"analyzed,omitzero"`
}

// Worst is the highest risk any auditor gave.
func (a SkillAudit) Worst() string {
	worst := ""
	for _, r := range []string{a.Gen, a.Socket, a.Snyk} {
		if riskRank(r) > riskRank(worst) {
			worst = r
		}
	}
	return worst
}

func riskRank(risk string) int {
	return map[string]int{"safe": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[risk]
}

// Verdict turns a risk level into the Pass, Warn or Fail that skills.sh shows.
func Verdict(risk string) string {
	switch risk {
	case "safe", "low":
		return "Pass"
	case "medium":
		return "Warn"
	case "high", "critical":
		return "Fail"
	}
	return "--"
}

// SkillAudits fetches skills.sh audits for skills by GitHub source. It uses
// the same endpoint as the skills CLI and honors the same opt-outs.
func SkillAudits(ctx context.Context, bySource map[string][]string) (map[string]SkillAudit, error) {
	if os.Getenv("DISABLE_TELEMETRY") != "" || os.Getenv("DO_NOT_TRACK") != "" {
		return nil, nil
	}
	out := map[string]SkillAudit{}
	for source, slugs := range bySource {
		var resp map[string]struct {
			Ath struct {
				Risk       string    `json:"risk"`
				AnalyzedAt time.Time `json:"analyzedAt"`
			} `json:"ath"`
			Socket struct {
				Risk   string `json:"risk"`
				Alerts int    `json:"alerts"`
			} `json:"socket"`
			Snyk struct {
				Risk string `json:"risk"`
			} `json:"snyk"`
		}
		q := url.Values{"source": {source}, "skills": {strings.Join(slugs, ",")}}
		if err := get(ctx, "https://www.skills.sh/tele/audit?"+q.Encode(), &resp); err != nil {
			return out, fmt.Errorf("skills.sh: %w", err)
		}
		for slug, r := range resp {
			out[source+"/"+slug] = SkillAudit{Gen: r.Ath.Risk, Socket: r.Socket.Risk, SocketAlerts: r.Socket.Alerts, Snyk: r.Snyk.Risk, Analyzed: r.Ath.AnalyzedAt}
		}
	}
	return out, nil
}

// SkillPage is the skill's page on skills.sh, which shows the full audits.
func SkillPage(source, slug string) string {
	return "https://www.skills.sh/" + source + "/" + slug
}

// History lists every advisory OSV has for a package, whatever the version,
// so versions ahead of the installed one can be checked too.
func History(ctx context.Context, ecosystem, name string) ([]Advisory, error) {
	var advs []Advisory
	token := ""
	for {
		body := map[string]any{"package": map[string]string{"name": name, "ecosystem": ecosystem}}
		if token != "" {
			body["page_token"] = token
		}
		var resp struct {
			Vulns         []osvRecord `json:"vulns"`
			NextPageToken string      `json:"next_page_token"`
		}
		if err := post(ctx, "https://api.osv.dev/v1/query", body, &resp); err != nil {
			return nil, fmt.Errorf("osv: %w", err)
		}
		for _, r := range resp.Vulns {
			advs = append(advs, r.advisory())
		}
		if token = resp.NextPageToken; token == "" {
			return advs, nil
		}
	}
}
