package vuln

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A formula Homebrew reports with fix commits cannot be cleared by a version,
// so the tag Homebrew scanned decides: when it already contains the fix, the
// advisory is resolved instead of staying a finding forever.
func TestBrewResolvesFixesAlreadyInTheBuild(t *testing.T) {
	db := NewDB()
	now := time.Now()
	q := Query{Ecosystem: Homebrew, Name: "llama.cpp", Version: "1.0.0"}
	finding := BrewFinding{
		Formula: "llama.cpp", Version: "1.0.0",
		RepoURL: "https://github.com/ggml-org/llama.cpp", Tag: "1.0.0",
		Advisories: []Advisory{{
			ID:          "CVE-2024-42479",
			Severity:    "CRITICAL",
			Summary:     "write-what-where",
			Package:     "llama.cpp",
			Versions:    []string{"1.0.0"},
			CommitFixes: []string{"b72942fac998672a79a1ae3c03b340f7e629980b"},
		}},
	}
	result := BrewResult{Checked: 1, Complete: true, Findings: []BrewFinding{finding}}

	stubCompare(t, func(_ context.Context, repo, sha, ref string) (bool, error) {
		if repo != "https://github.com/ggml-org/llama.cpp" || ref != "1.0.0" {
			t.Errorf("asked about %s at %s, want the scanned repo and tag", repo, ref)
		}
		return true, nil
	})

	db.MergeBrewScanned(context.Background(), result, []Query{q}, now)

	if ids := db.Hits[q.Key()]; len(ids) != 0 {
		t.Errorf("the advisory stayed a finding: %v", ids)
	}
	if got := db.BrewResolved()["llama.cpp"]; len(got) != 1 || got[0] != "CVE-2024-42479" {
		t.Errorf("resolved = %v, want the CVE named", got)
	}
	if a := db.Advisories["brew/CVE-2024-42479"]; a.ContainedIn != "1.0.0" {
		t.Errorf("containedIn = %q, want the scanned tag", a.ContainedIn)
	}
}

// The flip side: a tag that does not contain the fix keeps the finding, because
// the installed build really is missing it.
func TestBrewKeepsFixesTheBuildLacks(t *testing.T) {
	db := NewDB()
	now := time.Now()
	q := Query{Ecosystem: Homebrew, Name: "llama.cpp", Version: "0.9.0"}
	result := BrewResult{Checked: 1, Complete: true, Findings: []BrewFinding{{
		Formula: "llama.cpp", Version: "0.9.0",
		RepoURL: "https://github.com/ggml-org/llama.cpp", Tag: "0.9.0",
		Advisories: []Advisory{{
			ID: "CVE-2026-0001", Severity: "HIGH", Package: "llama.cpp",
			Versions:    []string{"0.9.0"},
			CommitFixes: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}},
	}}}

	stubCompare(t, func(context.Context, string, string, string) (bool, error) { return false, nil })
	db.MergeBrewScanned(context.Background(), result, []Query{q}, now)

	if ids := db.Hits[q.Key()]; len(ids) != 1 {
		t.Errorf("a fix the build lacks must stay a finding, got %v", ids)
	}
	if len(db.BrewResolved()) != 0 {
		t.Errorf("nothing should be resolved: %v", db.BrewResolved())
	}
}

// An API that cannot answer must never clear a finding.
func TestBrewKeepsFindingsWhenTheCompareFails(t *testing.T) {
	db := NewDB()
	now := time.Now()
	q := Query{Ecosystem: Homebrew, Name: "llama.cpp", Version: "1.0.0"}
	result := BrewResult{Checked: 1, Complete: true, Findings: []BrewFinding{{
		Formula: "llama.cpp", Version: "1.0.0",
		RepoURL: "https://github.com/ggml-org/llama.cpp", Tag: "1.0.0",
		Advisories: []Advisory{{
			ID: "CVE-2026-0002", Package: "llama.cpp", Versions: []string{"1.0.0"},
			CommitFixes: []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		}},
	}}}

	stubCompare(t, func(context.Context, string, string, string) (bool, error) {
		return false, errors.New("403 rate limited")
	})
	db.MergeBrewScanned(context.Background(), result, []Query{q}, now)

	if ids := db.Hits[q.Key()]; len(ids) != 1 {
		t.Errorf("an unreachable API must leave the finding alone, got %v", ids)
	}
	if _, cached := db.Containment["https://github.com/ggml-org/llama.cpp@1.0.0@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]; cached {
		t.Error("a failed answer was cached")
	}
}

// Answers are cached per repo, tag and commit: a tag and a commit never change,
// so the same question must not be asked twice.
func TestBrewAsksOncePerCommit(t *testing.T) {
	db := NewDB()
	now := time.Now()
	q := Query{Ecosystem: Homebrew, Name: "llama.cpp", Version: "1.0.0"}
	sha := "cccccccccccccccccccccccccccccccccccccccc"
	finding := BrewFinding{
		Formula: "llama.cpp", Version: "1.0.0",
		RepoURL: "https://github.com/ggml-org/llama.cpp", Tag: "1.0.0",
		Advisories: []Advisory{{ID: "CVE-1", Package: "llama.cpp", Versions: []string{"1.0.0"}, CommitFixes: []string{sha}},
			{ID: "CVE-2", Package: "llama.cpp", Versions: []string{"1.0.0"}, CommitFixes: []string{sha}}},
	}
	asked := 0
	stubCompare(t, func(context.Context, string, string, string) (bool, error) { asked++; return true, nil })
	db.MergeBrewScanned(context.Background(), BrewResult{Checked: 1, Complete: true, Findings: []BrewFinding{finding}}, []Query{q}, now)
	if asked != 1 {
		t.Errorf("asked %d times for one commit, want 1", asked)
	}
}

// stubCompare swaps the GitHub call for a test double and restores it after.
func stubCompare(t *testing.T, fn func(ctx context.Context, repo, sha, ref string) (bool, error)) {
	t.Helper()
	old := compareCommits
	compareCommits = fn
	t.Cleanup(func() { compareCommits = old })
}
