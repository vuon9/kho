package vuln

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// githubRepoURL reads owner and name out of a GitHub URL. The compare endpoint
// is the only thing that can answer "does this tag already contain that
// commit", and it exists for GitHub repositories only.
var githubRepoURL = regexp.MustCompile(`^https?://(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)

// githubCompare reports whether ref already contains sha. GitHub answers
// "ahead" when ref is downstream of sha, "behind" when sha is the newer one,
// and "diverged" when neither contains the other.
func githubCompare(ctx context.Context, repoURL, sha, ref string) (bool, error) {
	m := githubRepoURL.FindStringSubmatch(strings.TrimSpace(repoURL))
	if m == nil {
		return false, fmt.Errorf("%s is not a GitHub repository", repoURL)
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s", m[1], m[2], sha, ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := do(req, &out); err != nil {
		return false, err
	}
	switch out.Status {
	case "ahead", "identical":
		return true, nil
	case "behind", "diverged":
		return false, nil
	}
	return false, fmt.Errorf("comparing %s with %s answered %q", sha, ref, out.Status)
}

// githubToken is optional: unauthenticated compare calls are allowed, they just
// count against a lower hourly limit.
func githubToken() string {
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

// compareCommits is this package's one GitHub call, kept in a variable so tests
// can answer without the network.
var compareCommits = githubCompare

// containsFix reports whether ref already contains every one of shas, and the
// ref itself when it does. Answers are cached per repository, ref and commit,
// because both a tag and a commit are immutable: a yes or a no never changes.
// A commit that cannot be resolved leaves the answer false without caching it,
// so the next run can try again.
func (db *DB) containsFix(ctx context.Context, repoURL, ref string, shas []string) (string, bool) {
	if ref == "" || repoURL == "" || len(shas) == 0 {
		return "", false
	}
	if db.Containment == nil {
		db.Containment = map[string]bool{}
	}
	contained := true
	for _, sha := range shas {
		key := repoURL + "@" + ref + "@" + sha
		ok, cached := db.Containment[key]
		if !cached {
			var err error
			ok, err = compareCommits(ctx, repoURL, sha, ref)
			if err != nil {
				contained = false
				continue
			}
			db.Containment[key] = ok
		}
		if !ok {
			contained = false
		}
	}
	return ref, contained
}
