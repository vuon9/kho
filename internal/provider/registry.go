package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// fillLatest looks up every package concurrently. A failed lookup leaves that
// package's latest unknown and says why in its note.
func fillLatest(ctx context.Context, pkgs []Package, lookup func(context.Context, Package) (string, error)) []Package {
	var g errgroup.Group
	g.SetLimit(8)
	for i := range pkgs {
		g.Go(func() error {
			v, err := lookup(ctx, pkgs[i])
			if err != nil {
				pkgs[i].Note = "latest unknown: " + err.Error()
				return nil
			}
			pkgs[i].Latest = v
			markOutdated(&pkgs[i])
			return nil
		})
	}
	g.Wait()
	return pkgs
}

func getJSON(ctx context.Context, url string, header http.Header, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func pypiLatest(ctx context.Context, name string) (string, error) {
	var r struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	err := getJSON(ctx, "https://pypi.org/pypi/"+name+"/json", nil, &r)
	return r.Info.Version, err
}

func goProxyLatest(ctx context.Context, module string) (string, error) {
	var r struct{ Version string }
	err := getJSON(ctx, "https://proxy.golang.org/"+escapeModule(module)+"/@latest", nil, &r)
	return r.Version, err
}

// escapeModule applies the module proxy's case encoding: "A" becomes "!a".
func escapeModule(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

type githubTree struct {
	SHA  string `json:"sha"`
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"tree"`
}

// folderHashes maps every folder in the repo's default branch to its git tree
// SHA, the same hash the skills CLI records as skillFolderHash.
func folderHashes(ctx context.Context, repo string) (map[string]string, error) {
	var t githubTree
	if err := githubGet(ctx, "repos/"+repo+"/git/trees/HEAD?recursive=1", &t); err != nil {
		return nil, err
	}
	hashes := map[string]string{"": t.SHA}
	for _, e := range t.Tree {
		if e.Type == "tree" {
			hashes[e.Path] = e.SHA
		}
	}
	return hashes, nil
}

func githubGet(ctx context.Context, path string, v any) error {
	header := http.Header{"Accept": {"application/vnd.github+json"}}
	if token := githubToken(); token != "" {
		header.Set("Authorization", "Bearer "+token)
	}
	return getJSON(ctx, "https://api.github.com/"+path, header, v)
}

var githubToken = sync.OnceValue(func() string {
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if !onPath("gh") {
		return ""
	}
	out, err := run(context.Background(), "gh", "auth", "token")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
})

var githubURL = regexp.MustCompile(`github\.com[/:]([\w.-]+)/([\w.-]+)`)

// githubRepo finds "owner/name" in any GitHub URL, such as a tarball or git remote.
func githubRepo(urls ...string) string {
	for _, u := range urls {
		if m := githubURL.FindStringSubmatch(u); m != nil {
			return m[1] + "/" + strings.TrimSuffix(m[2], ".git")
		}
	}
	return ""
}

func githubReleases(ctx context.Context, repo string) ([]Release, error) {
	var rs []struct {
		TagName     string    `json:"tag_name"`
		Body        string    `json:"body"`
		HTMLURL     string    `json:"html_url"`
		PublishedAt time.Time `json:"published_at"`
		Draft       bool      `json:"draft"`
	}
	if err := githubGet(ctx, "repos/"+repo+"/releases?per_page=100", &rs); err != nil {
		return nil, err
	}
	var out []Release
	for _, r := range rs {
		if !r.Draft {
			out = append(out, Release{Version: r.TagName, Date: r.PublishedAt, Notes: r.Body, URL: r.HTMLURL})
		}
	}
	return out, nil
}

// TagVersion strips what tags add around a version: "v1.2", "pkg@1.2", "pkg/v1.2".
func TagVersion(tag string) string {
	if i := strings.LastIndexAny(tag, "@/"); i >= 0 {
		tag = tag[i+1:]
	}
	return strings.TrimPrefix(tag, "v")
}

// withNotes copies GitHub release notes onto registry versions with the same
// number. Notes are a bonus, so a failed lookup leaves the versions as they are.
func withNotes(ctx context.Context, repo string, rels []Release) []Release {
	if repo == "" {
		return rels
	}
	gh, err := githubReleases(ctx, repo)
	if err != nil {
		return rels
	}
	byVersion := map[string]Release{}
	for _, r := range gh {
		byVersion[TagVersion(r.Version)] = r
	}
	for i, r := range rels {
		if g, ok := byVersion[TagVersion(r.Version)]; ok {
			rels[i].Notes, rels[i].URL = g.Notes, g.URL
		}
	}
	return rels
}

func newestFirst(rels []Release) {
	slices.SortStableFunc(rels, func(a, b Release) int { return b.Date.Compare(a.Date) })
}
