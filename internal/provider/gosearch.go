package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Go has no registry search, so a keyword search goes through GitHub's
// repository search, then reads each repository's module path and main
// packages. It is best effort: a Go package that is not on GitHub, or not a
// module, is not found.
const (
	goSearchRepos   = 8
	goSearchMains   = 2
	goSearchWorkers = 4
)

// githubRepository is one repository from GitHub's search API.
type githubRepository struct {
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	Stars       int    `json:"stargazers_count"`
	Fork        bool   `json:"fork"`
	Archived    bool   `json:"archived"`
}

// goModuleInfo is what the module proxy says about a module.
type goModuleInfo struct {
	Version string
	RepoURL string
}

// The reads a Go keyword search makes, so tests can feed captured answers.
var (
	gitHubRepos    = searchGitHubRepos
	goModFile      = fetchGoModFile
	gitTreePaths   = fetchGitTreePaths
	goModuleLatest = lookupGoModule
)

// Search finds Go packages by keyword through GitHub. A query that names a
// package or module path is resolved exactly instead, so a pasted pkg.go.dev
// URL works in the same box.
func (GoBin) Search(ctx context.Context, query string, limit int) ([]Package, error) {
	if target, ok := goPathQuery(query); ok {
		p, err := GoBin{}.Find(ctx, "go", target)
		if err != nil {
			return nil, err
		}
		return []Package{p}, nil
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("no Go search query")
	}
	limit = searchLimit(limit)
	n := min(max(limit, 1), goSearchRepos)
	repos, err := gitHubRepos(ctx, query, n)
	if err != nil {
		return nil, err
	}
	results := make([][]Package, len(repos))
	var errs []error
	var mu sync.Mutex
	var g errgroup.Group
	g.SetLimit(goSearchWorkers)
	for i, repo := range repos {
		i, repo := i, repo
		if repo.Fork || repo.Archived {
			continue
		}
		g.Go(func() error {
			pkgs, err := goRepoPackages(ctx, repo, query)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return nil
			}
			results[i] = pkgs
			return nil
		})
	}
	g.Wait()
	var out []Package
	for _, pkgs := range results {
		for _, p := range pkgs {
			if len(out) < limit {
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errs[0]
	}
	return out, nil
}

// goPathQuery reads a pasted pkg.go.dev URL or a bare package path. A keyword
// is not a path.
func goPathQuery(q string) (string, bool) {
	q = strings.TrimSpace(q)
	for _, prefix := range []string{"https://pkg.go.dev/", "http://pkg.go.dev/", "pkg.go.dev/"} {
		if strings.HasPrefix(q, prefix) {
			q = strings.TrimPrefix(q, prefix)
			break
		}
	}
	if i := strings.IndexAny(q, "?#"); i >= 0 {
		q = q[:i]
	}
	if i := strings.LastIndex(q, "@"); i > 0 {
		q = q[:i]
	}
	q = strings.TrimSuffix(q, "/")
	if q == "" || strings.ContainsAny(q, " \t\n") || strings.Contains("/"+q+"/", "/../") {
		return "", false
	}
	first, _, _ := strings.Cut(q, "/")
	if !strings.Contains(q, "/") || !strings.Contains(first, ".") {
		return "", false
	}
	return q, true
}

// resolveGoModule finds the module that holds target by trying target and then
// each parent path, so a package inside a module installs from its module.
func resolveGoModule(ctx context.Context, target string) (module, version, repoURL string, err error) {
	parts := strings.Split(target, "/")
	for i := len(parts); i >= 2; i-- {
		candidate := strings.Join(parts[:i], "/")
		mod, err := goModuleLatest(ctx, candidate)
		if err == nil {
			return candidate, mod.Version, mod.RepoURL, nil
		}
	}
	return "", "", "", fmt.Errorf("no Go module at %s", target)
}

// searchGitHubRepos asks GitHub for Go repositories matching query, most
// starred first.
func searchGitHubRepos(ctx context.Context, query string, n int) ([]githubRepository, error) {
	return searchGitHubReposLang(ctx, query, "go", n)
}

func searchGitHubReposLang(ctx context.Context, query, language string, n int) ([]githubRepository, error) {
	q := url.QueryEscape(query + " language:" + language)
	var raw json.RawMessage
	path := "search/repositories?q=" + q + "&sort=stars&order=desc&per_page=" + strconv.Itoa(n)
	if err := githubGet(ctx, path, &raw); err != nil {
		return nil, githubRateHint(err)
	}
	return parseGitHubRepos(raw, n)
}

func parseGitHubRepos(data []byte, limit int) ([]githubRepository, error) {
	var out struct {
		Items []githubRepository `json:"items"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("GitHub search: %w", err)
	}
	if limit > 0 && len(out.Items) > limit {
		out.Items = out.Items[:limit]
	}
	return out.Items, nil
}

// githubRateHint names the one error people can act on.
func githubRateHint(err error) error {
	s := err.Error()
	lower := strings.ToLower(s)
	if strings.Contains(s, "403") || strings.Contains(s, "429") || strings.Contains(lower, "rate limit") {
		return fmt.Errorf("%w (GitHub rate limit; set GITHUB_TOKEN or sign in with gh)", err)
	}
	return err
}

// lookupGoModule asks the Go module proxy for a module's newest version and
// its source repository.
func lookupGoModule(ctx context.Context, module string) (goModuleInfo, error) {
	var r struct {
		Version string `json:"Version"`
		Origin  struct {
			URL string `json:"URL"`
		} `json:"Origin"`
	}
	if err := getJSON(ctx, goProxy+"/"+escapeModule(module)+"/@latest", nil, &r); err != nil {
		return goModuleInfo{}, err
	}
	if r.Version == "" {
		return goModuleInfo{}, fmt.Errorf("no version for %s", module)
	}
	return goModuleInfo{Version: r.Version, RepoURL: r.Origin.URL}, nil
}

// errRepoFileNotFound says a repository has no such file, which is not an
// error for a best-effort search.
var errRepoFileNotFound = errors.New("no such repo file")

// fetchRepoFile reads one file from a repository's default branch.
func fetchRepoFile(ctx context.Context, repo, file string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://raw.githubusercontent.com/"+repo+"/HEAD/"+file, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", khoUserAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return "", errRepoFileNotFound
	case http.StatusOK:
	default:
		return "", githubRateHint(fmt.Errorf("github raw: %s", resp.Status))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// fetchGoModFile reads a repository's module path from its root go.mod. A
// repository without one is skipped with no error.
func fetchGoModFile(ctx context.Context, repo string) (string, error) {
	data, err := fetchRepoFile(ctx, repo, "go.mod")
	if errors.Is(err, errRepoFileNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return parseGoModModule(data), nil
}

func parseGoModModule(data string) string {
	for line := range strings.Lines(data) {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 2 && f[0] == "module" {
			return strings.Trim(f[1], `"`)
		}
	}
	return ""
}

// fetchGitTreePaths lists a repository's files at its default branch.
func fetchGitTreePaths(ctx context.Context, repo string) ([]string, error) {
	var raw json.RawMessage
	if err := githubGet(ctx, "repos/"+repo+"/git/trees/HEAD?recursive=1", &raw); err != nil {
		return nil, githubRateHint(err)
	}
	return parseGitTreePaths(raw)
}

func parseGitTreePaths(data []byte) ([]string, error) {
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("GitHub tree: %w", err)
	}
	var paths []string
	for _, e := range tree.Tree {
		if e.Type == "blob" {
			paths = append(paths, e.Path)
		}
	}
	return paths, nil
}

// goMainDirs names the directories under paths that hold a main package. A
// root main.go wins; otherwise every cmd/<tool> directory holding Go files
// counts, because tools often name their main file after the tool
// (cmd/staticcheck/staticcheck.go). Root level directories need a main.go.
// Vendor, test and internal trees do not count.
func goMainDirs(paths []string) []string {
	var root bool
	var cmd, other []string
	seen := map[string]bool{}
	add := func(list *[]string, dir string) {
		if dir == "" || seen[dir] || skipGoMainDir(dir) {
			return
		}
		seen[dir] = true
		*list = append(*list, dir)
	}
	for _, p := range paths {
		if p == "main.go" {
			root = true
			continue
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		dir := path.Dir(p)
		switch {
		case strings.HasPrefix(dir, "cmd/") && strings.Count(dir, "/") == 1:
			add(&cmd, dir)
		case !strings.Contains(dir, "/") && p == dir+"/main.go":
			add(&other, dir)
		}
	}
	if root {
		return []string{"."}
	}
	slices.Sort(cmd)
	slices.Sort(other)
	var out []string
	out = append(out, cmd...)
	return append(out, other...)
}

// rankGoMainDirs puts the candidate whose name matches the query, or the
// repository, before the rest, so searching staticcheck does not lead with
// structlayout just because it sorts first.
func rankGoMainDirs(dirs []string, query, repo string) {
	q := strings.ToLower(query)
	r := strings.ToLower(path.Base(repo))
	rank := func(dir string) int {
		base := strings.ToLower(path.Base(dir))
		switch {
		case q != "" && (strings.Contains(base, q) || strings.Contains(q, base)):
			return 0
		case r != "" && (strings.Contains(base, r) || strings.Contains(r, base)):
			return 1
		case strings.HasPrefix(dir, "cmd/"):
			return 2
		}
		return 3
	}
	slices.SortStableFunc(dirs, func(a, b string) int { return rank(a) - rank(b) })
}

func skipGoMainDir(dir string) bool {
	for _, part := range strings.Split(dir, "/") {
		switch part {
		case "vendor", "testdata", "internal", "examples", "example", "tests", "test", "fixtures":
			return true
		}
		if strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
			return true
		}
	}
	return false
}

// goRepoPackages turns one repository into the packages it can install. A
// repository with no go.mod, no main package, or no proxy version is skipped.
func goRepoPackages(ctx context.Context, repo githubRepository, query string) ([]Package, error) {
	module, err := goModFile(ctx, repo.FullName)
	if err != nil {
		return nil, err
	}
	if module == "" {
		return nil, nil
	}
	paths, err := gitTreePaths(ctx, repo.FullName)
	if err != nil {
		return nil, err
	}
	dirs := goMainDirs(paths)
	rankGoMainDirs(dirs, query, repo.FullName)
	if len(dirs) > goSearchMains {
		dirs = dirs[:goSearchMains]
	}
	if len(dirs) == 0 {
		return nil, nil
	}
	mod, err := goModuleLatest(ctx, module)
	if err != nil {
		// Not a module the proxy serves; nothing installable here.
		return nil, nil
	}
	out := make([]Package, 0, len(dirs))
	for _, dir := range dirs {
		entry, name := module, goBinName(module)
		if dir != "." {
			entry, name = module+"/"+dir, path.Base(dir)
		}
		out = append(out, Package{
			Source: "go", Name: name, Latest: mod.Version, Desc: repo.Description,
			Homepage: repo.HTMLURL, Repo: repo.FullName, Origin: module, Entry: entry,
		})
	}
	return out, nil
}
