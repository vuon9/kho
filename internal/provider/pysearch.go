package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// Python has no search API, so a keyword search goes through GitHub the way Go
// does: find Python repositories, read the project name from pyproject.toml or
// the setup files, then keep the ones PyPI publishes. It is best effort.
const (
	pySearchRepos   = 8
	pySearchWorkers = 4
)

// pythonFound is one repository that maps to a PyPI project.
type pythonFound struct {
	project pypiProject
	repo    githubRepository
	name    string
}

// The reads a Python keyword search makes, so tests can feed captured answers.
var (
	gitHubPyRepos  = searchPythonRepos
	pyRepoFile     = fetchRepoFile
	pyPIProjectDoc = fetchPyPIProjectDoc
	setupPyNameRE  = regexp.MustCompile(`(?m)\bname\s*=\s*["']([^"']+)["']`)
)

// pipx and uv read the same index, so one search answers both. The cache is in
// memory for this session only, and errors are not kept.
var pythonSearches = struct {
	sync.Mutex
	byQuery map[string][]pythonFound
	group   singleflight.Group
}{byQuery: map[string][]pythonFound{}}

// Search finds Python tools by keyword through GitHub and PyPI.
func (Pipx) Search(ctx context.Context, query string, limit int) ([]Package, error) {
	return searchPython(ctx, "pipx", query, limit)
}

func (Uv) Search(ctx context.Context, query string, limit int) ([]Package, error) {
	return searchPython(ctx, "uv", query, limit)
}

func searchPython(ctx context.Context, source, query string, limit int) ([]Package, error) {
	if name, ok := pyPIProjectPath(query); ok {
		p, err := pypiFind(ctx, source, name)
		if err != nil {
			return nil, nil
		}
		return []Package{p}, nil
	}
	query = strings.TrimSpace(query)
	if len([]rune(query)) < 2 {
		return nil, fmt.Errorf("a Python search needs two characters")
	}
	limit = searchLimit(limit)
	found, err := findPythonProjects(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(found))
	for _, f := range found {
		p := pypiCandidate(f.project, source, f.name)
		p.Repo = f.repo.FullName
		out = append(out, p)
	}
	return out, nil
}

// findPythonProjects turns a query into PyPI projects, once per query even when
// pipx and uv ask together.
func findPythonProjects(ctx context.Context, query string, limit int) ([]pythonFound, error) {
	key := fmt.Sprintf("%s\x00%d", query, limit)
	pythonSearches.Lock()
	if hits, ok := pythonSearches.byQuery[key]; ok {
		pythonSearches.Unlock()
		return hits, nil
	}
	pythonSearches.Unlock()
	v, err, _ := pythonSearches.group.Do(key, func() (any, error) {
		hits, err := searchPythonProjects(ctx, query, limit)
		if err != nil {
			return nil, err
		}
		pythonSearches.Lock()
		pythonSearches.byQuery[key] = hits
		pythonSearches.Unlock()
		return hits, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]pythonFound), nil
}

// searchPythonProjects does the GitHub and PyPI reads behind findPythonProjects.
func searchPythonProjects(ctx context.Context, query string, limit int) ([]pythonFound, error) {
	n := min(max(limit, 1), pySearchRepos)
	repos, err := gitHubPyRepos(ctx, query, n)
	if err != nil {
		return nil, err
	}
	results := make([][]pythonFound, len(repos))
	var errs []error
	var mu sync.Mutex
	var g errgroup.Group
	g.SetLimit(pySearchWorkers)
	for i, repo := range repos {
		i, repo := i, repo
		if repo.Fork || repo.Archived {
			continue
		}
		g.Go(func() error {
			name, err := repoPyPIName(ctx, repo.FullName)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return nil
			}
			if name == "" {
				return nil
			}
			project, err := pyPIProjectDoc(ctx, name)
			if err != nil || project.Info.Version == "" {
				// Not on PyPI, or no release: skip it.
				return nil
			}
			results[i] = []pythonFound{{project: project, repo: repo, name: name}}
			return nil
		})
	}
	g.Wait()
	var out []pythonFound
	for _, found := range results {
		for _, f := range found {
			if len(out) >= limit {
				break
			}
			out = append(out, f)
		}
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errs[0]
	}
	return out, nil
}

// pyPIProjectPath reads https://pypi.org/project/<name>/[<version>/] and
// returns the project name.
func pyPIProjectPath(q string) (string, bool) {
	q = strings.TrimSpace(q)
	for _, prefix := range []string{"https://pypi.org/project/", "http://pypi.org/project/", "pypi.org/project/"} {
		if !strings.HasPrefix(q, prefix) {
			continue
		}
		rest := strings.TrimPrefix(q, prefix)
		if i := strings.IndexAny(rest, "?#"); i >= 0 {
			rest = rest[:i]
		}
		rest = strings.Trim(rest, "/")
		name, _, _ := strings.Cut(rest, "/")
		if name == "" {
			return "", false
		}
		return name, true
	}
	return "", false
}

// searchPythonRepos asks GitHub for Python repositories matching query.
func searchPythonRepos(ctx context.Context, query string, n int) ([]githubRepository, error) {
	return searchGitHubReposLang(ctx, query, "python", n)
}

// repoPyPIName reads the project name a repository publishes under. A repo
// without a name in its packaging files falls back to its own name.
func repoPyPIName(ctx context.Context, repo string) (string, error) {
	files := []struct {
		name  string
		parse func(string) string
	}{
		{"pyproject.toml", parsePyProjectName},
		{"setup.cfg", parseSetupCfgName},
		{"setup.py", parseSetupPyName},
	}
	for _, f := range files {
		data, err := pyRepoFile(ctx, repo, f.name)
		if err == nil {
			if name := f.parse(data); name != "" {
				return NormalizePyPI(name), nil
			}
			continue
		}
		if !errors.Is(err, errRepoFileNotFound) {
			return "", err
		}
	}
	name := path.Base(repo)
	if name == "" || name == "." || name == "/" {
		return "", nil
	}
	return NormalizePyPI(name), nil
}

func parsePyProjectName(data string) string {
	section := ""
	for line := range strings.Lines(data) {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			continue
		}
		if section != "project" && section != "tool.poetry" {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || strings.TrimSpace(k) != "name" {
			continue
		}
		if name := tomlString(strings.TrimSpace(v)); name != "" {
			return name
		}
	}
	return ""
}

// tomlString reads a quoted or bare TOML value, ignoring a trailing comment.
func tomlString(v string) string {
	if v == "" {
		return ""
	}
	if q := v[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if i := strings.IndexAny(v, " \t#"); i >= 0 {
		v = v[:i]
	}
	return strings.Trim(v, `"'`)
}

func parseSetupCfgName(data string) string {
	section := ""
	for line := range strings.Lines(data) {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			continue
		}
		if section != "metadata" {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if ok && strings.TrimSpace(k) == "name" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseSetupPyName(data string) string {
	if m := setupPyNameRE.FindStringSubmatch(data); m != nil {
		return m[1]
	}
	return ""
}

func fetchPyPIProjectDoc(ctx context.Context, name string) (pypiProject, error) {
	var r pypiProject
	u := pypiSite + "/pypi/" + url.PathEscape(NormalizePyPI(name)) + "/json"
	if err := getJSON(ctx, u, nil, &r); err != nil {
		return r, err
	}
	return r, nil
}
