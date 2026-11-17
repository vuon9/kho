package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vuon9/kho/internal/image"
)

// Search results are read from the internet, so the caller strips terminal
// escapes before it shows Name or Description.
type HubRepo struct {
	// As Docker Hub names it: an official image has no namespace, as in redis.
	Name        string    `json:"repository"`
	Description string    `json:"desc,omitempty"`
	Stars       int       `json:"stars"`
	Pulls       int64     `json:"pulls"`
	Official    bool      `json:"official,omitempty"`
	Updated     time.Time `json:"updated,omitzero"`
}

func (h HubRepo) Ref(tag string) image.Ref {
	return image.Parse(h.Name + ":" + tag)
}

func (h HubRepo) URL() string {
	r := h.Ref("latest")
	if !strings.Contains(r.Repo, "/") {
		return HubURL + "/_/" + r.Repo
	}
	return HubURL + "/r/" + r.Repo
}

var ErrHubRateLimited = errors.New("docker hub is rate limiting searches, try again in a minute")

// Docker Hub's search sorts by relevance and takes the words as they are. A
// pasted repository page resolves to that one repository instead.
func (c *Client) SearchHub(ctx context.Context, query string, limit int) ([]HubRepo, error) {
	if name, ok := HubRepoPath(query); ok {
		repo, err := c.hubRepo(ctx, name)
		if err != nil {
			return nil, err
		}
		return []HubRepo{repo}, nil
	}
	query = strings.TrimSpace(query)
	key := fmt.Sprintf("%s\x00%d", query, limit)
	c.mu.Lock()
	cached, ok := c.searches[key]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}
	raw := fmt.Sprintf("%s/v2/search/repositories/?query=%s&page_size=%d", c.hubBase(), url.QueryEscape(query), limit)
	body, err := c.hubGet(ctx, raw)
	if err != nil {
		return nil, err
	}
	repos, err := parseHubSearch(body)
	if err != nil {
		return nil, err
	}
	if len(repos) > limit {
		repos = repos[:limit]
	}
	c.mu.Lock()
	if c.searches == nil {
		c.searches = map[string][]HubRepo{}
	}
	c.searches[key] = repos
	c.mu.Unlock()
	return repos, nil
}

func (c *Client) hubRepo(ctx context.Context, name string) (HubRepo, error) {
	r := image.Parse(name)
	body, err := c.hubGet(ctx, fmt.Sprintf("%s/v2/repositories/%s/", c.hubBase(), r.RemoteRepo()))
	if err != nil {
		return HubRepo{}, err
	}
	repo, err := parseHubRepo(body)
	if err != nil {
		return HubRepo{}, err
	}
	return repo, nil
}

func (c *Client) hubGet(ctx context.Context, raw string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return nil, ErrHubRateLimited
	case http.StatusNotFound:
		return nil, fmt.Errorf("docker hub has no such repository")
	default:
		return nil, fmt.Errorf("docker hub answered %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func parseHubSearch(body []byte) ([]HubRepo, error) {
	var doc struct {
		Results *[]struct {
			Name        string `json:"repo_name"`
			Description string `json:"short_description"`
			Stars       int    `json:"star_count"`
			Pulls       int64  `json:"pull_count"`
			Official    bool   `json:"is_official"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("docker hub sent a search answer kho can't read: %w", err)
	}
	if doc.Results == nil {
		return nil, fmt.Errorf("docker hub sent a search answer with no results list")
	}
	out := []HubRepo{}
	for _, r := range *doc.Results {
		if r.Name == "" {
			continue
		}
		out = append(out, HubRepo{Name: r.Name, Description: r.Description, Stars: r.Stars, Pulls: r.Pulls, Official: r.Official})
	}
	return out, nil
}

func parseHubRepo(body []byte) (HubRepo, error) {
	var doc struct {
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Stars       int    `json:"star_count"`
		Pulls       int64  `json:"pull_count"`
		Updated     string `json:"last_updated"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return HubRepo{}, fmt.Errorf("docker hub sent a repository kho can't read: %w", err)
	}
	if doc.Name == "" {
		return HubRepo{}, fmt.Errorf("docker hub sent a repository with no name")
	}
	name := doc.Namespace + "/" + doc.Name
	if doc.Namespace == "library" || doc.Namespace == "" {
		name = doc.Name
	}
	repo := HubRepo{Name: name, Description: doc.Description, Stars: doc.Stars,
		Pulls: doc.Pulls, Official: doc.Namespace == "library", Updated: parseStamp(doc.Updated)}
	return repo, nil
}

// Takes hub.docker.com/r/<namespace>/<repo> and hub.docker.com/_/<repo>, with
// or without the scheme, and anything after the repository, such as /tags.
func HubRepoPath(q string) (string, bool) {
	q = strings.TrimSpace(q)
	for _, prefix := range []string{"https://", "http://"} {
		q = strings.TrimPrefix(q, prefix)
	}
	rest, ok := strings.CutPrefix(q, "hub.docker.com/")
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case len(parts) >= 2 && parts[0] == "_" && validRepoPart(parts[1]):
		return parts[1], true
	case len(parts) >= 3 && parts[0] == "r" && validRepoPart(parts[1]) && validRepoPart(parts[2]):
		return parts[1] + "/" + parts[2], true
	}
	return "", false
}

func validRepoPart(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}

// tagName is the shape docker accepts for a tag, which never starts with a dash.
var tagName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// The name and tag come from Docker Hub, so both are checked before they reach
// docker's arguments, where a leading dash would read as a flag.
func (h HubRepo) PullRef(tag string) (string, bool) {
	parts := strings.Split(h.Name, "/")
	if len(parts) > 2 || !tagName.MatchString(tag) {
		return "", false
	}
	for _, p := range parts {
		if !validRepoPart(p) || strings.HasPrefix(p, "-") {
			return "", false
		}
	}
	return h.Name + ":" + tag, true
}

// latest when the repository has it, as docker pull would pick, and else the
// most recently pushed tag.
func SuggestTag(tags []image.Tag) string {
	newest := ""
	var at time.Time
	for _, t := range tags {
		if t.Name == "latest" {
			return t.Name
		}
		if newest == "" || t.Pushed.After(at) {
			newest, at = t.Name, t.Pushed
		}
	}
	return newest
}

// 51200000 reads 51.2M, as Docker Hub shows a pull count.
func Count(n int64) string {
	trim := func(s string) string { return strings.TrimSuffix(s, ".0") }
	switch {
	case n >= 1_000_000_000:
		return trim(fmt.Sprintf("%.1f", float64(n)/1e9)) + "B"
	case n >= 1_000_000:
		return trim(fmt.Sprintf("%.1f", float64(n)/1e6)) + "M"
	case n >= 1_000:
		return trim(fmt.Sprintf("%.1f", float64(n)/1e3)) + "k"
	}
	return fmt.Sprint(n)
}
