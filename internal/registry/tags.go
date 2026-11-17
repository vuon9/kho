package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/vuln"
)

// Docker Hub answers with dates and digests; every other registry answers with names only.
func (c *Client) Tags(ctx context.Context, r image.Ref) ([]image.Tag, error) {
	if r.Registry == "" || r.Repo == "" || r.Repo == image.Scratch {
		return nil, nil
	}
	if r.Registry == image.DockerHub {
		tags, err := c.hubTags(ctx, r)
		if err == nil && len(tags) > 0 {
			return tags, nil
		}
		// The hub's web API is rate limited on its own, and a registry lists the same tags
		// without dates. A list of names beats an empty tab.
		if alt, altErr := c.registryTags(ctx, r); altErr == nil && len(alt) > 0 {
			return alt, nil
		}
		return tags, err
	}
	return c.registryTags(ctx, r)
}

func (c *Client) hubTags(ctx context.Context, r image.Ref) ([]image.Tag, error) {
	// A busy repository's newest tags are all newer lines, so ask the Hub for the line's
	// own tags, and for a full version (3.19.9) ask about its line, or the list is one row.
	var tags []image.Tag
	if line := releaseLine(r.Tag); line != "" {
		if got, err := c.hubTagPage(ctx, r, "&page_size=100&name="+url.QueryEscape(line)); err == nil {
			// The hub matches the line anywhere in a tag, so 13 also finds
			// 16.13: keep only the tags that belong to this line.
			for _, t := range got {
				if onLine(t.Name, line) {
					tags = append(tags, t)
				}
			}
		}
	}
	// Some lines are named thinly (debian's 13.4 is two tags), and a version
	// tab holding two rows says less than the repository's recent tags do.
	if len(tags) < 8 {
		if newest, err := c.hubTagPage(ctx, r, "&page_size=40"); err == nil {
			tags = mergeTags(tags, newest)
		}
	}
	if len(tags) == 0 {
		return c.hubTagPage(ctx, r, "&page_size=40")
	}
	return tags, nil
}

// A registry sorts lexically, where trixie outranks 0.11.6.
func orderTags(names []string) []string {
	version := func(name string) string {
		base, _, _ := strings.Cut(name, "-")
		if m := tagVersion.FindStringSubmatch(base); m != nil {
			return m[1]
		}
		return ""
	}
	out := append([]string(nil), names...)
	sort.SliceStable(out, func(i, j int) bool {
		vi, vj := version(out[i]), version(out[j])
		if (vi == "") != (vj == "") {
			return vi != ""
		}
		if vi != "" {
			if c := vuln.Compare(vi, vj); c != 0 {
				return c > 0
			}
		}
		return out[i] < out[j]
	})
	return out
}

func onLine(name, line string) bool {
	if name == line {
		return true
	}
	if !strings.HasPrefix(name, line) {
		return false
	}
	return strings.ContainsRune(".-_+", rune(name[len(line)]))
}

func mergeTags(pages ...[]image.Tag) []image.Tag {
	seen := map[string]bool{}
	var out []image.Tag
	for _, page := range pages {
		for _, t := range page {
			if seen[t.Name] {
				continue
			}
			seen[t.Name] = true
			out = append(out, t)
		}
	}
	return out
}

// The same shape the image package reads for a lifecycle line.
var tagVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

func releaseLine(tag string) string {
	base, _, _ := strings.Cut(tag, "-")
	m := tagVersion.FindStringSubmatch(base)
	if m == nil {
		return ""
	}
	parts := strings.Split(m[1], ".")
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, ".")
}

func (c *Client) hubTagPage(ctx context.Context, r image.Ref, query string) ([]image.Tag, error) {
	raw := fmt.Sprintf("%s/v2/repositories/%s/tags?ordering=last_updated%s", c.hubBase(), r.RemoteRepo(), query)
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker hub answered %d for %s", resp.StatusCode, r.RemoteRepo())
	}
	var doc struct {
		Results []struct {
			Name        string `json:"name"`
			LastUpdated string `json:"last_updated"`
			Digest      string `json:"digest"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	tags := make([]image.Tag, 0, len(doc.Results))
	for _, t := range doc.Results {
		tags = append(tags, image.Tag{Name: t.Name, Pushed: parseStamp(t.LastUpdated), Digest: t.Digest})
	}
	return tags, nil
}

func (c *Client) registryTags(ctx context.Context, r image.Ref) ([]image.Tag, error) {
	host := r.Registry
	if host == image.DockerHub {
		host = dockerHubAPI
	}
	// The distribution API lists tags lexically, so a plain page holds the alphabetically
	// first tags (0.11.6 sits past five pages of 0.1.x). A line is contiguous in that order,
	// so ask for what follows the line and keep the line's own tags.
	if line := releaseLine(r.Tag); line != "" {
		names, err := c.tagPage(ctx, r, host, "&last="+url.QueryEscape(line))
		if err != nil {
			return nil, err
		}
		var own []string
		for _, name := range names {
			if strings.HasPrefix(name, line) && (len(name) == len(line) || strings.ContainsRune(".-_+", rune(name[len(line)]))) {
				own = append(own, name)
			}
		}
		if len(own) > 0 {
			return tagList(own), nil
		}
	}
	names, err := c.tagPage(ctx, r, host, "")
	if err != nil {
		return nil, err
	}
	return tagList(names), nil
}

func (c *Client) tagPage(ctx context.Context, r image.Ref, host, extra string) ([]string, error) {
	raw := fmt.Sprintf("%s/v2/%s/tags/list?n=1000%s", c.base(host), r.RemoteRepo(), extra)
	body, _, status, err := c.get(ctx, raw, host, r.RemoteRepo())
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", r.Registry, status)
	}
	var doc struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return doc.Tags, nil
}

func tagList(names []string) []image.Tag {
	names = orderTags(names)
	if len(names) > 40 {
		names = names[:40]
	}
	tags := make([]image.Tag, 0, len(names))
	for _, t := range names {
		tags = append(tags, image.Tag{Name: t})
	}
	return tags
}

func (c *Client) hubBase() string {
	if c.HubBase != "" {
		return c.HubBase
	}
	return HubURL
}

func parseStamp(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
