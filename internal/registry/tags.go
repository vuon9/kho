package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/vuln"
)

// Tags lists what a repository publishes, newest first. Docker Hub answers
// with dates and digests; every other registry answers with names, which are
// ordered by version so the newest line comes first.
func (c *Client) Tags(ctx context.Context, r image.Ref) ([]image.Tag, error) {
	if r.Registry == "" || r.Repo == "" || r.Repo == "scratch" {
		return nil, nil
	}
	if r.Registry == "docker.io" {
		return c.hubTags(ctx, r)
	}
	return c.registryTags(ctx, r)
}

func (c *Client) hubTags(ctx context.Context, r image.Ref) ([]image.Tag, error) {
	raw := fmt.Sprintf("%s/v2/repositories/%s/tags?page_size=40&ordering=last_updated", c.hubBase(), r.RemoteRepo())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kho")
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

// registryTags asks the OCI distribution API, which returns names only.
func (c *Client) registryTags(ctx context.Context, r image.Ref) ([]image.Tag, error) {
	host := r.Registry
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	raw := fmt.Sprintf("%s/v2/%s/tags/list?n=60", c.base(host), r.RemoteRepo())
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
	sort.SliceStable(doc.Tags, func(i, j int) bool { return vuln.Compare(doc.Tags[i], doc.Tags[j]) > 0 })
	if len(doc.Tags) > 40 {
		doc.Tags = doc.Tags[:40]
	}
	tags := make([]image.Tag, 0, len(doc.Tags))
	for _, t := range doc.Tags {
		tags = append(tags, image.Tag{Name: t})
	}
	return tags, nil
}

// hubBase is where the Docker Hub web API lives, for tests.
func (c *Client) hubBase() string {
	if c.HubBase != "" {
		return c.HubBase
	}
	return "https://hub.docker.com"
}

// parseStamp reads the timestamps the Docker Hub API writes.
func parseStamp(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
