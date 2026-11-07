// Package registry asks a container registry what a tag resolves to and what
// an image says about itself. It reads manifests and config blobs, never a
// layer, so it never downloads or runs an image.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vuon9/kho/internal/image"
)

// Client is an anonymous registry reader. Private images answer 401 and are
// reported as such, never guessed at.
type Client struct {
	HTTP *http.Client
	// Cache holds answers for a while, so a second run is quiet.
	Cache *Cache
	// Base turns a registry host into the URL to ask. Tests point it at a
	// local server.
	Base func(host string) string
	// LifeBase is where endoflife.date lives, and HubBase where its web API
	// lives, for tests.
	LifeBase string
	HubBase  string
	// NoCache asks the registries again, for --refresh.
	NoCache bool
}

func (c *Client) base(host string) string {
	if c.Base != nil {
		return c.Base(host)
	}
	return "https://" + host
}

// New is a client with a timeout and a cache at path, which may be "".
func New(cachePath string) *Client {
	return &Client{
		HTTP:  &http.Client{Timeout: 15 * time.Second},
		Cache: Open(cachePath, 6*time.Hour),
	}
}

const manifestAccept = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json," +
	"application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

// Remote answers what the tag resolves to and what the image declares about
// itself. A tag the registry does not publish comes back Gone, not as an
// error, because that is a fact worth showing.
func (c *Client) Remote(ctx context.Context, r image.Ref) (image.Remote, error) {
	if r.Repo == "scratch" || r.Registry == "" || r.Repo == "" {
		return image.Remote{}, nil
	}
	key := r.Canonical()
	if c.Cache != nil && !c.NoCache {
		if remote, life, ok := c.Cache.Get(key); ok {
			_ = life
			return remote, nil
		}
	}
	remote, err := c.fetch(ctx, r)
	if err != nil {
		return image.Remote{}, err
	}
	if c.Cache != nil {
		c.Cache.PutRemote(key, remote)
	}
	return remote, nil
}

func (c *Client) fetch(ctx context.Context, r image.Ref) (image.Remote, error) {
	ref := r.Tag
	if ref == "" {
		ref = r.Digest
	}
	host := r.Registry
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", c.base(host), r.RemoteRepo(), ref)
	body, media, status, err := c.get(ctx, manifestURL, host, r.RemoteRepo())
	if err != nil {
		return image.Remote{}, err
	}
	if status == http.StatusNotFound {
		return image.Remote{Gone: true}, nil
	}
	if status != http.StatusOK {
		return image.Remote{}, fmt.Errorf("%s answered %d", r.Registry, status)
	}
	remote := image.Remote{Digest: "sha256:" + hex.EncodeToString(sum(body))}
	var doc struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return image.Remote{}, err
	}
	if len(doc.Manifests) > 0 {
		child := pickPlatform(doc.Manifests)
		childBody, _, status, err := c.get(ctx, fmt.Sprintf("%s/v2/%s/manifests/%s", c.base(host), r.RemoteRepo(), child), host, r.RemoteRepo())
		if err != nil || status != http.StatusOK {
			// The index answered, so the tag exists: report the digest and
			// leave the rest to the next run.
			return remote, nil
		}
		if err := json.Unmarshal(childBody, &doc); err != nil {
			return remote, nil
		}
	}
	if doc.Config.Digest == "" {
		return remote, nil
	}
	configBody, _, status, err := c.get(ctx, fmt.Sprintf("%s/v2/%s/blobs/%s", c.base(host), r.RemoteRepo(), doc.Config.Digest), host, r.RemoteRepo())
	if err != nil || status != http.StatusOK {
		return remote, nil
	}
	remote.Pushed, remote.Upstream, remote.Base = readConfig(configBody, r)
	_ = media
	return remote, nil
}

func pickPlatform(manifests []struct {
	Digest   string `json:"digest"`
	Platform struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}) string {
	for _, want := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}} {
		for _, m := range manifests {
			if m.Platform.OS == want[0] && m.Platform.Architecture == want[1] {
				return m.Digest
			}
		}
	}
	return manifests[0].Digest
}

// readConfig pulls the facts an image declares: when it was built, which
// upstream version it carries, and which distribution it sits on.
func readConfig(body []byte, r image.Ref) (pushed time.Time, upstream, base string) {
	var doc struct {
		Created time.Time `json:"created"`
		Config  struct {
			Env    []string          `json:"Env"`
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return time.Time{}, "", ""
	}
	pushed = doc.Created
	versions := map[string]string{}
	for _, e := range doc.Config.Env {
		name, value, ok := strings.Cut(e, "=")
		if ok {
			versions[name] = value
		}
	}
	for _, name := range []string{"NODE_VERSION", "PYTHON_VERSION", "RUBY_VERSION", "GO_VERSION", "PHP_VERSION",
		"JAVA_VERSION", "NGINX_VERSION", "REDIS_VERSION", "PG_VERSION", "MARIADB_VERSION", "MYSQL_VERSION"} {
		if v := versions[name]; v != "" {
			upstream = v
			break
		}
	}
	if upstream == "" {
		upstream = doc.Config.Labels["org.opencontainers.image.version"]
	}
	base = doc.Config.Labels["org.opencontainers.image.base.name"]
	if base == "" {
		base = baseFromTag(r.Tag)
	}
	return pushed, upstream, base
}

// baseFromTag names the distribution an official image sits on, which its
// tag says and its config does not.
func baseFromTag(tag string) string {
	switch {
	case strings.Contains(tag, "alpine"):
		return "alpine"
	case strings.Contains(tag, "distroless"):
		return "distroless"
	case strings.Contains(tag, "slim"), strings.Contains(tag, "bookworm"),
		strings.Contains(tag, "bullseye"), strings.Contains(tag, "trixie"), strings.Contains(tag, "buster"):
		return "debian"
	case strings.Contains(tag, "noble"), strings.Contains(tag, "jammy"), strings.Contains(tag, "focal"):
		return "ubuntu"
	}
	return ""
}

// get asks for a URL, taking a bearer token when the registry asks for one.
func (c *Client) get(ctx context.Context, raw, host, repo string) (body []byte, media string, status int, err error) {
	body, media, status, challenge, err := c.do(ctx, raw, "")
	if status != http.StatusUnauthorized || challenge == "" {
		return body, media, status, err
	}
	token, err := c.token(ctx, challenge, repo)
	if err != nil {
		return nil, "", status, err
	}
	body, media, status, _, err = c.do(ctx, raw, token)
	return body, media, status, err
}

func (c *Client) do(ctx context.Context, raw, token string) (body []byte, media string, status int, challenge string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, "", 0, "", err
	}
	req.Header.Set("Accept", manifestAccept)
	req.Header.Set("User-Agent", "kho")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, "", resp.StatusCode, "", err
	}
	return data, resp.Header.Get("Content-Type"), resp.StatusCode, resp.Header.Get("Www-Authenticate"), nil
}

// token follows a registry's bearer challenge, which is how public images on
// Docker Hub and ghcr are read without an account.
func (c *Client) token(ctx context.Context, challenge, repo string) (string, error) {
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			params[key] = strings.Trim(value, `"`)
		}
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("registry wants credentials")
	}
	q := url.Values{}
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + repo + ":pull"
	}
	q.Set("scope", scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint answered %d", resp.StatusCode)
	}
	var doc struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}
	if doc.Token != "" {
		return doc.Token, nil
	}
	if doc.AccessToken != "" {
		return doc.AccessToken, nil
	}
	return "", fmt.Errorf("token endpoint returned no token")
}

func sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
