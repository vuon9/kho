// Package registry reads manifests and config blobs, never a layer, so it never
// downloads or runs an image.
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
	"sync"
	"time"

	"github.com/vuon9/kho/internal/image"
)

const (
	// Docker Hub's web API lists tags with their digests and push dates, which the
	// distribution API leaves out.
	HubURL  = "https://hub.docker.com"
	LifeURL = "https://endoflife.date"
	// dockerHubAPI is the host that serves Docker Hub's distribution API.
	dockerHubAPI = "registry-1.docker.io"
	userAgent    = "kho"
	cacheFor     = 6 * time.Hour
)

// Anonymous: private images answer 401 and are reported as such, never guessed at.
type Client struct {
	HTTP     *http.Client
	Cache    *Cache
	Base     func(host string) string
	LifeBase string
	HubBase  string
	NoCache  bool

	mu      sync.Mutex
	tokens  map[string]string
	demands map[string]string
}

func (c *Client) base(host string) string {
	if c.Base != nil {
		return c.Base(host)
	}
	return "https://" + host
}

func New(cachePath string) *Client {
	// Images are asked about in parallel, so the pool has to be wider than the
	// two connections net/http keeps per host by default, or every lookup pays
	// for a new handshake.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 32
	transport.MaxIdleConnsPerHost = 16
	return &Client{
		HTTP:    &http.Client{Timeout: 15 * time.Second, Transport: transport},
		Cache:   Open(cachePath, cacheFor),
		tokens:  map[string]string{},
		demands: map[string]string{},
	}
}

const manifestAccept = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json," +
	"application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

// A tag the registry does not publish comes back Gone, not as an error, because that
// is a fact worth showing.
func (c *Client) Remote(ctx context.Context, r image.Ref) (image.Remote, error) {
	if r.Repo == image.Scratch || r.Registry == "" || r.Repo == "" {
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

type source struct {
	host   string
	prefix string
}

// Docker Hub rate limits anonymous pulls hard enough to fail a whole project, so a
// docker.io reference tries a pull-through mirror first. Mirrors only carry Hub images.
func sources(r image.Ref) []source {
	if r.Registry != image.DockerHub {
		return []source{{host: r.Registry}}
	}
	return []source{
		{host: "mirror.gcr.io"},
		{host: "public.ecr.aws", prefix: "docker/"},
		{host: dockerHubAPI},
	}
}

func (c *Client) fetch(ctx context.Context, r image.Ref) (image.Remote, error) {
	ref := r.Tag
	if ref == "" {
		ref = r.Digest
	}
	all := sources(r)
	var missing, errored int
	var lastErr error
	for _, s := range all {
		remote, found, err := c.fetchFrom(ctx, r, s, ref)
		switch {
		case err != nil:
			errored++
			lastErr = err
		case !found:
			missing++
		default:
			return remote, nil
		}
	}
	// A tag is only gone when every source says so: a mirror that has not
	// cached it yet says the same thing as one that never will.
	if missing == len(all) {
		return image.Remote{Gone: true}, nil
	}
	return image.Remote{}, lastErr
}

// A missing tag is found=false, not an error: the next source may have it.
func (c *Client) fetchFrom(ctx context.Context, r image.Ref, s source, ref string) (image.Remote, bool, error) {
	repo, base := s.prefix+r.RemoteRepo(), c.base(s.host)
	body, media, status, err := c.get(ctx, fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, ref), s.host, repo)
	if err != nil {
		return image.Remote{}, false, err
	}
	switch status {
	case http.StatusNotFound:
		return image.Remote{}, false, nil
	case http.StatusOK:
	default:
		return image.Remote{}, false, fmt.Errorf("%s answered %d", s.host, status)
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
		return image.Remote{}, false, err
	}
	if len(doc.Manifests) > 0 {
		child := pickPlatform(doc.Manifests)
		childBody, _, status, err := c.get(ctx, fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, child), s.host, repo)
		if err != nil || status != http.StatusOK {
			// The index answered, so the tag exists: report the digest and
			// leave the rest to the next run.
			return remote, true, nil
		}
		if err := json.Unmarshal(childBody, &doc); err != nil {
			return remote, true, nil
		}
	}
	if doc.Config.Digest == "" {
		return remote, true, nil
	}
	configBody, _, status, err := c.get(ctx, fmt.Sprintf("%s/v2/%s/blobs/%s", base, repo, doc.Config.Digest), s.host, repo)
	if err != nil || status != http.StatusOK {
		return remote, true, nil
	}
	remote.Pushed, remote.Upstream, remote.Base, remote.BaseVersion = readConfig(configBody, r)
	_ = media
	return remote, true, nil
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

func readConfig(body []byte, r image.Ref) (pushed time.Time, upstream, base, baseVersion string) {
	var doc struct {
		Created time.Time `json:"created"`
		Config  struct {
			Env    []string          `json:"Env"`
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return time.Time{}, "", "", ""
	}
	pushed = doc.Created
	versions := map[string]string{}
	for _, e := range doc.Config.Env {
		name, value, ok := strings.Cut(e, "=")
		if ok {
			versions[name] = value
		}
	}
	base = shortBase(doc.Config.Labels["org.opencontainers.image.base.name"])
	if base == "" {
		base = baseFromTag(r.Tag)
	}
	upstream, baseVersion, runtime := imageVersion(versions, r, base)
	if upstream == "" {
		upstream = doc.Config.Labels["org.opencontainers.image.version"]
	}
	if base == "" {
		base = runtime
	}
	if baseVersion == "" && base != "" {
		baseVersion = versions[versionToken(base)+"_VERSION"]
	}
	return pushed, upstream, base, baseVersion
}

// composer:2 carries both PHP_VERSION and COMPOSER_VERSION, and only the second is Composer.
func imageVersion(versions map[string]string, r image.Ref, base string) (upstream, baseVersion, runtime string) {
	product := versionToken(r.Repo)
	if product != "" {
		for name, v := range versions {
			if v == "" || !strings.HasSuffix(name, "_VERSION") {
				continue
			}
			if name == product+"_VERSION" || strings.Contains(name, product) {
				upstream = v
				break
			}
		}
	}
	baseToken := versionToken(base)
	for _, name := range []string{"NODE_VERSION", "PYTHON_VERSION", "RUBY_VERSION", "GO_VERSION", "PHP_VERSION",
		"JAVA_VERSION", "NGINX_VERSION", "REDIS_VERSION", "PG_VERSION", "MARIADB_VERSION", "MYSQL_VERSION"} {
		v := versions[name]
		if v == "" {
			continue
		}
		if product != "" && strings.Contains(name, product) {
			continue
		}
		if baseToken != "" && strings.Contains(name, baseToken) {
			// The base is known by name, so this version is the base's, never the product's.
			baseVersion = v
			break
		}
		if upstream == "" {
			// Nothing names the product, so the runtime is the best answer there is.
			upstream = v
			continue
		}
		baseVersion = v
		if base == "" {
			runtime = strings.ToLower(strings.TrimSuffix(name, "_VERSION"))
		}
		break
	}
	return upstream, baseVersion, runtime
}

func shortBase(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.IndexAny(name, ":@"); i >= 0 {
		name = name[:i]
	}
	return name
}

func versionToken(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.IndexAny(name, ":@"); i >= 0 {
		name = name[:i]
	}
	var b strings.Builder
	for _, c := range strings.ToUpper(name) {
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// An official image's tag names its distribution; its config does not.
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

func (c *Client) get(ctx context.Context, raw, host, repo string) (body []byte, media string, status int, err error) {
	// A registry that asked for a token once will ask again, and every probe
	// costs a round trip: remember the challenge and skip it.
	if challenge := c.remembered(host); challenge != "" {
		if token, terr := c.token(ctx, challenge, repo); terr == nil {
			body, media, status, _, err = c.do(ctx, raw, token)
			return body, media, status, err
		}
	}
	body, media, status, challenge, err := c.do(ctx, raw, "")
	if status != http.StatusUnauthorized || challenge == "" {
		return body, media, status, err
	}
	c.remember(host, challenge)
	token, err := c.token(ctx, challenge, repo)
	if err != nil {
		return nil, "", status, err
	}
	body, media, status, _, err = c.do(ctx, raw, token)
	return body, media, status, err
}

func (c *Client) remembered(host string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.demands[host]
}

func (c *Client) remember(host, challenge string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A Client built as a literal, which tests do, has no maps yet.
	if c.demands == nil {
		c.demands = map[string]string{}
	}
	c.demands[host] = challenge
}

func (c *Client) do(ctx context.Context, raw, token string) (body []byte, media string, status int, challenge string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, "", 0, "", err
	}
	req.Header.Set("Accept", manifestAccept)
	req.Header.Set("User-Agent", userAgent)
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

// The bearer challenge is how public images on Docker Hub and ghcr are read without an account.
func (c *Client) token(ctx context.Context, challenge, repo string) (string, error) {
	realm, service, scope := challengeScope(challenge, repo)
	if realm == "" {
		return "", fmt.Errorf("registry wants credentials")
	}
	key := realm + "|" + service + "|" + scope
	c.mu.Lock()
	cached := c.tokens[key]
	c.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	tok, err := c.askToken(ctx, realm, service, scope)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if c.tokens == nil {
		c.tokens = map[string]string{}
	}
	c.tokens[key] = tok
	c.mu.Unlock()
	return tok, nil
}

func challengeScope(challenge, repo string) (realm, service, scope string) {
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			params[key] = strings.Trim(value, `"`)
		}
	}
	scope = params["scope"]
	if scope == "" {
		scope = "repository:" + repo + ":pull"
	}
	return params["realm"], params["service"], scope
}

func (c *Client) askToken(ctx context.Context, realm, service, scope string) (string, error) {
	q := url.Values{}
	if service != "" {
		q.Set("service", service)
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
