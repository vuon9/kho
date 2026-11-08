package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vuon9/kho/internal/image"
)

// registryServer is a registry that asks for a token, then serves an index, a
// platform manifest and a config blob, the way a real one does.
func registryServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	var asks int
	config := []byte(`{"created":"2026-11-05T08:09:10Z","config":{"Env":["PATH=/usr/bin","PYTHON_VERSION=3.12.16"],"Labels":{}}}`)
	configDigest := digestOf(config)
	child := []byte(fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"%s"}}`, configDigest))
	childDigest := digestOf(child)
	index := []byte(fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
		{"digest":"sha256:other","platform":{"os":"linux","architecture":"arm64"}},
		{"digest":"%s","platform":{"os":"linux","architecture":"amd64"}}]}`, childDigest))

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") != "repository:python:pull" {
			t.Errorf("token scope %q", r.URL.Query().Get("scope"))
		}
		fmt.Fprint(w, `{"token":"good"}`)
	})
	mux.HandleFunc("/v2/python/manifests/3.12-slim", func(w http.ResponseWriter, r *http.Request) {
		asks++
		if r.Header.Get("Authorization") != "Bearer good" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test",scope="repository:python:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write(index)
	})
	mux.HandleFunc("/v2/python/manifests/"+childDigest, func(w http.ResponseWriter, r *http.Request) {
		w.Write(child)
	})
	mux.HandleFunc("/v2/python/blobs/"+configDigest, func(w http.ResponseWriter, r *http.Request) {
		w.Write(config)
	})
	mux.HandleFunc("/v2/python/manifests/gone", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &asks
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func TestRemote(t *testing.T) {
	srv, asks := registryServer(t)
	c := &Client{HTTP: srv.Client(), Base: func(string) string { return srv.URL }}
	ref := image.Parse("python:3.12-slim")
	ref.Registry = "test"
	remote, err := c.Remote(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Upstream != "3.12.16" {
		t.Errorf("upstream %q, want 3.12.16", remote.Upstream)
	}
	if !remote.Pushed.Equal(time.Date(2026, 11, 5, 8, 9, 10, 0, time.UTC)) {
		t.Errorf("pushed %v", remote.Pushed)
	}
	if remote.Base != "debian" {
		t.Errorf("base %q, want debian from the tag", remote.Base)
	}
	if len(remote.Digest) != 71 || remote.Digest[:7] != "sha256:" {
		t.Errorf("digest %q", remote.Digest)
	}
	if *asks != 2 {
		t.Errorf("asked %d times, want 2: one refused, one with the token", *asks)
	}
}

func TestRemoteGone(t *testing.T) {
	srv, _ := registryServer(t)
	c := &Client{HTTP: srv.Client(), Base: func(string) string { return srv.URL }}
	ref := image.Parse("python:gone")
	ref.Registry = "test"
	remote, err := c.Remote(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if !remote.Gone {
		t.Errorf("a 404 should be Gone, got %+v", remote)
	}
}

func TestLife(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/python.json" {
			t.Errorf("path %q", r.URL.Path)
		}
		fmt.Fprint(w, `[{"cycle":"3.12","eol":"2028-10-31","latest":"3.12.16"},{"cycle":"3.9","eol":"2025-10-31","latest":"3.9.23"}]`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), LifeBase: srv.URL}
	life, err := c.Life(context.Background(), image.Parse("python:3.9-slim"))
	if err != nil {
		t.Fatal(err)
	}
	if !life.EOL.Equal(time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC)) || life.Latest != "3.9.23" {
		t.Errorf("life %+v", life)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kho", "images.json")
	c := Open(path, time.Hour)
	c.PutRemote("docker.io/library/python:3.12-slim", image.Remote{Digest: "sha256:x", Upstream: "3.12.16"})
	c.PutLife("life:python/3.12", image.Life{Cycle: "3.12", EOL: time.Date(2028, 10, 31, 0, 0, 0, 0, time.UTC)})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	again := Open(path, time.Hour)
	remote, _, ok := again.Get("docker.io/library/python:3.12-slim")
	if !ok || remote.Upstream != "3.12.16" {
		t.Fatalf("remote not cached: %+v %v", remote, ok)
	}
	if _, l, ok := again.Get("life:python/3.12"); !ok || !l.EOL.Equal(time.Date(2028, 10, 31, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("life not cached: %+v %v", l, ok)
	}
	expired := Open(path, 0)
	if _, _, ok := expired.Get("docker.io/library/python:3.12-slim"); ok {
		t.Error("a zero TTL should expire an entry")
	}
}

func TestBaseFromTag(t *testing.T) {
	tests := map[string]string{
		"22-alpine":       "alpine",
		"3.12-slim":       "debian",
		"12-bookworm":     "debian",
		"22.04-jammy":     "ubuntu",
		"nonroot":         "",
		"3.13.13":         "",
		"1.29-alpine3.21": "alpine",
	}
	for tag, want := range tests {
		if got := baseFromTag(tag); got != want {
			t.Errorf("baseFromTag(%q) = %q, want %q", tag, got, want)
		}
	}
}

func TestReadConfig(t *testing.T) {
	body := []byte(`{"created":"2026-11-05T19:50:58Z","config":{"Env":["NODE_VERSION=22.23.4","YARN_VERSION=1.22.22"],"Labels":{"org.opencontainers.image.version":"22.23.4"}}}`)
	pushed, upstream, base := readConfig(body, image.Parse("node:22-alpine"))
	if upstream != "22.23.4" || base != "alpine" || pushed.IsZero() {
		t.Errorf("readConfig = %v %q %q", pushed, upstream, base)
	}
	if json.Valid(body) == false {
		t.Error("fixture is not JSON")
	}
}

// A tag names a release line, and the repository's newest tags belong to newer
// lines, so the Hub is asked for the line's own tags.
func TestHubTagsAskForTheLine(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.RawQuery)
		if r.URL.Query().Get("name") == "3.19" {
			fmt.Fprint(w, `{"results":[{"name":"3.19.9","last_updated":"2025-01-01T00:00:00Z"},{"name":"3.19.0"}]}`)
			return
		}
		fmt.Fprint(w, `{"results":[{"name":"3.22.0"},{"name":"latest"}]}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), HubBase: srv.URL}

	tags, err := c.Tags(context.Background(), image.Ref{Registry: "docker.io", Repo: "library/alpine", Tag: "3.19"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0].Name != "3.19.9" || tags[1].Name != "3.19.0" {
		t.Errorf("tags %+v, want the 3.19 line", tags)
	}
	if len(asked) != 1 || !strings.Contains(asked[0], "name=3.19") {
		t.Errorf("asked %q, want the line first", asked)
	}

	asked = nil
	tags, err = c.Tags(context.Background(), image.Ref{Registry: "docker.io", Repo: "library/alpine", Tag: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || len(asked) != 1 || strings.Contains(asked[0], "name=") {
		t.Errorf("a tag with no line asked %q and got %+v, want the newest page", asked, tags)
	}
}

// mirrorServer answers per host, so a test can make one mirror refuse and see
// which source kho settles on.
func mirrorServer(t *testing.T, answer map[string]http.HandlerFunc) (*httptest.Server, *[]string) {
	t.Helper()
	var asked []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Host+r.URL.Path)
		for prefix, h := range answer {
			if strings.HasPrefix(r.URL.Path, prefix) {
				h(w, r)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &asked
}

// byHost routes each registry host at the same test server, keeping the host in
// the path so the handlers can tell them apart.
func byHost(srv *httptest.Server) func(string) string {
	return func(host string) string { return srv.URL + "/" + host }
}

func TestRemoteMirrorsDockerHub(t *testing.T) {
	config := []byte(`{"created":"2026-11-05T08:09:10Z","config":{"Env":["PYTHON_VERSION=3.12.16"],"Labels":{}}}`)
	child := []byte(fmt.Sprintf(`{"config":{"digest":"%s"}}`, digestOf(config)))
	served := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/manifests/3.12-slim"):
			fmt.Fprintf(w, `{"manifests":[{"digest":"%s","platform":{"os":"linux","architecture":"arm64"}}]}`, digestOf(child))
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Write(child)
		default:
			w.Write(config)
		}
	}
	srv, asked := mirrorServer(t, map[string]http.HandlerFunc{
		"/mirror.gcr.io/":        func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) },
		"/public.ecr.aws/":       served,
		"/registry-1.docker.io/": served,
	})
	c := &Client{HTTP: srv.Client(), Base: byHost(srv)}
	ref := image.Parse("python:3.12-slim")

	remote, err := c.Remote(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Upstream != "3.12.16" {
		t.Errorf("upstream %q, want the answer the mirror chain found", remote.Upstream)
	}
	joined := strings.Join(*asked, " ")
	if !strings.Contains(joined, "/public.ecr.aws/v2/docker/library/python/manifests/3.12-slim") {
		t.Errorf("asked %q, want the ecr mirror with its docker/ prefix", joined)
	}
	if strings.Contains(joined, "registry-1.docker.io") {
		t.Errorf("asked %q, want the last source left alone when the second answers", joined)
	}
}

func TestRemoteGoneOnlyWhenEverySourceSaysSo(t *testing.T) {
	srv, asked := mirrorServer(t, map[string]http.HandlerFunc{
		"/mirror.gcr.io/":        func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) },
		"/public.ecr.aws/":       func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) },
		"/registry-1.docker.io/": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) },
	})
	c := &Client{HTTP: srv.Client(), Base: byHost(srv)}

	if _, err := c.Remote(context.Background(), image.Parse("python:3.12-slim")); err == nil {
		t.Errorf("a source that could not answer must not read as gone, asked %q", *asked)
	}
	if len(*asked) != 3 {
		t.Errorf("asked %q, want every source tried", *asked)
	}

	srv2, _ := mirrorServer(t, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) },
	})
	c2 := &Client{HTTP: srv2.Client(), Base: byHost(srv2)}
	remote, err := c2.Remote(context.Background(), image.Parse("python:3.12-slim"))
	if err != nil || !remote.Gone {
		t.Errorf("got %+v err %v, want gone when every source says so", remote, err)
	}
}
