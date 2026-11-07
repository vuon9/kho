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
