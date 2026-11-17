package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vuon9/kho/internal/image"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/hub/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseHubSearch(t *testing.T) {
	tests := []struct {
		id      string
		body    []byte
		want    []HubRepo
		wantErr string
	}{
		{id: "results keep the hub's order and drop a row with no name", body: fixture(t, "search.json"), want: []HubRepo{
			{Name: "kettle", Description: "Kettle boils water for every build.", Stars: 1204, Pulls: 51200000, Official: true},
			{Name: "acme/kettle-tools", Description: "Extra tools for kettle", Stars: 12, Pulls: 4300},
		}},
		{id: "no match is an empty list, not an error", body: []byte(`{"count":0,"results":[]}`), want: []HubRepo{}},
		{id: "bad JSON is a source error", body: []byte(`<html>busy</html>`), wantErr: "can't read"},
		{id: "an answer without results means the API changed", body: []byte(`{"count":3}`), wantErr: "no results list"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := parseHubSearch(tt.body)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, %v\nwant %+v", got, err, tt.want)
			}
		})
	}
}

func TestParseHubRepo(t *testing.T) {
	tests := []struct {
		id      string
		body    []byte
		want    HubRepo
		wantErr bool
	}{
		{id: "a namespaced repository", body: fixture(t, "repo.json"), want: HubRepo{Name: "acme/kettle-tools",
			Description: "Extra tools for kettle", Stars: 12, Pulls: 4300, Updated: time.Date(2031, 4, 2, 8, 15, 0, 123456000, time.UTC)}},
		{id: "an official repository drops library/", body: []byte(`{"namespace":"library","name":"kettle","pull_count":7}`),
			want: HubRepo{Name: "kettle", Pulls: 7, Official: true}},
		{id: "bad JSON", body: []byte(`{`), wantErr: true},
		{id: "no name", body: []byte(`{"namespace":"acme"}`), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := parseHubRepo(tt.body)
			if (err != nil) != tt.wantErr || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, %v\nwant %+v", got, err, tt.want)
			}
		})
	}
}

func TestParseHubTags(t *testing.T) {
	got, err := parseHubTags(fixture(t, "tags.json"))
	want := []image.Tag{
		{Name: "2.4.1", Pushed: time.Date(2031, 4, 2, 8, 15, 0, 123456000, time.UTC),
			Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Size:   48210944, Platforms: []string{"linux/amd64", "linux/arm64/v8"}},
		{Name: "latest", Pushed: time.Date(2031, 3, 30, 10, 0, 0, 0, time.UTC),
			Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			Size:   48210944, Platforms: []string{"linux/amd64"}},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, %v\nwant %+v", got, err, want)
	}
}

func TestHubRepoPath(t *testing.T) {
	tests := []struct {
		id, in, want string
		ok           bool
	}{
		{id: "a namespaced page", in: "https://hub.docker.com/r/acme/kettle-tools", want: "acme/kettle-tools", ok: true},
		{id: "an official page", in: "https://hub.docker.com/_/kettle", want: "kettle", ok: true},
		{id: "the tags page of a repository", in: "hub.docker.com/r/acme/kettle-tools/tags?name=2", want: "acme/kettle-tools", ok: true},
		{id: "a trailing slash", in: " http://hub.docker.com/_/kettle/ ", want: "kettle", ok: true},
		{id: "a keyword is not a page", in: "kettle"},
		{id: "a search page is not a repository", in: "https://hub.docker.com/search?q=kettle"},
		{id: "a user page is not a repository", in: "https://hub.docker.com/u/acme"},
		{id: "a path that climbs out", in: "https://hub.docker.com/r/../kettle"},
		{id: "another registry", in: "https://quay.io/repository/acme/kettle"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, ok := HubRepoPath(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Errorf("HubRepoPath(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestSearchHub(t *testing.T) {
	tests := []struct {
		id      string
		query   string
		status  int
		body    []byte
		want    []string
		path    string
		wantErr error
	}{
		{id: "keywords ask the search API", query: "kettle", status: 200, body: fixture(t, "search.json"),
			want: []string{"kettle", "acme/kettle-tools"}, path: "/v2/search/repositories/?query=kettle&page_size=20"},
		{id: "a pasted page asks for that repository", query: "https://hub.docker.com/r/acme/kettle-tools", status: 200,
			body: fixture(t, "repo.json"), want: []string{"acme/kettle-tools"}, path: "/v2/repositories/acme/kettle-tools/"},
		{id: "an official page asks under library", query: "https://hub.docker.com/_/kettle", status: 200,
			body: []byte(`{"namespace":"library","name":"kettle"}`), want: []string{"kettle"}, path: "/v2/repositories/library/kettle/"},
		{id: "a rate limit is a source error", query: "kettle", status: 429, wantErr: ErrHubRateLimited},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			var asked []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked = append(asked, r.URL.RequestURI())
				if ua := r.Header.Get("User-Agent"); ua != userAgent {
					t.Errorf("User-Agent %q", ua)
				}
				w.WriteHeader(tt.status)
				w.Write(tt.body)
			}))
			defer srv.Close()
			c := &Client{HTTP: srv.Client(), HubBase: srv.URL}
			got, err := c.SearchHub(context.Background(), tt.query, 20)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err %v, want %v", err, tt.wantErr)
				}
				return
			}
			var names []string
			for _, r := range got {
				names = append(names, r.Name)
			}
			if err != nil || !reflect.DeepEqual(names, tt.want) || !reflect.DeepEqual(asked, []string{tt.path}) {
				t.Errorf("got %v, %v after asking %v; want %v after %s", names, err, asked, tt.want, tt.path)
			}
		})
	}
}

func TestSearchHubAsksOncePerQuery(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write(fixture(t, "search.json"))
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), HubBase: srv.URL}
	for range 2 {
		if _, err := c.SearchHub(context.Background(), "kettle", 20); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("asked docker hub %d times for one query", hits.Load())
	}
}

func TestSuggestTag(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2031, 1, d, 0, 0, 0, 0, time.UTC) }
	tests := []struct {
		id   string
		tags []image.Tag
		want string
	}{
		{id: "latest wins when it exists", tags: []image.Tag{{Name: "2.0", Pushed: day(9)}, {Name: "latest", Pushed: day(1)}}, want: "latest"},
		{id: "else the most recently pushed", tags: []image.Tag{{Name: "1.0", Pushed: day(1)}, {Name: "2.0-slim", Pushed: day(9)}, {Name: "2.0", Pushed: day(5)}}, want: "2.0-slim"},
		{id: "no tags", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := SuggestTag(tt.tags); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHubRepoURL(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"kettle", HubURL + "/_/kettle"},
		{"acme/kettle-tools", HubURL + "/r/acme/kettle-tools"},
	} {
		if got := (HubRepo{Name: tt.name}).URL(); got != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestPullRef(t *testing.T) {
	tests := []struct {
		id, name, tag, want string
		ok                  bool
	}{
		{id: "an official image", name: "kettle", tag: "2.4.1", want: "kettle:2.4.1", ok: true},
		{id: "a namespaced image", name: "acme/kettle-tools", tag: "latest", want: "acme/kettle-tools:latest", ok: true},
		{id: "a name that reads as a flag", name: "-v/kettle", tag: "latest"},
		{id: "a tag that reads as a flag", name: "kettle", tag: "--help"},
		{id: "a tag with a space", name: "kettle", tag: "1 2"},
		{id: "a name with a host", name: "evil.example/acme/kettle", tag: "1"},
		{id: "an empty tag", name: "kettle", tag: ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, ok := HubRepo{Name: tt.name}.PullRef(tt.tag)
			if got != tt.want || ok != tt.ok {
				t.Errorf("got %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestHubTagsFindANamedTagPastTheNewestPage(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("name"))
		if r.URL.Query().Get("name") == "latest" {
			w.Write([]byte(`{"results":[{"name":"latest-slim"},{"name":"latest"}]}`))
			return
		}
		w.Write([]byte(`{"results":[{"name":"9.1-slim"},{"name":"9.1"}]}`))
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), HubBase: srv.URL}
	tags, err := c.Tags(context.Background(), image.Parse("kettle:latest"))
	var names []string
	for _, tag := range tags {
		names = append(names, tag.Name)
	}
	if err != nil || !reflect.DeepEqual(names, []string{"9.1-slim", "9.1", "latest"}) || !reflect.DeepEqual(asked, []string{"", "latest"}) {
		t.Errorf("got %v, %v after asking %q", names, err, asked)
	}
	if SuggestTag(tags) != "latest" {
		t.Errorf("suggested %q, want latest", SuggestTag(tags))
	}
}

func TestMirrorRef(t *testing.T) {
	index := []byte(`{"manifests":[]}`)
	old := []byte(`{"manifests":[{"digest":"sha256:0"}]}`)
	serve := func(body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { w.Write(body) }
	}
	missing := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
	tests := []struct {
		id        string
		ref       string
		digest    string
		gcr, ecr  http.HandlerFunc
		want      string
		wantStale bool
	}{
		{id: "the first mirror with the tag", ref: "kettle:2.4.1", digest: digestOf(index), gcr: serve(index), ecr: serve(index),
			want: "mirror.gcr.io/library/kettle:2.4.1"},
		{id: "the next mirror when the first lacks it", ref: "kettle:2.4.1", gcr: missing, ecr: serve(index),
			want: "public.ecr.aws/docker/library/kettle:2.4.1"},
		{id: "a stale copy is skipped for a current one", ref: "kettle:latest", digest: digestOf(index), gcr: serve(old), ecr: serve(index),
			want: "public.ecr.aws/docker/library/kettle:latest"},
		{id: "only stale copies send it to Docker Hub", ref: "kettle:latest", digest: digestOf(index), gcr: serve(old), ecr: serve(old), wantStale: true},
		{id: "no mirror has it", ref: "acme/kettle-tools:0.4", gcr: missing, ecr: missing},
		{id: "a mirror that fails is passed over", ref: "kettle:2.4.1",
			gcr: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }, ecr: serve(index),
			want: "public.ecr.aws/docker/library/kettle:2.4.1"},
		{id: "another registry has no mirror", ref: "ghcr.io/acme/kettle:1", gcr: serve(index), ecr: serve(index)},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			srv, asked := mirrorServer(t, map[string]http.HandlerFunc{
				"/mirror.gcr.io/":  tt.gcr,
				"/public.ecr.aws/": tt.ecr,
			})
			c := &Client{HTTP: srv.Client(), Base: byHost(srv)}
			got, stale := c.MirrorRef(context.Background(), image.Parse(tt.ref), tt.digest)
			if got != tt.want || stale != tt.wantStale {
				t.Errorf("got %q, stale %v; want %q, %v", got, stale, tt.want, tt.wantStale)
			}
			for _, a := range *asked {
				if strings.Contains(a, "registry-1.docker.io") {
					t.Errorf("asked Docker Hub itself: %s", a)
				}
			}
		})
	}
}
