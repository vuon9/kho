package image

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFind(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"Dockerfile":                  "FROM alpine:3.20\n",
		"api/Dockerfile":              "ARG BASE=node:22-alpine\nFROM ${BASE} AS build\n",
		"api/docker-compose.yml":      "services:\n  db:\n    image: postgres:13\n",
		"web/compose.yaml":            "services:\n  app:\n    image: nginx:1.29-alpine\n",
		"web/compose.override.yaml":   "services:\n  app:\n    image: nginx:1.29-alpine-alpine\n",
		"node_modules/pkg/Dockerfile": "FROM ignored:1\n",
		".hidden/Dockerfile":          "FROM hidden:1\n",
		"deploy/Dockerfile.prod":      "FROM scratch\n",
		"docs/notes.md":               "FROM not-a-dockerfile:1\n",
		"deep/a/b/c/d/Dockerfile":     "FROM too-deep:1\n",
	}
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Find(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range s.Refs {
		got[r.File+"|"+r.Image] = string(r.State)
	}
	want := []string{
		"Dockerfile|alpine:3.20",
		"api/Dockerfile|node:22-alpine",
		"api/docker-compose.yml|postgres:13",
		"web/compose.yaml|nginx:1.29-alpine",
		"deploy/Dockerfile.prod|scratch",
		"web/compose.override.yaml|nginx:1.29-alpine-alpine",
		"web/compose.override.yaml|nginx:1.29-alpine-alpine",
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing ref %q, have %v", w, got)
		}
	}
	for _, unwanted := range []string{"node_modules/pkg/Dockerfile|ignored:1", ".hidden/Dockerfile|hidden:1", "deep/a/b/c/d/Dockerfile|too-deep:1"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("found %q, which the walk should skip", unwanted)
		}
	}
	if len(s.Files) != 6 {
		t.Errorf("read %d files, want 6: %v", len(s.Files), s.Files)
	}
}

func TestFindBudget(t *testing.T) {
	old := Budget
	Budget = 0
	defer func() { Budget = old }()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Find(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if s.Capped == "" {
		t.Errorf("a zero budget should cap the walk, got %+v", s)
	}
}

type fakeAsker struct {
	remote map[string]Remote
	life   map[string]Life
}

func (f fakeAsker) Remote(_ context.Context, r Ref) (Remote, error) {
	if v, ok := f.remote[r.Canonical()]; ok {
		return v, nil
	}
	return Remote{}, errText("no route")
}

func (f fakeAsker) Life(_ context.Context, r Ref) (Life, error) {
	return f.life[r.Product()], nil
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	old := now.Add(-240 * day)
	recent := now.Add(-2 * day)
	tests := []struct {
		id   string
		ref  Ref
		rem  Remote
		life Life
		want State
	}{
		{id: "a closed line outranks a fresh digest",
			ref:  Parse("python:3.9-slim"),
			rem:  Remote{Digest: "sha256:new", Pushed: recent},
			life: Life{Cycle: "3.9", EOL: now.Add(-8 * day)},
			want: EOL},
		{id: "a tag the registry does not publish is gone",
			ref: Parse("nginx:1.27-alpine"), rem: Remote{Gone: true}, want: Gone},
		{id: "a digest with no tag has nothing to drift",
			ref: Parse("ghcr.io/astral-sh/uv@sha256:b3c5"), rem: Remote{Digest: "sha256:b3c5"}, want: Pinned},
		{id: "a tag that moved off the pinned digest is stale",
			ref: Ref{Image: "node:26-bookworm-slim", Registry: "docker.io", Repo: "node", Tag: "26-bookworm-slim", Digest: "sha256:mine"},
			rem: Remote{Digest: "sha256:theirs"}, want: Stale},
		{id: "a tag still on the pinned digest is fresh",
			ref: Ref{Image: "node:26-bookworm-slim", Registry: "docker.io", Repo: "node", Tag: "26-bookworm-slim", Digest: "sha256:same"},
			rem: Remote{Digest: "sha256:same"}, want: Fresh},
		{id: "a local build older than the tag is stale",
			ref:  Ref{Image: "node:22-alpine", Registry: "docker.io", Repo: "node", Tag: "22-alpine", Presence: OnDisk, Built: old},
			rem:  Remote{Digest: "sha256:x", Pushed: recent},
			want: Stale},
		{id: "a ref the registry answered nothing for is unknown",
			ref: Parse("node:22-alpine"), rem: Remote{}, want: Unknown},
		{id: "scratch has nothing to ask",
			ref: Parse("scratch"), rem: Remote{}, want: None},
		{id: "an unresolved ref stays without a state",
			ref: Ref{Image: "${BASE}", Unresolved: true}, rem: Remote{}, want: ""},
	}
	for _, tt := range tests {
		got := Decide(tt.ref, tt.rem, tt.life, now)
		if got.State != tt.want {
			t.Errorf("%s: state %q, want %q", tt.id, got.State, tt.want)
		}
	}
}

func TestJoin(t *testing.T) {
	local := []LocalImage{
		{Image: "postgres:13", Repo: "postgres", Tag: "13", Digest: "sha256:p", Created: time.Now()},
		{Image: "nginx:alpine", Repo: "nginx", Tag: "alpine", Digest: "sha256:n", Created: time.Now()},
	}
	refs := Join([]Ref{Parse("postgres:13"), Parse("nginx:1.27-alpine"), Parse("node:22-alpine")}, local)
	if refs[0].Presence != OnDisk {
		t.Errorf("postgres:13 should be on disk, got %q", refs[0].Presence)
	}
	if refs[1].Presence != NotPulled || refs[1].Note == "" {
		t.Errorf("nginx:1.27-alpine should be missing with a hint, got %q %q", refs[1].Presence, refs[1].Note)
	}
	if refs[2].Presence != NotPulled || refs[2].Note != "" {
		t.Errorf("node:22-alpine should be missing with no hint, got %q %q", refs[2].Presence, refs[2].Note)
	}
}
