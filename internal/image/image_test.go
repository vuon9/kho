package image

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		id                       string
		in                       string
		registry, repo, tag, dig string
		canonical, name, cycle   string
	}{
		{id: "official image takes the library prefix", in: "node:22-alpine",
			registry: "docker.io", repo: "node", tag: "22-alpine",
			canonical: "docker.io/library/node:22-alpine", name: "node:22-alpine", cycle: "22"},
		{id: "a path stays under the user", in: "vanjayak/open-design:latest",
			registry: "docker.io", repo: "vanjayak/open-design", tag: "latest",
			canonical: "docker.io/vanjayak/open-design:latest", name: "vanjayak/open-design:latest", cycle: ""},
		{id: "a registry in the first part is kept", in: "ghcr.io/open-design/od:edge",
			registry: "ghcr.io", repo: "open-design/od", tag: "edge",
			canonical: "ghcr.io/open-design/od:edge", name: "ghcr.io/open-design/od:edge", cycle: ""},
		{id: "no tag means latest", in: "postgres",
			registry: "docker.io", repo: "postgres", tag: "latest",
			canonical: "docker.io/library/postgres:latest", name: "postgres:latest", cycle: ""},
		{id: "a digest keeps the tag", in: "node:26-bookworm-slim@sha256:9e6f",
			registry: "docker.io", repo: "node", tag: "26-bookworm-slim", dig: "sha256:9e6f",
			canonical: "docker.io/library/node:26-bookworm-slim", name: "node:26-bookworm-slim", cycle: "26"},
		{id: "a digest alone has no tag", in: "ghcr.io/astral-sh/uv@sha256:b3c5",
			registry: "ghcr.io", repo: "astral-sh/uv", tag: "", dig: "sha256:b3c5",
			canonical: "ghcr.io/astral-sh/uv@sha256:b3c5", name: "ghcr.io/astral-sh/uv@sha256:b3c5", cycle: ""},
		{id: "a port is not a tag", in: "localhost:5000/app:1.2",
			registry: "localhost:5000", repo: "app", tag: "1.2",
			canonical: "localhost:5000/app:1.2", name: "localhost:5000/app:1.2", cycle: "1.2"},
		{id: "python keeps two numbers", in: "python:3.12-slim",
			registry: "docker.io", repo: "python", tag: "3.12-slim",
			canonical: "docker.io/library/python:3.12-slim", name: "python:3.12-slim", cycle: "3.12"},
	}
	for _, tt := range tests {
		r := Parse(tt.in)
		if r.Registry != tt.registry || r.Repo != tt.repo || r.Tag != tt.tag || r.Digest != tt.dig {
			t.Errorf("%s: parsed %q as %s/%s:%s@%s", tt.id, tt.in, r.Registry, r.Repo, r.Tag, r.Digest)
		}
		if got := r.Canonical(); got != tt.canonical {
			t.Errorf("%s: canonical %q, want %q", tt.id, got, tt.canonical)
		}
		if got := r.Name(); got != tt.name {
			t.Errorf("%s: name %q, want %q", tt.id, got, tt.name)
		}
		if got := r.Cycle(); got != tt.cycle {
			t.Errorf("%s: cycle %q, want %q", tt.id, got, tt.cycle)
		}
	}
}

func TestProduct(t *testing.T) {
	tests := []struct{ in, want string }{
		{"node:22-alpine", "nodejs"},
		{"python:3.12-slim", "python"},
		{"postgres:17-alpine", "postgresql"},
		{"ghcr.io/open-design/od:edge", ""},
		{"vanjayak/open-design:latest", ""},
	}
	for _, tt := range tests {
		if got := Parse(tt.in).Product(); got != tt.want {
			t.Errorf("Product(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A base reads like a reference when both halves are known, and never makes one
// up when they are not.
func TestBaseImage(t *testing.T) {
	tests := []struct {
		id   string
		ref  Ref
		want string
	}{
		{"name and version", Ref{Base: "php", BaseVersion: "8.5.12"}, "php:8.5.12"},
		{"name only", Ref{Base: "debian"}, "debian"},
		{"version only", Ref{BaseVersion: "8.5.12"}, "8.5.12"},
		{"neither", Ref{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := tt.ref.BaseImage(); got != tt.want {
				t.Errorf("BaseImage() = %q, want %q", got, tt.want)
			}
		})
	}
}
