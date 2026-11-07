package image

import "testing"

func TestParseDockerfile(t *testing.T) {
	tests := []struct {
		id   string
		src  string
		want []Ref
	}{
		{
			id:   "a plain base image",
			src:  "FROM debian:13.4\nRUN apt-get update\n",
			want: []Ref{{Image: "debian:13.4", Registry: "docker.io", Repo: "debian", Tag: "13.4", Source: "dockerfile", Line: 1}},
		},
		{
			id:  "an arg default is the image",
			src: "ARG NODE_IMAGE=docker.io/library/node:24-alpine\nFROM ${NODE_IMAGE} AS build\n",
			want: []Ref{{Image: "docker.io/library/node:24-alpine", Raw: "${NODE_IMAGE}", Via: "NODE_IMAGE",
				Registry: "docker.io", Repo: "library/node", Tag: "24-alpine", Source: "dockerfile", Line: 2, Stage: "build"}},
		},
		{
			id:  "an arg with no default leaves it open",
			src: "ARG CONTROLLER_IMAGE\nFROM ${CONTROLLER_IMAGE}\n",
			want: []Ref{{Image: "${CONTROLLER_IMAGE}", Raw: "${CONTROLLER_IMAGE}", Via: "CONTROLLER_IMAGE",
				Unresolved: true, Source: "dockerfile", Line: 2}},
		},
		{
			id:  "an inline default fills a missing arg",
			src: "FROM ${BASE:-alpine:3.20}\n",
			want: []Ref{{Image: "alpine:3.20", Raw: "${BASE:-alpine:3.20}", Via: "BASE",
				Registry: "docker.io", Repo: "alpine", Tag: "3.20", Source: "dockerfile", Line: 1}},
		},
		{
			id:   "a stage alias is not an image",
			src:  "FROM node:22 AS build\nRUN make\nFROM build\n",
			want: []Ref{{Image: "node:22", Registry: "docker.io", Repo: "node", Tag: "22", Source: "dockerfile", Line: 1, Stage: "build"}},
		},
		{
			id:   "a platform flag is not part of the image",
			src:  "FROM --platform=$BUILDPLATFORM golang:1.24 AS build\n",
			want: []Ref{{Image: "golang:1.24", Registry: "docker.io", Repo: "golang", Tag: "1.24", Source: "dockerfile", Line: 1, Stage: "build"}},
		},
		{
			id:   "scratch is named as it is",
			src:  "FROM scratch\n",
			want: []Ref{{Image: "scratch", Registry: "docker.io", Repo: "scratch", Tag: "latest", Source: "dockerfile", Line: 1, Presence: NotPulled}},
		},
		{
			id:  "a continuation line is one instruction",
			src: "FROM \\\n  ghcr.io/astral-sh/uv:0.11.6-python3.13-trixie@sha256:b3c5 AS uv\n",
			want: []Ref{{Image: "ghcr.io/astral-sh/uv:0.11.6-python3.13-trixie@sha256:b3c5", Registry: "ghcr.io",
				Repo: "astral-sh/uv", Tag: "0.11.6-python3.13-trixie", Digest: "sha256:b3c5", Source: "dockerfile", Line: 1, Stage: "uv"}},
		},
		{
			id:   "a comment is not an instruction",
			src:  "# FROM ignored:1\nFROM alpine:3.20\n",
			want: []Ref{{Image: "alpine:3.20", Registry: "docker.io", Repo: "alpine", Tag: "3.20", Source: "dockerfile", Line: 2}},
		},
	}
	for _, tt := range tests {
		got := ParseDockerfile("Dockerfile", []byte(tt.src))
		if len(got) != len(tt.want) {
			t.Fatalf("%s: %d refs, want %d: %+v", tt.id, len(got), len(tt.want), got)
		}
		for i := range got {
			got[i].File = ""
			if got[i] != tt.want[i] {
				t.Errorf("%s: ref %d\n got %+v\nwant %+v", tt.id, i, got[i], tt.want[i])
			}
		}
	}
}

func TestExpand(t *testing.T) {
	tests := []struct {
		in, out, missing string
		via              string
		ok               bool
		args             map[string]string
	}{
		{in: "${A}", out: "x", via: "A", ok: true, args: map[string]string{"A": "x"}},
		{in: "${A:-d}", out: "d", via: "A", ok: true, args: nil},
		{in: "$A", out: "y", via: "A", ok: true, args: map[string]string{"A": "y"}},
		{in: "${A}", missing: "A", via: "A", args: nil},
		{in: "plain", out: "plain", ok: true},
	}
	for _, tt := range tests {
		out, via, ok := expand(tt.in, tt.args)
		missing := ""
		if !ok {
			missing = via
		}
		if out != tt.out || missing != tt.missing || via != tt.via || ok != tt.ok {
			t.Errorf("expand(%q) = %q, %q, %v; want %q, %q, %v", tt.in, out, via, ok, tt.out, tt.via, tt.ok)
		}
	}
}
