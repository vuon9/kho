// Package image reads the container images a project refers to and the ones
// a machine holds. It reads files and registry metadata. It never pulls,
// builds or runs an image, and it never reads inside one, so nothing here
// can say whether an image is vulnerable: only whether it is current, past
// its upstream life, or built here.
package image

import (
	"regexp"
	"strings"
	"time"
)

// State is what kho can say about an image. None of these mean "safe": kho
// does not read what is inside an image.
type State string

const (
	// Fresh means the tag still resolves to the digest the image carries.
	Fresh State = "fresh"
	// Stale means the tag was rebuilt upstream after this image was made.
	Stale State = "stale"
	// EOL means the upstream release line is past its end of life.
	EOL State = "eol"
	// Gone means the tag is no longer published at all.
	Gone State = "gone"
	// Pinned means the reference is a digest, so there is nothing to drift.
	Pinned State = "pinned"
	// Local means the image was built here and has no registry copy.
	Local State = "local"
	// None means there is nothing public to ask, as for scratch.
	None State = "none"
	// Unknown means kho could not ask the registry.
	Unknown State = "unknown"
)

// Presence says whether the machine holds an image.
type Presence string

const (
	// OnDisk means docker listed it.
	OnDisk Presence = "local"
	// NotPulled means docker answered and did not list it.
	NotPulled Presence = "missing"
	// Unasked means docker did not answer, so kho does not claim either way.
	Unasked Presence = "unknown"
)

// Ref is one image reference, as a file writes it and as kho understands it.
type Ref struct {
	// Image is the reference as written, once variables are resolved.
	Image string `json:"image"`
	// Raw is the reference as the file spells it, when it differs, as for
	// ${NODE_IMAGE}.
	Raw string `json:"raw,omitempty"`
	// Registry is the host the image comes from, docker.io when the file
	// leaves it out.
	Registry string `json:"registry"`
	// Repo is the repository path without the registry or the tag.
	Repo string `json:"repo"`
	Tag  string `json:"tag,omitempty"`
	// Digest is set when the reference pins one.
	Digest string `json:"digest,omitempty"`

	// File and Line say where the reference was read, relative to the scan
	// root and slash separated.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Source is dockerfile or compose.
	Source string `json:"source,omitempty"`
	// Stage is the Dockerfile stage the reference opens.
	Stage string `json:"stage,omitempty"`
	// Service is the compose service the reference belongs to.
	Service string `json:"service,omitempty"`

	// Via names the ARG or compose variable the image came from, and
	// Unresolved says the file does not say which image that is.
	Via        string `json:"via,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"`
	// StageRef says FROM named an earlier stage, not an image.
	StageRef bool `json:"-"`

	// Presence is filled from the machine's images.
	Presence Presence `json:"presence,omitempty"`
	// Note carries a hint, as when another tag of the same repository is on
	// disk.
	Note string `json:"note,omitempty"`

	// What the registry and the lifecycle pages said.
	Upstream     string    `json:"upstream,omitempty"`
	Base         string    `json:"base,omitempty"`
	BaseVersion  string    `json:"baseVersion,omitempty"`
	Built        time.Time `json:"built,omitzero"`
	RemoteDigest string    `json:"remoteDigest,omitempty"`
	RemotePushed time.Time `json:"remotePushed,omitzero"`
	EOL          time.Time `json:"eol,omitzero"`
	State        State     `json:"state,omitempty"`
}

// Parse splits a reference the way docker does: an implicit docker.io/library
// prefix, an implicit latest tag, and a digest after @.
func Parse(s string) Ref {
	r := Ref{Image: strings.TrimSpace(s)}
	rest := r.Image
	if i := strings.Index(rest, "@"); i >= 0 {
		r.Digest = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		r.Tag = rest[i+1:]
		rest = rest[:i]
	}
	r.Registry, r.Repo = splitRegistry(rest)
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r
}

func splitRegistry(s string) (registry, repo string) {
	first, rest, ok := strings.Cut(s, "/")
	if ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first, rest
	}
	return "docker.io", s
}

// Canonical is the reference with the registry and the library prefix
// spelled out, so the same image written two ways compares equal.
func (r Ref) Canonical() string {
	if r.Tag == "" {
		return r.CanonicalRepo() + "@" + r.Digest
	}
	return r.CanonicalRepo() + ":" + r.Tag
}

// BaseImage is the image this one sits on, written the way a reference is:
// php:8.5.12 when both halves are known, and whichever half we have when not.
func (r Ref) BaseImage() string {
	switch {
	case r.Base != "" && r.BaseVersion != "":
		return r.Base + ":" + r.BaseVersion
	case r.Base != "":
		return r.Base
	}
	return r.BaseVersion
}

// CanonicalRepo is Canonical without the tag, for finding another tag of the
// same repository.
func (r Ref) CanonicalRepo() string {
	return r.Registry + "/" + r.RemoteRepo()
}

// RemoteRepo is the repository path a registry expects: an official Docker
// Hub image lives under library/.
func (r Ref) RemoteRepo() string {
	if r.Registry == "docker.io" && !strings.Contains(r.Repo, "/") {
		return "library/" + r.Repo
	}
	return r.Repo
}

// Name is the reference without the registry, which is how docker lists an
// official image: node:22-alpine rather than docker.io/library/node.
func (r Ref) Name() string {
	repo := r.Repo
	if r.Registry == "docker.io" {
		repo = strings.TrimPrefix(repo, "library/")
	} else if r.Registry != "" {
		repo = r.Registry + "/" + repo
	}
	if r.Tag == "" {
		return repo + "@" + shortDigest(r.Digest)
	}
	return repo + ":" + r.Tag
}

// shortDigest trims a digest to what a person reads.
func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

var versionPrefix = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

// Cycle is the upstream release line a tag names, as in 22 from 22-alpine or
// 3.12 from 3.12-slim. It is "" when the tag names no version.
func (r Ref) Cycle() string {
	base, _, _ := strings.Cut(r.Tag, "-")
	m := versionPrefix.FindStringSubmatch(base)
	if m == nil {
		return ""
	}
	return m[1]
}

// products maps a repository to the endoflife.date product that publishes
// its release lines. A repository that is not here gets no end of life
// claim, rather than a guess.
var products = map[string]string{
	"library/node":          "nodejs",
	"library/python":        "python",
	"library/postgres":      "postgresql",
	"library/nginx":         "nginx",
	"library/redis":         "redis",
	"library/debian":        "debian",
	"library/alpine":        "alpine",
	"library/ubuntu":        "ubuntu",
	"library/golang":        "go",
	"library/ruby":          "ruby",
	"library/php":           "php",
	"library/mysql":         "mysql",
	"library/mariadb":       "mariadb",
	"library/elasticsearch": "elasticsearch",
	"library/memcached":     "memcached",
	"library/rabbitmq":      "rabbitmq",
	"library/mongo":         "mongodb",
	"library/httpd":         "apache-httpd",
	"library/caddy":         "caddy",
	"library/traefik":       "traefik",
}

// Product names the endoflife.date product a reference belongs to, or "".
func (r Ref) Product() string {
	repo := strings.TrimPrefix(r.CanonicalRepo(), r.Registry+"/")
	return products[repo]
}

// Tag is one tag a registry publishes for a repository.
type Tag struct {
	Name   string    `json:"name"`
	Pushed time.Time `json:"pushed,omitzero"`
	Digest string    `json:"digest,omitempty"`
}
