// Package image never pulls, builds, runs or reads inside an image, so it cannot
// say whether one is vulnerable: only whether it is current, past its upstream
// life, or built here.
package image

import (
	"regexp"
	"strings"
	"time"
)

type State string

const (
	// Fresh means the tag still resolves to the digest the image carries.
	Fresh State = "fresh"
	// Stale means the tag was rebuilt upstream after this image was made.
	Stale State = "stale"
	EOL   State = "eol"
	Gone  State = "gone"
	// Pinned means the reference is a digest, so there is nothing to drift.
	Pinned State = "pinned"
	// Local means the image was built here and has no registry copy.
	Local State = "local"
	// None means there is nothing public to ask, as for scratch.
	None    State = "none"
	Unknown State = "unknown"
)

// Same marks as packages, so a stale image reads like an outdated package.
func (s State) Mark() string {
	switch s {
	case Fresh:
		return "✓"
	case Stale:
		return "↑"
	case EOL:
		return "⚠"
	case Gone:
		return "✗"
	case Pinned:
		return "⚑"
	}
	return "·"
}

const DockerHub = "docker.io"

// No registry holds the empty base image.
const Scratch = "scratch"

type Presence string

const (
	OnDisk Presence = "local"
	// NotPulled means docker answered and did not list it.
	NotPulled Presence = "missing"
	// Unasked means docker did not answer, so kho does not claim either way.
	Unasked Presence = "unknown"
)

func (p Presence) Mark() string {
	switch p {
	case OnDisk:
		return "●"
	case NotPulled:
		return "○"
	}
	return "?"
}

type Ref struct {
	// Once variables are resolved.
	Image string `json:"image"`
	// As the file spells it, when it differs, as for ${NODE_IMAGE}.
	Raw      string `json:"raw,omitempty"`
	Registry string `json:"registry"`
	Repo     string `json:"repo"`
	Tag      string `json:"tag,omitempty"`
	Digest   string `json:"digest,omitempty"`

	// Relative to the scan root and slash separated.
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Source  string `json:"source,omitempty"`
	Stage   string `json:"stage,omitempty"`
	Service string `json:"service,omitempty"`

	// Unresolved says the file does not say which image Via is.
	Via        string `json:"via,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"`
	StageRef   bool   `json:"-"`

	Presence Presence `json:"presence,omitempty"`
	Note     string   `json:"note,omitempty"`

	Upstream     string    `json:"upstream,omitempty"`
	Base         string    `json:"base,omitempty"`
	BaseVersion  string    `json:"baseVersion,omitempty"`
	Built        time.Time `json:"built,omitzero"`
	RemoteDigest string    `json:"remoteDigest,omitempty"`
	RemotePushed time.Time `json:"remotePushed,omitzero"`
	EOL          time.Time `json:"eol,omitzero"`
	State        State     `json:"state,omitempty"`
}

// Docker implies a docker.io/library prefix and a latest tag; a digest follows @.
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
	return DockerHub, s
}

func (r Ref) Canonical() string {
	if r.Tag == "" {
		return r.CanonicalRepo() + "@" + r.Digest
	}
	return r.CanonicalRepo() + ":" + r.Tag
}

func (r Ref) BaseImage() string {
	switch {
	case r.Base != "" && r.BaseVersion != "":
		return r.Base + ":" + r.BaseVersion
	case r.Base != "":
		return r.Base
	}
	return r.BaseVersion
}

func (r Ref) CanonicalRepo() string {
	return r.Registry + "/" + r.RemoteRepo()
}

// An official Docker Hub image lives under library/.
func (r Ref) RemoteRepo() string {
	if r.Registry == DockerHub && !strings.Contains(r.Repo, "/") {
		return "library/" + r.Repo
	}
	return r.Repo
}

// Docker lists an official image without the registry: node:22-alpine.
func (r Ref) Name() string {
	repo := r.Repo
	if r.Registry == DockerHub {
		repo = strings.TrimPrefix(repo, "library/")
	} else if r.Registry != "" {
		repo = r.Registry + "/" + repo
	}
	if r.Tag == "" {
		return repo + "@" + shortDigest(r.Digest)
	}
	return repo + ":" + r.Tag
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

var versionPrefix = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

func (r Ref) Cycle() string {
	base, _, _ := strings.Cut(r.Tag, "-")
	m := versionPrefix.FindStringSubmatch(base)
	if m == nil {
		return ""
	}
	return m[1]
}

// A repository missing here gets no end of life claim, rather than a guess.
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

func (r Ref) Product() string {
	repo := strings.TrimPrefix(r.CanonicalRepo(), r.Registry+"/")
	return products[repo]
}

type Tag struct {
	Name   string    `json:"name"`
	Pushed time.Time `json:"pushed,omitzero"`
	Digest string    `json:"digest,omitempty"`
}
