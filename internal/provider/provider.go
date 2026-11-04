package provider

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sort"
	"time"
)

type Package struct {
	Source     string   `json:"source"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Latest     string   `json:"latest,omitempty"`
	Outdated   bool     `json:"outdated,omitempty"`
	Pinned     bool     `json:"pinned,omitempty"`
	Dependency bool     `json:"dependency,omitempty"`
	Versions   []string `json:"versions,omitempty"`
	Origin     string   `json:"origin,omitempty"`
	Desc       string   `json:"desc,omitempty"`
	Homepage   string   `json:"homepage,omitempty"`
	Path       string   `json:"path,omitempty"`
	Agents     []string `json:"agents,omitempty"`
	Note       string   `json:"note,omitempty"`
	// Repo is the GitHub owner/name the package is built from, when known.
	Repo string `json:"repo,omitempty"`
	// Entry is the main package `go install` builds a Go binary from.
	Entry string `json:"entry,omitempty"`
	Deps  []Dep  `json:"deps,omitempty"`
}

type Dep struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Direct  bool   `json:"direct,omitempty"`
}

// Release is one published version. URL is the page that holds its notes.
type Release struct {
	Version string    `json:"version"`
	Date    time.Time `json:"date,omitzero"`
	Notes   string    `json:"notes,omitempty"`
	URL     string    `json:"url,omitempty"`
}

// Provider adapts one package manager. List must be fast and local; Latest
// may hit the network and returns the packages with Latest and Outdated set.
// Deps and Versions load one package's details on demand, newest version first.
type Provider interface {
	Name() string
	Available() bool
	List(ctx context.Context) ([]Package, error)
	Latest(ctx context.Context, pkgs []Package) ([]Package, error)
	Deps(ctx context.Context, p Package) ([]Dep, error)
	Versions(ctx context.Context, p Package) ([]Release, error)
}

// ProviderOf names the provider a package belongs to.
func ProviderOf(p Package) string {
	if p.Source == "cask" {
		return "brew"
	}
	return p.Source
}

func All() []Provider {
	return []Provider{Brew{}, Npm{}, Pipx{}, Uv{}, GoBin{}, Mise{}, Skills{}}
}

// needs says what each provider looks for, so a provider that is not set up
// can be named instead of skipped in silence. Homebrew answers from its local
// package list, mise and cask are listed under their own names.
var needs = map[string]string{
	"brew":   "brew not on PATH",
	"npm":    "npm not on PATH",
	"pipx":   "pipx not on PATH",
	"uv":     "uv not on PATH",
	"go":     "no Go binary directory",
	"mise":   "mise not on PATH",
	"skills": "no ~/.agents/skills directory",
}

// Missing names every provider this machine is not set up for, with what was
// looked for. A provider that is left out of a scan reads as "nothing
// installed", which hides the packages it would have found, so callers report
// these instead of dropping them.
func Missing() map[string]string {
	out := map[string]string{}
	for _, p := range All() {
		if p.Available() {
			continue
		}
		reason, ok := needs[p.Name()]
		if !ok {
			reason = "not set up"
		}
		out[p.Name()] = reason
	}
	return out
}

func Available() []Provider {
	var ps []Provider
	for _, p := range All() {
		if p.Available() {
			ps = append(ps, p)
		}
	}
	return ps
}

func onPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// Record hears about every command a provider runs, for kho's history.
var Record = func(command []string, took time.Duration, err error) {}

// run returns stdout even when the command exits non-zero, because
// `npm outdated` exits 1 whenever it finds something.
func run(ctx context.Context, name string, args ...string) (out []byte, err error) {
	start := time.Now()
	defer func() { Record(append([]string{name}, args...), time.Since(start), err) }()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && stdout.Len() > 0 {
		return stdout.Bytes(), nil
	}
	if err != nil && stderr.Len() > 0 {
		return nil, errors.New(string(bytes.TrimSpace(stderr.Bytes())))
	}
	return stdout.Bytes(), err
}

func markOutdated(p *Package) {
	p.Outdated = p.Latest != "" && p.Latest != p.Version
}

func sortByName(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
}
