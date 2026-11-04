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
	// Missing is what this machine lacks for the provider, such as "uv not on
	// PATH", or "" when it is set up.
	Missing() string
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

// Detect splits All into the providers this machine is set up for and the
// ones it is not, with what each was missing. A provider that is left out of
// a scan reads as "nothing installed", which hides the packages it would have
// found, so callers report skipped instead of dropping it.
func Detect() (ready []Provider, skipped map[string]string) {
	skipped = map[string]string{}
	for _, p := range All() {
		if why := p.Missing(); why != "" {
			skipped[p.Name()] = why
		} else {
			ready = append(ready, p)
		}
	}
	return ready, skipped
}

func onPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func notOnPath(bin string) string {
	if onPath(bin) {
		return ""
	}
	return bin + " not on PATH"
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
