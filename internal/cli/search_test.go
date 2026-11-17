package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

type fakeProvider struct {
	name      string
	installed []provider.Package
	versions  []provider.Release
	listErr   error
}

func (f *fakeProvider) Name() string    { return f.name }
func (f *fakeProvider) Missing() string { return "" }
func (f *fakeProvider) List(context.Context) ([]provider.Package, error) {
	return f.installed, f.listErr
}
func (f *fakeProvider) Latest(_ context.Context, pkgs []provider.Package) ([]provider.Package, error) {
	return pkgs, nil
}
func (f *fakeProvider) Deps(context.Context, provider.Package) ([]provider.Dep, error) {
	return nil, nil
}
func (f *fakeProvider) Versions(context.Context, provider.Package) ([]provider.Release, error) {
	return f.versions, nil
}

type fakeSearchCall struct {
	query    string
	limit    int
	deadline bool
}

type fakeSearchable struct {
	fakeProvider
	results   []provider.Package
	searchErr error
	calls     []fakeSearchCall
}

func (f *fakeSearchable) Search(ctx context.Context, query string, limit int) ([]provider.Package, error) {
	_, hasDeadline := ctx.Deadline()
	f.calls = append(f.calls, fakeSearchCall{query, limit, hasDeadline})
	return f.results, f.searchErr
}

type fakeFindable struct {
	fakeProvider
	found   provider.Package
	findErr error
	finds   []string
}

func (f *fakeFindable) Find(_ context.Context, source, name string) (provider.Package, error) {
	f.finds = append(f.finds, source+"/"+name)
	return f.found, f.findErr
}

// Installing a new package needs both search and find from the managers that can search.
type fakeFull struct {
	fakeProvider
	results   []provider.Package
	found     provider.Package
	searchErr error
	findErr   error
	calls     []fakeSearchCall
	finds     []string
}

func (f *fakeFull) Search(ctx context.Context, query string, limit int) ([]provider.Package, error) {
	_, hasDeadline := ctx.Deadline()
	f.calls = append(f.calls, fakeSearchCall{query, limit, hasDeadline})
	return f.results, f.searchErr
}

func (f *fakeFull) Find(_ context.Context, source, name string) (provider.Package, error) {
	f.finds = append(f.finds, source+"/"+name)
	return f.found, f.findErr
}

func catalogKho(t *testing.T, providers []provider.Provider, skipped map[string]string, args ...string) run {
	t.Helper()
	var out, errOut bytes.Buffer
	var r run
	env := Env{
		Version:   "v9.9.9",
		Providers: providers,
		Skipped:   skipped,
		DB:        vuln.NewDB(),
		Log:       history.Open(""),
		Out:       &out,
		Err:       &errOut,
		Now:       func() time.Time { return clock },
		Scan: func(context.Context, []vuln.Query, map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
			return map[string][]string{}, map[string]vuln.Advisory{}, nil
		},
		Audits: func(context.Context, map[string][]string) (map[string]vuln.SkillAudit, error) {
			return nil, nil
		},
		Run: func(cmd *exec.Cmd) (string, error) {
			r.ran = append(r.ran, strings.Join(cmd.Args, " "))
			return "installed", nil
		},
	}
	r.code = Main(env, args)
	r.out, r.err, r.log = out.String(), errOut.String(), env.Log.Entries()
	return r
}

func TestSearch(t *testing.T) {
	defaultLimit := &fakeSearchable{fakeProvider: fakeProvider{name: "brew"}}
	tests := []struct {
		id        string
		providers []provider.Provider
		skipped   map[string]string
		args      []string
		code      int
		out       string
		err       string
		check     func(t *testing.T) string
	}{
		{
			id: "results print one copyable row each and name what answered",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A YAML processor"},
				}},
				&fakeSearchable{fakeProvider: fakeProvider{name: "npm"}, results: []provider.Package{
					{Source: "npm", Name: "yml", Latest: "2.8.1", Desc: "A YAML lib"},
				}},
			},
			args: []string{"search", "yaml"},
			code: ExitOK,
			out:  "brew/yq  0.2.94  A YAML processor\nnpm/yml  2.8.1   A YAML lib\n\nsearched brew, cask, npm in 0.0s\n",
		},
		{
			id: "a name-only manager is named, not dropped",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}},
				&fakeFindable{fakeProvider: fakeProvider{name: "pipx"}},
				&fakeFindable{fakeProvider: fakeProvider{name: "uv"}},
				&fakeFindable{fakeProvider: fakeProvider{name: "go"}},
			},
			args: []string{"search", "yaml"},
			code: ExitOK,
			out: "no packages match \"yaml\"\nsearched brew, cask in 0.0s\n" +
				"pipx, uv and go cannot search by keyword; install one by exact name, like kho install pipx/ruff@latest\n",
		},
		{
			id: "a failed source does not hide the ones that answered",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A YAML processor"},
				}},
				&fakeSearchable{fakeProvider: fakeProvider{name: "npm"}, searchErr: errors.New("429 too many requests")},
			},
			args: []string{"search", "yaml"},
			code: ExitOK,
			out:  "brew/yq  0.2.94  A YAML processor\n\nsearched brew, cask in 0.0s\n",
			err:  "npm could not search: 429 too many requests\n",
		},
		{
			id: "every source failed exits 1",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, searchErr: errors.New("brew is down")},
				&fakeSearchable{fakeProvider: fakeProvider{name: "npm"}, searchErr: errors.New("npm is down")},
			},
			args: []string{"search", "yaml"},
			code: ExitError,
			err:  "brew could not search: brew is down\nnpm could not search: npm is down\ncould not search any package manager\n",
		},
		{
			id: "no match is still an answer",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}},
			},
			args: []string{"search", "zzzz"},
			code: ExitOK,
			out:  "no packages match \"zzzz\"\nsearched brew, cask in 0.0s\n",
		},
		{
			id: "a source that gave no version shows a question mark",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "composer"}, results: []provider.Package{
					{Source: "composer", Name: "acme/yaml", Desc: "A YAML package"},
				}},
			},
			args: []string{"search", "yaml"},
			code: ExitOK,
			out:  "composer/acme/yaml  ?  A YAML package\n\nsearched composer in 0.0s\n",
		},
		{
			id:        "one character is a usage error",
			providers: []provider.Provider{defaultLimit},
			args:      []string{"search", "z"},
			code:      ExitUsage,
			err:       "search needs at least 2 characters\n",
		},
		{
			id:   "a missing query is a usage error",
			args: []string{"search"},
			code: ExitUsage,
			err:  "usage: kho search <query...> [--source brew,npm] [--limit N] [--json]\n",
		},
		{
			id: "descriptions cannot move the cursor",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A \x1b[31mred\x1b[0m\nparser\tfor yaml"},
				}},
			},
			args: []string{"search", "yaml"},
			code: ExitOK,
			out:  "brew/yq  0.2.94  A red parser for yaml\n\nsearched brew, cask in 0.0s\n",
		},
		{
			id:        "a search asks for the default limit under a deadline",
			providers: []provider.Provider{defaultLimit},
			args:      []string{"search", "yaml"},
			code:      ExitOK,
			out:       "no packages match \"yaml\"\nsearched brew, cask in 0.0s\n",
			check: func(t *testing.T) string {
				if len(defaultLimit.calls) != 1 {
					return "brew was asked " + itoa(len(defaultLimit.calls)) + " times"
				}
				call := defaultLimit.calls[0]
				if call.query != "yaml" || call.limit != 20 || !call.deadline {
					return "brew was asked for " + call.query + " with limit " + itoa(call.limit)
				}
				return ""
			},
		},
		{
			id:      "a named source this machine lacks exits 1",
			skipped: map[string]string{"uv": "uv not on PATH"},
			args:    []string{"search", "ruff", "--source", "uv"},
			code:    ExitError,
			err:     "uv is not on this machine (uv not on PATH)\ncould not search any package manager\n",
		},
		{
			id:        "a ready manager that cannot search fails cleanly",
			providers: []provider.Provider{&fakeProvider{name: "pipx"}},
			args:      []string{"search", "ruff", "--source", "pipx"},
			code:      ExitError,
			err:       "pipx could not search: pipx cannot search yet\ncould not search any package manager\n",
		},
		{
			id: "no searcher ready names the exact-name managers and exits 1",
			providers: []provider.Provider{
				&fakeFindable{fakeProvider: fakeProvider{name: "pipx"}},
				&fakeFindable{fakeProvider: fakeProvider{name: "uv"}},
				&fakeFindable{fakeProvider: fakeProvider{name: "go"}},
			},
			args: []string{"search", "yaml"},
			code: ExitError,
			out: "pipx, uv and go cannot search by keyword; install one by exact name, " +
				"like kho install pipx/ruff@latest\n",
			err: "no package manager on this machine can search by keyword\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := catalogKho(t, tt.providers, tt.skipped, tt.args...)
			why := ""
			if got.code != tt.code {
				why = "exit code"
			} else if got.out != tt.out {
				why = "stdout"
			} else if got.err != tt.err {
				why = "stderr"
			} else if tt.check != nil {
				why = tt.check(t)
			}
			if why != "" {
				t.Errorf("%s: exit %d\nstdout %q\nstderr %q", why, got.code, got.out, got.err)
			}
		})
	}
}

func TestSearchNarrowsTheSource(t *testing.T) {
	limitFive := &fakeSearchable{fakeProvider: fakeProvider{name: "npm"}}
	joined := &fakeSearchable{fakeProvider: fakeProvider{name: "brew"}}
	tests := []struct {
		id    string
		world []provider.Provider
		args  []string
		code  int
		out   string
		err   string
		check func(t *testing.T) string
	}{
		{
			id: "brew asks only formulae",
			world: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A YAML processor"},
					{Source: "cask", Name: "focobar", Latest: "1.2.3", Desc: "A cask"},
				}},
			},
			args: []string{"search", "yq", "--source", "brew"},
			code: ExitOK,
			out:  "brew/yq  0.2.94  A YAML processor\n\nsearched brew in 0.0s\n",
		},
		{
			id: "cask asks only casks",
			world: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A YAML processor"},
					{Source: "cask", Name: "focobar", Latest: "1.2.3", Desc: "A cask"},
				}},
			},
			args: []string{"search", "yq", "--source", "cask"},
			code: ExitOK,
			out:  "cask/focobar  1.2.3  A cask\n\nsearched cask in 0.0s\n",
		},
		{
			id: "a name-only manager resolves the exact name",
			world: []provider.Provider{
				&fakeFindable{fakeProvider: fakeProvider{name: "uv"}, found: provider.Package{
					Source: "uv", Name: "ruff", Latest: "0.14.0", Desc: "A Python linter",
				}},
			},
			args: []string{"search", "ruff", "--source", "uv"},
			code: ExitOK,
			out:  "uv/ruff  0.14.0  A Python linter\n\nsearched uv in 0.0s\n",
		},
		{
			id: "an exact-name manager with no match answers",
			world: []provider.Provider{
				&fakeFindable{fakeProvider: fakeProvider{name: "uv"}},
			},
			args: []string{"search", "zzzz", "--source", "uv"},
			code: ExitOK,
			out:  "no packages match \"zzzz\"\nsearched uv in 0.0s\n",
		},
		{
			id:   "mise cannot be searched",
			args: []string{"search", "yaml", "--source", "mise"},
			code: ExitUsage,
			err:  "--source mise is not supported yet\n",
		},
		{
			id:   "an unknown source is a usage error",
			args: []string{"search", "yaml", "--source", "npmm"},
			code: ExitUsage,
			err:  "unknown source in --source: npmm\n",
		},
		{
			id:   "a limit under one is a usage error",
			args: []string{"search", "yaml", "--limit", "0"},
			code: ExitUsage,
			err:  "--limit must be at least 1\n",
		},
		{
			id:    "arguments join into one query",
			world: []provider.Provider{joined},
			args:  []string{"search", "yaml", "parser"},
			code:  ExitOK,
			out:   "no packages match \"yaml parser\"\nsearched brew, cask in 0.0s\n",
			check: func(t *testing.T) string {
				if len(joined.calls) != 1 || joined.calls[0].query != "yaml parser" {
					return "the words did not join into one query"
				}
				return ""
			},
		},
		{
			id:    "a custom limit reaches the source",
			world: []provider.Provider{limitFive},
			args:  []string{"search", "yaml", "--limit", "5", "--source", "npm"},
			code:  ExitOK,
			out:   "no packages match \"yaml\"\nsearched npm in 0.0s\n",
			check: func(t *testing.T) string {
				if len(limitFive.calls) != 1 || limitFive.calls[0].limit != 5 {
					return "the limit did not reach the source"
				}
				return ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := catalogKho(t, tt.world, nil, tt.args...)
			why := ""
			if got.code != tt.code {
				why = "exit code"
			} else if got.out != tt.out {
				why = "stdout"
			} else if got.err != tt.err {
				why = "stderr"
			} else if tt.check != nil {
				why = tt.check(t)
			}
			if why != "" {
				t.Errorf("%s: exit %d\nstdout %q\nstderr %q", why, got.code, got.out, got.err)
			}
		})
	}
}

func TestSearchJSON(t *testing.T) {
	tests := []struct {
		id        string
		providers []provider.Provider
		skipped   map[string]string
		args      []string
		code      int
		want      SearchReport
	}{
		{
			id: "the report carries results, what was not searched, skipped and errors",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A lightweight and portable command-line YAML processor",
						Homepage: "https://mikefarah.gitbook.io/yq/", Repo: "mikefarah/yq"},
					{Source: "cask", Name: "focobar", Latest: "1.2.3"},
				}},
				&fakeFindable{fakeProvider: fakeProvider{name: "pipx"}},
			},
			skipped: map[string]string{"uv": "uv not on PATH"},
			args:    []string{"search", "yaml", "--json"},
			code:    ExitOK,
			want: SearchReport{
				Query: "yaml",
				Results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A lightweight and portable command-line YAML processor",
						Homepage: "https://mikefarah.gitbook.io/yq/", Repo: "mikefarah/yq"},
					{Source: "cask", Name: "focobar", Latest: "1.2.3"},
				},
				NotSearched: []string{"pipx"},
				Skipped:     map[string]string{"uv": "uv not on PATH"},
				Errors:      map[string]string{},
			},
		},
		{
			id: "an exact-name lookup has one result and no notSearched",
			providers: []provider.Provider{
				&fakeFindable{fakeProvider: fakeProvider{name: "uv"}, found: provider.Package{
					Source: "uv", Name: "ruff", Latest: "0.14.0", Desc: "A Python linter",
				}},
			},
			args: []string{"search", "ruff", "--source", "uv", "--json"},
			code: ExitOK,
			want: SearchReport{
				Query: "ruff",
				Results: []provider.Package{
					{Source: "uv", Name: "ruff", Latest: "0.14.0", Desc: "A Python linter"},
				},
				NotSearched: []string{},
				Skipped:     map[string]string{},
				Errors:      map[string]string{},
			},
		},
		{
			id: "a failed source is an error keyed by manager, not a lost result",
			providers: []provider.Provider{
				&fakeSearchable{fakeProvider: fakeProvider{name: "brew"}, results: []provider.Package{
					{Source: "brew", Name: "yq", Latest: "0.2.94"},
				}},
				&fakeSearchable{fakeProvider: fakeProvider{name: "npm"}, searchErr: errors.New("429 too many requests")},
			},
			args: []string{"search", "yaml", "--json"},
			code: ExitOK,
			want: SearchReport{
				Query:       "yaml",
				Results:     []provider.Package{{Source: "brew", Name: "yq", Latest: "0.2.94"}},
				NotSearched: []string{},
				Skipped:     map[string]string{},
				Errors:      map[string]string{"npm": "429 too many requests"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := catalogKho(t, tt.providers, tt.skipped, tt.args...)
			if got.code != tt.code {
				t.Fatalf("exit %d, want %d: stderr %q", got.code, tt.code, got.err)
			}
			var report SearchReport
			if err := json.Unmarshal([]byte(got.out), &report); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, got.out)
			}
			if !reflect.DeepEqual(report, tt.want) {
				t.Errorf("got  %+v\nwant %+v", report, tt.want)
			}
		})
	}
}

func TestInstallNew(t *testing.T) {
	uvRuff := func() *fakeFindable {
		return &fakeFindable{
			fakeProvider: fakeProvider{name: "uv", versions: []provider.Release{{Version: "0.14.0"}}},
			found:        provider.Package{Source: "uv", Name: "ruff", Latest: "0.14.0"},
		}
	}
	tests := []struct {
		id        string
		providers []provider.Provider
		skipped   map[string]string
		args      []string
		code      int
		out       string
		err       string
		ran       []string
		log       int
		json      *InstallResult
	}{
		{
			id:        "a new package dry run says the exact command",
			providers: []provider.Provider{uvRuff()},
			args:      []string{"install", "uv/ruff@latest"},
			code:      ExitOK,
			out:       "would run: uv tool install ruff==0.14.0\nadd --yes to run it\n",
		},
		{
			id: "a skill installs its newest commit",
			providers: []provider.Provider{&fakeFull{fakeProvider: fakeProvider{name: "skills"}, found: provider.Package{
				Source: "skills", Name: "yaml", Entry: "yaml", Repo: "acme/skills", Latest: provider.SkillNewest,
			}}},
			args: []string{"install", "skills/yaml@latest"},
			code: ExitOK,
			out:  "would run: npx -y skills add acme/skills --skill yaml -g -y --json\nadd --yes to run it\n",
		},
		{
			id:        "a new package with --yes runs it and records the change",
			providers: []provider.Provider{uvRuff()},
			args:      []string{"install", "uv/ruff@latest", "--yes"},
			code:      ExitOK,
			ran:       []string{"uv tool install ruff==0.14.0"},
			log:       1,
		},
		{
			id:        "JSON marks the install as new with no from version",
			providers: []provider.Provider{uvRuff()},
			args:      []string{"install", "uv/ruff@latest", "--json"},
			code:      ExitOK,
			json: &InstallResult{Package: "uv/ruff", From: "", To: "0.14.0", New: true,
				Command: []string{"uv", "tool", "install", "ruff==0.14.0"}},
		},
		{
			id: "an installed package keeps its upgrade path",
			providers: []provider.Provider{
				&fakeFull{fakeProvider: fakeProvider{name: "pipx",
					installed: []provider.Package{{Source: "pipx", Name: "bramble", Version: "22.12.0", Latest: "26.10.1", Outdated: true}},
					versions:  []provider.Release{{Version: "26.10.1"}, {Version: "24.3.0"}, {Version: "22.12.0"}}}},
			},
			args: []string{"install", "pipx/bramble@24.3.0", "--json"},
			code: ExitOK,
			json: &InstallResult{Package: "pipx/bramble", From: "22.12.0", To: "24.3.0",
				Command: []string{"pipx", "install", "--force", "bramble==24.3.0"}},
		},
		{
			id: "a pinned package is still refused",
			providers: []provider.Provider{
				&fakeFull{fakeProvider: fakeProvider{name: "pipx",
					installed: []provider.Package{{Source: "pipx", Name: "inkwell", Version: "9.0.2", Latest: "9.0.2", Pinned: true}},
					versions:  []provider.Release{{Version: "9.0.2"}}}},
			},
			args: []string{"install", "pipx/inkwell@9.0.2", "--yes"},
			code: ExitError,
			err:  "inkwell is pinned, so kho leaves it where it is\n",
		},
		{
			id:        "a name no registry knows",
			providers: []provider.Provider{&fakeFindable{fakeProvider: fakeProvider{name: "uv"}, findErr: errors.New("PyPI says 404")}},
			args:      []string{"install", "uv/nope@latest"},
			code:      ExitError,
			err:       "could not find nope in uv: PyPI says 404\n",
		},
		{
			id:        "a version never published",
			providers: []provider.Provider{uvRuff()},
			args:      []string{"install", "uv/ruff@0.9.9"},
			code:      ExitError,
			err:       "ruff has no published version \"0.9.9\"\n",
		},
		{
			id:      "a source this machine lacks",
			skipped: map[string]string{"uv": "uv not on PATH"},
			args:    []string{"install", "uv/ruff@latest"},
			code:    ExitError,
			err:     "uv is not on this machine (uv not on PATH)\n",
		},
		{
			id: "a manager that only installs its newest keeps that refusal",
			providers: []provider.Provider{
				&fakeFull{fakeProvider: fakeProvider{name: "brew"}, found: provider.Package{Source: "brew", Name: "anvil", Latest: "0.2.94"}},
			},
			args: []string{"install", "brew/anvil@0.2.1"},
			code: ExitError,
			err:  "Homebrew can only install the newest version, 0.2.94\n",
		},
		{
			id: "a cask installs through brew with the cask flag",
			providers: []provider.Provider{
				&fakeFull{fakeProvider: fakeProvider{name: "brew"}, found: provider.Package{Source: "cask", Name: "focobar", Latest: "1.2.3"}},
			},
			args: []string{"install", "cask/focobar@latest"},
			code: ExitOK,
			out:  "would run: brew install --cask focobar\nadd --yes to run it\n",
		},
		{
			id:        "a manager that cannot install new packages says so",
			providers: []provider.Provider{&fakeProvider{name: "mise"}},
			args:      []string{"install", "mise/tool@latest"},
			code:      ExitError,
			err:       "kho can't install new mise packages yet\n",
		},
		{
			id:   "an unknown source is an error",
			args: []string{"install", "frobnicate/widget@latest"},
			code: ExitError,
			err:  "\"frobnicate\" is not a source kho knows; try brew, cask, npm, composer, pipx, uv, mise, go or skills\n",
		},
		{
			id:   "a ref with no source still names the shape",
			args: []string{"install", "plain@1.2.3"},
			code: ExitError,
			err:  "\"plain\" is not source/name, like pipx/ruff\n",
		},
		{
			id:        "latest with no known latest fails",
			providers: []provider.Provider{&fakeFindable{fakeProvider: fakeProvider{name: "uv"}, found: provider.Package{Source: "uv", Name: "ruff"}}},
			args:      []string{"install", "uv/ruff@latest"},
			code:      ExitError,
			err:       "no latest version known for ruff\n",
		},
		{
			id:        "an npm candidate installs at the chosen version",
			providers: []provider.Provider{&fakeFull{fakeProvider: fakeProvider{name: "npm", versions: []provider.Release{{Version: "2.0.0"}, {Version: "1.0.0"}}}, found: provider.Package{Source: "npm", Name: "yaml", Latest: "2.0.0"}}},
			args:      []string{"install", "npm/yaml@1.0.0", "--yes"},
			code:      ExitOK,
			ran:       []string{"npm install -g yaml@1.0.0"},
			log:       1,
		},
		{
			id: "a Go version the proxy cannot pre-check is best effort",
			providers: []provider.Provider{&fakeFull{fakeProvider: fakeProvider{name: "go"}, found: provider.Package{
				Source: "go", Name: "tool", Latest: "v0.0.0-20260101000000-abcdef123456",
				Origin: "example.com/tool", Entry: "example.com/tool"}}},
			args: []string{"install", "go/example.com/tool@latest"},
			code: ExitOK,
			out:  "would run: go install example.com/tool@v0.0.0-20260101000000-abcdef123456\nadd --yes to run it\n",
			err:  "note: tool has no published version \"v0.0.0-20260101000000-abcdef123456\"; go install is the final check\n",
		},
		{
			id:   "a missing version is still a usage error",
			args: []string{"install", "uv/ruff"},
			code: ExitUsage,
			err:  "say which version: kho install <source>/<name>@<version|latest>\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := catalogKho(t, tt.providers, tt.skipped, tt.args...)
			if got.code != tt.code {
				t.Fatalf("exit %d, want %d\nstdout %q\nstderr %q", got.code, tt.code, got.out, got.err)
			}
			if tt.json != nil {
				var res InstallResult
				if err := json.Unmarshal([]byte(got.out), &res); err != nil {
					t.Fatalf("not JSON: %v\n%s", err, got.out)
				}
				if !reflect.DeepEqual(res, *tt.json) {
					t.Errorf("got  %+v\nwant %+v", res, *tt.json)
				}
			} else if got.out != tt.out {
				t.Errorf("stdout %q, want %q", got.out, tt.out)
			}
			if got.err != tt.err {
				t.Errorf("stderr %q, want %q", got.err, tt.err)
			}
			if strings.Join(got.ran, "|") != strings.Join(tt.ran, "|") {
				t.Errorf("ran %v, want %v", got.ran, tt.ran)
			}
			if len(got.log) != tt.log {
				t.Errorf("history has %d entries, want %d", len(got.log), tt.log)
			}
			if tt.log > 0 && got.log[0].Kind != history.Change {
				t.Errorf("history entry is %q, not a change", got.log[0].Kind)
			}
		})
	}
}
