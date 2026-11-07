package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

// removeFakes is the machine every remove row starts from: one package per
// source, a project package, Go binaries with and without a path, a Homebrew
// formula that another formula needs, and the packages kho refuses to remove.
func removeFakes() []provider.Provider {
	return []provider.Provider{
		fake{name: "pipx", pkgs: []provider.Package{{Source: "pipx", Name: "bramble", Version: "22.12.0"}}},
		fake{name: "brew", pkgs: []provider.Package{
			{Source: "brew", Name: "anvil", Version: "0.11.2", Deps: []provider.Dep{{Name: "mist", Version: "3.1.0", Direct: true}}},
			{Source: "brew", Name: "mist", Version: "3.1.0", Dependency: true},
			{Source: "brew", Name: "node", Version: "26.13.0"},
			{Source: "cask", Name: "focusbar", Version: "4.2.0"},
		}},
		fake{name: "npm", pkgs: []provider.Package{
			{Source: "npm", Name: "@scope/tool", Version: "1.5.0"},
			{Source: "npm", Name: "evil name; rm -rf /", Version: "1.0.0"},
			{Source: "npm", Name: "left-trim", Version: "1.3.0", Lockfile: "package-lock.json"},
		}},
		fake{name: "composer", pkgs: []provider.Package{
			{Source: "composer", Name: "acme/legacy", Version: "1.2.0", Dependency: true},
		}},
		fake{name: "go", pkgs: []provider.Package{
			{Source: "go", Name: "nopath", Version: "v1.0.0"},
			{Source: "go", Name: "tidyup", Version: "v1.0.0", Path: "/home/dev/go/bin/tidyup"},
		}},
		fake{name: "mise", pkgs: []provider.Package{
			{Source: "mise", Name: "node", Version: "22.1.0", Versions: []string{"22.1.0", "24.2.0"}},
		}},
		fake{name: "skills", pkgs: []provider.Package{{Source: "skills", Name: "pathmaker", Version: "32b0ce9"}}},
	}
}

// runRemove runs one remove command against fakes and records what reached
// exec. A nil providers means removeFakes, and a nil runErr means the package
// manager succeeds.
func runRemove(t *testing.T, providers []provider.Provider, skipped map[string]string, runErr error, args ...string) run {
	t.Helper()
	var out, errOut bytes.Buffer
	var r run
	if providers == nil {
		providers = removeFakes()
	}
	env := Env{
		Version:   "v9.9.9",
		Providers: providers,
		DB:        vuln.NewDB(),
		Log:       history.Open(""),
		Out:       &out, Err: &errOut,
		Now:     func() time.Time { return clock },
		Skipped: skipped,
		Run: func(cmd *exec.Cmd) (string, error) {
			r.ran = append(r.ran, strings.Join(cmd.Args, " "))
			return "uninstalled", runErr
		},
	}
	r.code = Main(env, args)
	r.out, r.err, r.log = out.String(), errOut.String(), env.Log.Entries()
	return r
}

func TestRemove(t *testing.T) {
	npmDown := []provider.Provider{fake{name: "npm", listErr: errors.New("gateway timeout")}}
	miseNotes := "note: kho can't remove it from mise.toml, so mise may install it again\nnote: node also has 24.2.0 installed; kho removes only 22.1.0"
	tests := []struct {
		id        string
		args      []string
		providers []provider.Provider
		skipped   map[string]string
		runErr    error
		code      int
		out, err  string
		ran       []string
		log       int
	}{
		{id: "no ref is a usage error", args: []string{"remove"}, code: ExitUsage, err: "usage: kho remove <source>/<name> [--yes] [--force] [--json]"},
		{id: "two refs are a usage error", args: []string{"remove", "pipx/bramble", "brew/anvil"}, code: ExitUsage, err: "usage: kho remove <source>/<name> [--yes] [--force] [--json]"},
		{id: "without --yes it only says what it would run", args: []string{"remove", "pipx/bramble"}, code: ExitOK, out: "would run: pipx uninstall bramble\nadd --yes to run it"},
		{id: "--yes uninstalls it and records the change", args: []string{"remove", "pipx/bramble", "--yes"}, code: ExitOK, out: "removed pipx/bramble 22.12.0", ran: []string{"pipx uninstall bramble"}, log: 1},
		{id: "a package that is not installed is an error", args: []string{"remove", "pipx/nope"}, code: ExitError, err: "pipx/nope is not installed"},
		{id: "a ref without a source says what one looks like", args: []string{"remove", "bramble"}, code: ExitUsage, err: `"bramble" is not source/name, like pipx/ruff`},
		{id: "a version in the ref is a usage error", args: []string{"remove", "pipx/bramble@24.3.0"}, code: ExitUsage, err: "remove takes the installed version, so leave @version off: kho remove pipx/bramble"},
		{id: "a scoped name keeps its @ when the version is named", args: []string{"remove", "npm/@scope/tool@1.2.3"}, code: ExitUsage, err: "remove takes the installed version, so leave @version off: kho remove npm/@scope/tool"},
		{id: "a project package is never changed", args: []string{"remove", "npm/left-trim", "--yes"}, code: ExitError, err: "left-trim comes from package-lock.json, and kho doesn't change project lockfiles"},
		{id: "a Go binary names the file to delete", args: []string{"remove", "go/tidyup", "--yes"}, code: ExitError, err: "go has no uninstall; tidyup is /home/dev/go/bin/tidyup, so remove that file yourself and it stops being listed"},
		{id: "a Go binary with no known path still refuses", args: []string{"remove", "go/nopath", "--yes"}, code: ExitError, err: "go has no uninstall; remove the nopath binary yourself and it stops being listed"},
		{id: "a skill points at the skills CLI", args: []string{"remove", "skills/pathmaker", "--yes"}, code: ExitError, err: "kho doesn't remove skills; run npx skills remove pathmaker, or unlink it from each agent in the TUI"},
		{id: "--force on brew ignores the dependency check", args: []string{"remove", "brew/anvil", "--force", "--yes"}, code: ExitOK, out: "removed brew/anvil 0.11.2", ran: []string{"brew uninstall --ignore-dependencies anvil"}, log: 1},
		{id: "--force is not --cask's", args: []string{"remove", "cask/focusbar", "--force"}, code: ExitUsage, err: "--force is for Homebrew formulae; cask has no dependency check to override"},
		{id: "--force only exists for Homebrew formulae", args: []string{"remove", "npm/@scope/tool", "--force"}, code: ExitUsage, err: "--force is for Homebrew formulae; npm has no dependency check to override"},
		{id: "--force on a package that is not installed is still a usage error", args: []string{"remove", "npm/nope", "--force"}, code: ExitUsage, err: "--force is for Homebrew formulae; npm has no dependency check to override"},
		{id: "a cask uninstalls through brew --cask", args: []string{"remove", "cask/focusbar", "--yes"}, code: ExitOK, out: "removed cask/focusbar 4.2.0", ran: []string{"brew uninstall --cask focusbar"}, log: 1},
		{id: "a manager that refuses is an error", args: []string{"remove", "brew/anvil", "--yes"}, runErr: errors.New("exit status 1: anvil is needed by mist"), code: ExitError, err: "exit status 1: anvil is needed by mist", ran: []string{"brew uninstall anvil"}, log: 1},
		{id: "an unreadable source is not an uninstalled package", args: []string{"remove", "npm/@scope/tool"}, providers: npmDown, code: ExitError, err: "npm could not be read: gateway timeout"},
		{id: "a source this machine lacks says so", args: []string{"remove", "npm/@scope/tool"}, providers: []provider.Provider{fake{name: "pipx"}}, skipped: map[string]string{"npm": "npm was not found"}, code: ExitError, err: "npm is not on this machine (npm was not found)"},
		{id: "mise names the version and the ones left", args: []string{"remove", "mise/node", "--yes"}, code: ExitOK, out: "removed mise/node 22.1.0", err: miseNotes, ran: []string{"mise uninstall node@22.1.0"}, log: 1},
		{id: "mise notes both ways in a dry run too", args: []string{"remove", "mise/node"}, code: ExitOK, out: "would run: mise uninstall node@22.1.0\nadd --yes to run it", err: miseNotes},
		{id: "a name with a space is quoted in the dry run", args: []string{"remove", "npm/evil name; rm -rf /"}, code: ExitOK, out: "would run: npm uninstall -g 'evil name; rm -rf /'\nadd --yes to run it"},
		{id: "a versioned Homebrew name is not a version in the ref", args: []string{"remove", "brew/node@22"}, code: ExitError, err: "brew/node@22 is not installed"},
		{id: "a composer dependency gets a note without promising --force", args: []string{"remove", "composer/acme/legacy"}, code: ExitOK, out: "would run: composer global remove acme/legacy\nadd --yes to run it", err: "note: acme/legacy is installed as another package's dependency"},
		{id: "-h prints the usage line", args: []string{"remove", "-h"}, code: ExitUsage, err: "usage: kho remove <source>/<name> [--yes] [--force] [--json]"},
		{id: "a --json after -- is a positional argument", args: []string{"remove", "--", "--json"}, code: ExitUsage, err: `"--json" is not source/name, like pipx/ruff`},
		{id: "a dependency warns that the manager may refuse", args: []string{"remove", "brew/mist"}, code: ExitOK, out: "would run: brew uninstall mist\nadd --yes to run it", err: "note: mist is installed as another package's dependency; the manager may refuse, and --force goes ahead anyway"},
		{id: "a dependency with --force says what breaks", args: []string{"remove", "brew/mist", "--force"}, code: ExitOK, out: "would run: brew uninstall --ignore-dependencies mist\nadd --yes to run it", err: "note: mist is installed as another package's dependency; removing it leaves that package broken until it is installed again"},
		{id: "a source kho does not know is a usage error", args: []string{"remove", "frob/widget"}, code: ExitUsage, err: `"frob" is not a source kho knows; try brew, cask, npm, composer, pipx, uv, mise, go or skills`},
		{id: "a name installed under another manager is named", args: []string{"remove", "brew/focusbar"}, code: ExitUsage, err: "focusbar is installed as cask/focusbar, not brew/focusbar"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := runRemove(t, tt.providers, tt.skipped, tt.runErr, tt.args...)
			if got.code != tt.code || strings.TrimSpace(got.out) != tt.out || strings.TrimSpace(got.err) != tt.err ||
				strings.Join(got.ran, "|") != strings.Join(tt.ran, "|") || len(got.log) != tt.log {
				t.Errorf("exit %d, want %d\nstdout %q, want %q\nstderr %q, want %q\nran %v, want %v\nhistory %d entries, want %d",
					got.code, tt.code, got.out, tt.out, got.err, tt.err, got.ran, tt.ran, len(got.log), tt.log)
			}
		})
	}
}

// A name is never split by a shell, so the argv the provider built is exactly
// what exec sees, one element per argument.
func TestRemoveKeepsTheNameWhole(t *testing.T) {
	var argv []string
	var out, errOut bytes.Buffer
	env := Env{
		Providers: []provider.Provider{fake{name: "npm", pkgs: []provider.Package{{Source: "npm", Name: "evil name; rm -rf /", Version: "1.0.0"}}}},
		Log:       history.Open(""),
		Out:       &out, Err: &errOut,
		Now: func() time.Time { return clock },
		Run: func(cmd *exec.Cmd) (string, error) {
			argv = cmd.Args
			return "uninstalled", nil
		},
	}
	if code := Main(env, []string{"remove", "npm/evil name; rm -rf /", "--yes"}); code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	want := []string{"npm", "uninstall", "-g", "evil name; rm -rf /"}
	if !slices.Equal(argv, want) {
		t.Errorf("argv %q, want %q", argv, want)
	}
}

func TestRemoveJSON(t *testing.T) {
	tests := []struct {
		id     string
		args   []string
		runErr error
		code   int
		want   RemoveResult
	}{
		{"a dry run still reports the command", []string{"remove", "pipx/bramble", "--json"}, nil, ExitOK,
			RemoveResult{Package: "pipx/bramble", Version: "22.12.0", Command: []string{"pipx", "uninstall", "bramble"}}},
		{"a run is marked ran", []string{"remove", "pipx/bramble", "--yes", "--json"}, nil, ExitOK,
			RemoveResult{Package: "pipx/bramble", Version: "22.12.0", Command: []string{"pipx", "uninstall", "bramble"}, Ran: true}},
		{"a failed run carries the error", []string{"remove", "pipx/bramble", "--yes", "--json"}, errors.New("boom"), ExitError,
			RemoveResult{Package: "pipx/bramble", Version: "22.12.0", Command: []string{"pipx", "uninstall", "bramble"}, Ran: true, Error: "boom"}},
		{"a dependency note stays off stderr under JSON", []string{"remove", "brew/mist", "--json"}, nil, ExitOK,
			RemoveResult{Package: "brew/mist", Version: "3.1.0", Command: []string{"brew", "uninstall", "mist"}}},
		{"a refusal carries the version it knows", []string{"remove", "go/tidyup", "--json"}, nil, ExitError,
			RemoveResult{Package: "go/tidyup", Version: "v1.0.0", Error: "go has no uninstall; tidyup is /home/dev/go/bin/tidyup, so remove that file yourself and it stops being listed"}},
		{"a miss answers in JSON too", []string{"remove", "pipx/nope", "--json"}, nil, ExitError,
			RemoveResult{Package: "pipx/nope", Error: "pipx/nope is not installed"}},
		{"a usage mistake answers in JSON too", []string{"remove", "frob/widget", "--json"}, nil, ExitUsage,
			RemoveResult{Package: "frob/widget", Error: `"frob" is not a source kho knows; try brew, cask, npm, composer, pipx, uv, mise, go or skills`}},
		{"bad arguments answer in JSON too", []string{"remove", "--json"}, nil, ExitUsage,
			RemoveResult{Error: "usage: kho remove <source>/<name> [--yes] [--force] [--json]"}},
		{"an unknown flag answers in JSON too", []string{"remove", "pipx/bramble", "--dry-run", "--json"}, nil, ExitUsage,
			RemoveResult{Error: "flag provided but not defined: -dry-run"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := runRemove(t, nil, nil, tt.runErr, tt.args...)
			var res RemoveResult
			if err := json.Unmarshal([]byte(got.out), &res); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, got.out)
			}
			if got.code != tt.code || !reflect.DeepEqual(res, tt.want) {
				t.Errorf("exit %d, want %d\nresult %+v, want %+v", got.code, tt.code, res, tt.want)
			}
			if strings.Contains(got.out, "would run:") {
				t.Errorf("JSON output also printed the dry run text: %q", got.out)
			}
			if got.err != "" {
				t.Errorf("JSON output came with prose on stderr: %q", got.err)
			}
		})
	}
}

func TestRemoveIsRecorded(t *testing.T) {
	got := runRemove(t, nil, nil, nil, "remove", "brew/anvil", "--yes")
	want := []history.Entry{{At: clock, Kind: history.Change, Command: []string{"brew", "uninstall", "anvil"}, Output: "uninstalled"}}
	if !reflect.DeepEqual(got.log, want) {
		t.Errorf("history %+v, want %+v", got.log, want)
	}
}

// A failed removal is still a command kho ran, so it is in the history with
// the error, and a dry run is not.
func TestRemoveRecordsFailuresOnly(t *testing.T) {
	got := runRemove(t, nil, nil, errors.New("boom"), "remove", "pipx/bramble", "--yes")
	if len(got.log) != 1 || got.log[0].Err != "boom" || got.log[0].Kind != history.Change {
		t.Errorf("history %+v", got.log)
	}
	dry := runRemove(t, nil, nil, nil, "remove", "pipx/bramble")
	if len(dry.log) != 0 {
		t.Errorf("a dry run wrote history %+v", dry.log)
	}
}

// shrinking is a provider that stops listing a package once it is uninstalled,
// the way a real manager's List does.
type shrinking struct {
	fake
	gone map[string]bool
}

func (s *shrinking) List(context.Context) ([]provider.Package, error) {
	var left []provider.Package
	for _, p := range s.pkgs {
		if !s.gone[p.Name] {
			left = append(left, p)
		}
	}
	return left, nil
}

func TestRemoveTwiceIsIdempotent(t *testing.T) {
	var out, errOut bytes.Buffer
	var argv []string
	gone := map[string]bool{}
	env := Env{
		Providers: []provider.Provider{&shrinking{
			fake: fake{name: "pipx", pkgs: []provider.Package{{Source: "pipx", Name: "bramble", Version: "22.1.0"}}},
			gone: gone,
		}},
		Log: history.Open(""),
		Out: &out, Err: &errOut,
		Now: func() time.Time { return clock },
		Run: func(cmd *exec.Cmd) (string, error) {
			argv = append(argv, strings.Join(cmd.Args, " "))
			gone[cmd.Args[len(cmd.Args)-1]] = true
			return "uninstalled", nil
		},
	}
	if code := Main(env, []string{"remove", "pipx/bramble", "--yes"}); code != ExitOK {
		t.Fatalf("first remove: exit %d, stderr %q", code, errOut.String())
	}
	if code := Main(env, []string{"remove", "pipx/bramble", "--yes"}); code != ExitError {
		t.Fatalf("second remove: exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(errOut.String(), "pipx/bramble is not installed") {
		t.Errorf("second remove stderr %q", errOut.String())
	}
	if strings.Count(out.String(), "removed pipx/bramble 22.1.0") != 1 {
		t.Errorf("stdout %q, want exactly one removal", out.String())
	}
	if len(argv) != 1 || len(env.Log.Entries()) != 1 {
		t.Errorf("ran %v, history %+v; want one of each", argv, env.Log.Entries())
	}
}
