package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

type fake struct {
	name     string
	pkgs     []provider.Package
	versions []provider.Release
}

func (f fake) Name() string                                     { return f.name }
func (f fake) Available() bool                                  { return true }
func (f fake) List(context.Context) ([]provider.Package, error) { return f.pkgs, nil }
func (f fake) Latest(_ context.Context, p []provider.Package) ([]provider.Package, error) {
	return p, nil
}
func (f fake) Deps(context.Context, provider.Package) ([]provider.Dep, error) { return nil, nil }
func (f fake) Versions(context.Context, provider.Package) ([]provider.Release, error) {
	return f.versions, nil
}

var clock = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

var redos = vuln.Advisory{ID: "GHSA-test", Summary: "Bramble vulnerable to ReDoS", Severity: "MODERATE", Package: "bramble",
	Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "24.3.0"}}}

var netBug = vuln.Advisory{ID: "GO-test", Summary: "net: a parsing bug", Package: "example.org/net", Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "0.60.0"}}}

type run struct {
	out, err string
	code     int
	ran      []string
	scanned  int
	log      []history.Entry
}

func kho(t *testing.T, hits map[string][]string, audits map[string]vuln.SkillAudit, db *vuln.DB, args ...string) run {
	t.Helper()
	var out, errOut bytes.Buffer
	var r run
	if db == nil {
		db = vuln.NewDB()
	}
	env := Env{
		Version: "v9.9.9",
		Providers: []provider.Provider{
			fake{name: "pipx", pkgs: []provider.Package{
				{Source: "pipx", Name: "bramble", Version: "22.12.0", Latest: "26.10.1", Outdated: true},
				{Source: "pipx", Name: "inkwell", Version: "9.0.2", Latest: "9.0.2", Pinned: true},
			}, versions: []provider.Release{{Version: "26.10.1"}, {Version: "24.3.0"}, {Version: "22.12.0"}}},
			fake{name: "go", pkgs: []provider.Package{
				{Source: "go", Name: "tidyup", Version: "v1.0.0", Latest: "v1.0.0", Origin: "example.com/tidyup", Entry: "example.com/tidyup",
					Deps: []provider.Dep{{Name: "example.org/net", Version: "v0.50.0"}}},
			}},
			fake{name: "brew", pkgs: []provider.Package{{Source: "brew", Name: "anvil", Version: "0.2.89", Latest: "0.2.94", Outdated: true}}},
			fake{name: "skills", pkgs: []provider.Package{{Source: "skills", Name: "pathmaker", Version: "32b0ce9", Repo: "someone/skills"}}},
		},
		DB:  db,
		Log: history.Open(""),
		Out: &out, Err: &errOut,
		Now: func() time.Time { return clock },
		Scan: func(_ context.Context, qs []vuln.Query, _ map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
			r.scanned += len(qs)
			got := map[string][]string{}
			for _, q := range qs {
				got[q.Key()] = hits[q.Name]
			}
			return got, map[string]vuln.Advisory{redos.ID: redos, netBug.ID: netBug}, nil
		},
		Audits: func(context.Context, map[string][]string) (map[string]vuln.SkillAudit, error) { return audits, nil },
		Run: func(cmd *exec.Cmd) (string, error) {
			r.ran = append(r.ran, strings.Join(cmd.Args, " "))
			return "installed", nil
		},
	}
	r.code = Main(env, args)
	r.out, r.err, r.log = out.String(), errOut.String(), env.Log.Entries()
	return r
}

func TestCheck(t *testing.T) {
	vulnerable := map[string][]string{"bramble": {"GHSA-test"}}
	risky := map[string]vuln.SkillAudit{"someone/skills/pathmaker": {Gen: "safe", Socket: "critical", Snyk: "low"}}
	tests := []struct {
		id     string
		hits   map[string][]string
		audits map[string]vuln.SkillAudit
		code   int
		check  func(Report) bool
	}{
		{"nothing known is safe", nil, nil, ExitOK, func(r Report) bool {
			return r.Safe && r.Summary.Packages == 5 && r.Summary.Outdated == 2 && len(r.Vulnerable) == 0
		}},
		{"a vulnerable package is at risk, with the fix", vulnerable, nil, ExitAtRisk, func(r Report) bool {
			f := r.Vulnerable[0]
			return !r.Safe && f.Name == "bramble" && f.FixedIn == "24.3.0" && *f.LatestIsClear &&
				f.Fix == "kho install pipx/bramble@26.10.1 --yes" && f.Advisories[0].URL == "https://osv.dev/vulnerability/GHSA-test"
		}},
		{"a failed skill audit is at risk", nil, risky, ExitAtRisk, func(r Report) bool {
			return !r.Safe && r.RiskySkills[0].Report == "https://www.skills.sh/someone/skills/pathmaker"
		}},
		{"a vulnerable dependency is listed but stays safe", map[string][]string{"example.org/net": {"GO-test"}}, nil, ExitOK, func(r Report) bool {
			return r.Safe && r.Summary.WithVulnerableDeps == 1 && r.VulnerableDeps[0].Dependency == "example.org/net@v0.50.0" && r.VulnerableDeps[0].FixedIn == "0.60.0"
		}},
		{"brew is reported as not covered", nil, nil, ExitOK, func(r Report) bool {
			return len(r.NotCovered) == 1 && r.NotCovered[0] == "brew"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := kho(t, tt.hits, tt.audits, nil, "check", "--json")
			var r Report
			if err := json.Unmarshal([]byte(got.out), &r); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, got.out)
			}
			if got.code != tt.code || !tt.check(r) {
				t.Errorf("exit %d, report %+v", got.code, r)
			}
		})
	}
}

func TestCheckReportsWhatItDidNotCheck(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{
		Version: "v9.9.9",
		Providers: []provider.Provider{
			fake{name: "pipx", pkgs: []provider.Package{{Source: "pipx", Name: "bramble", Version: "22.12.0", Latest: "22.12.0"}}},
		},
		DB:      vuln.NewDB(),
		Log:     history.Open(""),
		Out:     &out,
		Err:     &errOut,
		Now:     func() time.Time { return clock },
		Skipped: map[string]string{"go": "no Go binary directory", "uv": "uv not on PATH"},
		Scan: func(context.Context, []vuln.Query, map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
			return map[string][]string{}, map[string]vuln.Advisory{}, nil
		},
		Audits: func(context.Context, map[string][]string) (map[string]vuln.SkillAudit, error) { return nil, nil },
	}
	if code := Main(env, []string{"check", "--json"}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	var r Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if got := r.Skipped; len(got) != 2 || got["uv"] != "uv not on PATH" {
		t.Errorf("JSON skipped %v, want both managers named", got)
	}
	if r.Complete {
		t.Error("a scan that skipped two managers must not call itself complete")
	}

	out.Reset()
	Main(env, []string{"check"})
	text := out.String()
	if !strings.Contains(text, "2 managers left out: go (no Go binary directory), uv (uv not on PATH)") {
		t.Errorf("plain report hides what was left out:\n%s", text)
	}
	if !strings.Contains(text, "safe for what was read: part of the machine could not be checked") {
		t.Errorf("plain verdict claims more than it read:\n%s", text)
	}

	// A source that failed leaves a hole just as wide as a skipped manager.
	env.Skipped = nil
	env.Scan = func(context.Context, []vuln.Query, map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
		return nil, nil, errors.New("osv is down")
	}
	out.Reset()
	Main(env, []string{"check", "--json"})
	var partial Report
	if err := json.Unmarshal(out.Bytes(), &partial); err != nil {
		t.Fatal(err)
	}
	if partial.Safe && partial.Complete {
		t.Error("a scan whose security lookup failed must not call itself complete")
	}

	env.Scan = func(context.Context, []vuln.Query, map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
		return map[string][]string{}, map[string]vuln.Advisory{}, nil
	}
	out.Reset()
	Main(env, []string{"check", "--json"})
	var full Report
	if err := json.Unmarshal(out.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if !full.Complete {
		t.Error("a scan that skipped nothing and failed at nothing must call itself complete")
	}
}

func TestCheckUsesTheCache(t *testing.T) {
	db := vuln.NewDB()
	first := kho(t, nil, nil, db, "check", "--json")
	second := kho(t, nil, nil, db, "check", "--json")
	refreshed := kho(t, nil, nil, db, "check", "--json", "--refresh")
	if first.scanned == 0 || second.scanned != 0 || refreshed.scanned != first.scanned {
		t.Errorf("scanned %d, then %d from a fresh cache, then %d on --refresh", first.scanned, second.scanned, refreshed.scanned)
	}
}

func TestCommands(t *testing.T) {
	tests := []struct {
		id   string
		args []string
		code int
		out  string
		err  string
		ran  []string
	}{
		{id: "show lists the advisories", args: []string{"show", "pipx/bramble"}, code: ExitOK, out: "GHSA-test  Bramble vulnerable to ReDoS (fixed in 24.3.0)"},
		{id: "show needs an installed package", args: []string{"show", "pipx/nope"}, code: ExitError, err: "pipx/nope is not installed"},
		{id: "install without --yes only says", args: []string{"install", "pipx/bramble@24.3.0"}, code: ExitOK, out: "would run: pipx install --force bramble==24.3.0"},
		{id: "install --yes runs it", args: []string{"install", "pipx/bramble@latest", "--yes"}, code: ExitOK, ran: []string{"pipx install --force bramble==26.10.1"}},
		{id: "a version the registry lacks is refused", args: []string{"install", "pipx/bramble@99.0.0", "--yes"}, code: ExitError, err: `bramble has no published version "99.0.0"`},
		{id: "a pinned package is refused", args: []string{"install", "pipx/inkwell@9.0.2", "--yes"}, code: ExitError, err: "inkwell is pinned"},
		{id: "brew only goes to the newest", args: []string{"install", "brew/anvil@0.2.1", "--yes"}, code: ExitError, err: "Homebrew can only install the newest version"},
		{id: "install needs a version", args: []string{"install", "pipx/bramble"}, code: ExitUsage, err: "say which version"},
		{id: "version", args: []string{"version"}, code: ExitOK, out: "v9.9.9"},
		{id: "an unknown command shows usage", args: []string{"frobnicate"}, code: ExitUsage, err: "usage:"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := kho(t, map[string][]string{"bramble": {"GHSA-test"}}, nil, nil, tt.args...)
			if got.code != tt.code || !strings.Contains(got.out, tt.out) || !strings.Contains(got.err, tt.err) || strings.Join(got.ran, "|") != strings.Join(tt.ran, "|") {
				t.Errorf("exit %d ran %v\nstdout %q\nstderr %q", got.code, got.ran, got.out, got.err)
			}
		})
	}
}

func TestInstallIsRecorded(t *testing.T) {
	got := kho(t, nil, nil, nil, "install", "pipx/bramble@24.3.0", "--yes", "--json")
	var res InstallResult
	json.Unmarshal([]byte(got.out), &res)
	if !res.Ran || res.From != "22.12.0" || res.To != "24.3.0" {
		t.Errorf("result %+v", res)
	}
	if len(got.log) != 1 || got.log[0].Kind != history.Change || got.log[0].Output != "installed" {
		t.Errorf("history %+v", got.log)
	}
}
