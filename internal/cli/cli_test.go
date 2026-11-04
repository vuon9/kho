package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

type fake struct {
	name               string
	pkgs               []provider.Package
	versions           []provider.Release
	listErr, latestErr error
}

func (f fake) Name() string                                     { return f.name }
func (f fake) Missing() string                                  { return "" }
func (f fake) List(context.Context) ([]provider.Package, error) { return f.pkgs, f.listErr }
func (f fake) Latest(_ context.Context, p []provider.Package) ([]provider.Package, error) {
	return p, f.latestErr
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

func TestRequireCompleteFailsOnAPartialScan(t *testing.T) {
	uvMissing := map[string]string{"uv": "uv not on PATH"}
	vulnerable := map[string][]string{"bramble": {"GHSA-test"}}
	npm := fake{name: "npm", pkgs: []provider.Package{{Source: "npm", Name: "diffkit", Version: "0.23.0", Latest: "0.23.0"}}}
	listFails, latestFails := npm, npm
	listFails.listErr = errors.New("npm ls: boom")
	latestFails.latestErr = errors.New("registry is down")
	type result struct {
		code   int
		stderr string
		errors map[string]string
	}
	tests := []struct {
		id      string
		npm     fake
		skipped map[string]string
		hits    map[string][]string
		args    []string
		want    result
	}{
		{"at risk wins over a partial scan, and stderr still says what was skipped", npm, uvMissing, vulnerable, []string{"--require-complete"},
			result{ExitAtRisk, "scan was not complete: uv (uv not on PATH)", nil}},
		{"a required source whose list failed fails, and says why", listFails, nil, nil, []string{"--require", "npm"},
			result{ExitIncomplete, "scan was not complete for npm failed: npm ls: boom", map[string]string{"npm": "npm ls: boom"}}},
		{"a required source whose latest versions failed was still read", latestFails, nil, nil, []string{"--require", "npm"},
			result{ExitOK, "", map[string]string{"npm latest": "registry is down"}}},
		{"a failed latest lookup still leaves the scan incomplete", latestFails, nil, nil, []string{"--require-complete"},
			result{ExitIncomplete, "scan was not complete: npm latest failed: registry is down", map[string]string{"npm latest": "registry is down"}}},
		{"a partial scan still passes without the flag", npm, uvMissing, nil, nil, result{ExitOK, "", nil}},
		{"a partial scan fails with the flag, and says why", npm, uvMissing, nil, []string{"--require-complete"},
			result{ExitIncomplete, "scan was not complete: uv (uv not on PATH)", nil}},
		{"a required source that was skipped fails", npm, uvMissing, nil, []string{"--require", "uv"},
			result{ExitIncomplete, "scan was not complete for uv (uv not on PATH)", nil}},
		{"a required source that was read passes", npm, uvMissing, nil, []string{"--require", "pipx"}, result{ExitOK, "", nil}},
		{"a manager this machine lacks is fine unless required", npm, uvMissing, nil, []string{"--require", "pipx,uv"},
			result{ExitIncomplete, "scan was not complete for uv (uv not on PATH)", nil}},
		{"cask is read by brew, so requiring it requires brew", npm, map[string]string{"brew": "brew not on PATH"}, nil, []string{"--require", "cask"},
			result{ExitIncomplete, "scan was not complete for brew (brew not on PATH)", nil}},
		{"a full scan passes with the flag", npm, nil, nil, []string{"--require-complete"}, result{ExitOK, "", nil}},
		{"an unknown source in the list is a usage error", npm, uvMissing, nil, []string{"--require", "npmm"},
			result{ExitUsage, "unknown source in --require: npmm", nil}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			var out, errOut bytes.Buffer
			env := Env{
				Version: "v9.9.9",
				Providers: []provider.Provider{
					fake{name: "pipx", pkgs: []provider.Package{{Source: "pipx", Name: "bramble", Version: "22.12.0", Latest: "22.12.0"}}},
					tt.npm,
				},
				DB:      vuln.NewDB(),
				Log:     history.Open(""),
				Out:     &out,
				Err:     &errOut,
				Now:     func() time.Time { return clock },
				Skipped: tt.skipped,
				Scan: func(_ context.Context, qs []vuln.Query, _ map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
					got := map[string][]string{}
					for _, q := range qs {
						got[q.Key()] = tt.hits[q.Name]
					}
					return got, map[string]vuln.Advisory{redos.ID: redos}, nil
				},
				Audits: func(context.Context, map[string][]string) (map[string]vuln.SkillAudit, error) { return nil, nil },
			}
			got := result{code: Main(env, append([]string{"check", "--json"}, tt.args...)), stderr: strings.TrimSpace(errOut.String())}
			if out.Len() > 0 {
				var r Report
				if err := json.Unmarshal(out.Bytes(), &r); err != nil {
					t.Fatalf("not JSON: %v\n%s", err, out.String())
				}
				got.errors = r.Errors
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
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

func TestCheckSkillAudits(t *testing.T) {
	const key = "someone/skills/pathmaker"
	high := map[string]vuln.SkillAudit{key: {Gen: "safe", Socket: "high", Snyk: "low"}}
	low := map[string]vuln.SkillAudit{key: {Gen: "safe", Socket: "low", Snyk: "low"}}
	down := errors.New("skills.sh: down")
	type answer struct {
		audits map[string]vuln.SkillAudit
		err    error
	}
	type result struct {
		code      int
		stderr    string
		asks      int
		risky     []string
		errors    map[string]string
		complete  bool
		audits    map[string]vuln.SkillAudit
		auditedAt map[string]time.Time
	}
	tests := []struct {
		id      string
		answers []answer
		runs    int
		flags   []string
		want    result
	}{
		{"an audit that came back with an error still puts the scan at risk", []answer{{high, down}}, 1, nil,
			result{ExitAtRisk, "", 1, []string{"pathmaker"}, map[string]string{"security": "skills.sh: down"}, false, high, map[string]time.Time{}}},
		{"at risk wins over incomplete, and stderr still says what failed", []answer{{high, down}}, 1, []string{"--require-complete"},
			result{ExitAtRisk, "scan was not complete: security failed: skills.sh: down", 1, []string{"pathmaker"}, map[string]string{"security": "skills.sh: down"}, false, high, map[string]time.Time{}}},
		{"a failed ask is incomplete", []answer{{nil, down}}, 1, []string{"--require-complete"},
			result{ExitIncomplete, "scan was not complete: security failed: skills.sh: down", 1, nil, map[string]string{"security": "skills.sh: down"}, false, map[string]vuln.SkillAudit{}, map[string]time.Time{}}},
		{"a failed ask is asked again on the next scan", []answer{{nil, down}, {low, nil}}, 2, nil,
			result{ExitOK, "", 2, nil, nil, true, low, map[string]time.Time{key: clock}}},
		{"a scan with telemetry off leaves the skill due, so the next scan asks", []answer{{nil, nil}, {high, nil}}, 2, []string{"--require-complete"},
			result{ExitAtRisk, "", 2, []string{"pathmaker"}, nil, true, high, map[string]time.Time{key: clock}}},
		{"an answer without an audit is not asked again", []answer{{map[string]vuln.SkillAudit{}, nil}}, 3, nil,
			result{ExitOK, "", 1, nil, nil, true, map[string]vuln.SkillAudit{}, map[string]time.Time{key: clock}}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			var out, errOut bytes.Buffer
			db := vuln.NewDB()
			got := result{audits: db.Audits, auditedAt: db.AuditedAt}
			env := Env{
				Version: "v9.9.9",
				Providers: []provider.Provider{
					fake{name: "skills", pkgs: []provider.Package{{Source: "skills", Name: "pathmaker", Version: "32b0ce9", Repo: "someone/skills"}}},
				},
				DB:  db,
				Log: history.Open(""),
				Out: &out, Err: &errOut,
				Now: func() time.Time { return clock },
				Scan: func(context.Context, []vuln.Query, map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
					return map[string][]string{}, map[string]vuln.Advisory{}, nil
				},
				Audits: func(context.Context, map[string][]string) (map[string]vuln.SkillAudit, error) {
					a := tt.answers[min(got.asks, len(tt.answers)-1)]
					got.asks++
					return a.audits, a.err
				},
			}
			for range tt.runs {
				out.Reset()
				errOut.Reset()
				got.code = Main(env, append([]string{"check", "--json"}, tt.flags...))
			}
			var r Report
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, out.String())
			}
			got.stderr, got.errors, got.complete = strings.TrimSpace(errOut.String()), r.Errors, r.Complete
			for _, s := range r.RiskySkills {
				got.risky = append(got.risky, s.Name)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
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

// Usage, SKILL.md and AGENTS.md are kept in step with the code by hand, so
// this reads the commands and exit codes from cli.go, asks each command for
// its flags, and looks for every one of them in the docs.
func TestDocsKeepUpWithTheCLI(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "cli.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var commands []string
	var codes []int
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			for i, name := range n.Names {
				if strings.HasPrefix(name.Name, "Exit") {
					code, _ := strconv.Atoi(n.Values[i].(*ast.BasicLit).Value)
					codes = append(codes, code)
				}
			}
		case *ast.FuncDecl:
			return n.Name.Name == "Main"
		case *ast.CaseClause:
			for _, e := range n.List {
				if cmd, _ := strconv.Unquote(e.(*ast.BasicLit).Value); !strings.HasPrefix(cmd, "-") {
					commands = append(commands, cmd)
				}
			}
		}
		return true
	})

	var tokens, flags []string
	for _, cmd := range commands {
		tokens = append(tokens, "kho "+cmd)
		var out, errOut bytes.Buffer
		Main(Env{DB: vuln.NewDB(), Log: history.Open(""), Out: &out, Err: &errOut, Now: func() time.Time { return clock }}, []string{cmd, "-h"})
		for _, m := range regexp.MustCompile(`(?m)^  -(\S+)`).FindAllStringSubmatch(errOut.String(), -1) {
			if len(m[1]) == 1 {
				flags = append(flags, "-"+m[1])
			} else {
				flags = append(flags, "--"+m[1])
			}
		}
	}
	if len(flags) == 0 {
		t.Fatalf("found no flags in %v", commands)
	}
	tokens = append(tokens, flags...)

	_, exits, _ := strings.Cut(Usage, "exit codes: ")
	exits, _, _ = strings.Cut(exits, "\n")
	var listed []int
	for _, item := range strings.Split(exits, ", ") {
		code, _ := strconv.Atoi(strings.Fields(item)[0])
		listed = append(listed, code)
	}
	if !reflect.DeepEqual(listed, codes) {
		t.Errorf("Usage lists exit codes %v, cli.go has %v", listed, codes)
	}

	skill, err := os.ReadFile("../../skills/use-kho/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	agents, err := os.ReadFile("../../AGENTS.md")
	if err != nil {
		t.Fatal(err)
	}
	// Every doc carries the exit code line, and it names --require and
	// --require-complete, so it is taken out before looking for the rest. A
	// token must stand alone, or --require would be found in --require-complete.
	tests := []struct {
		id     string
		doc    string
		tokens []string
	}{
		{"skills/use-kho/SKILL.md", string(skill), tokens},
		{"Usage", Usage, tokens},
		{"AGENTS.md", string(agents), nil},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			var missing []string
			if !strings.Contains(tt.doc, exits) {
				missing = append(missing, exits)
			}
			rest := strings.ReplaceAll(tt.doc, exits, "")
			for _, w := range tt.tokens {
				if !regexp.MustCompile(`(^|[^\w-])` + regexp.QuoteMeta(w) + `($|[^\w-])`).MatchString(rest) {
					missing = append(missing, w)
				}
			}
			if len(missing) > 0 {
				t.Errorf("%s does not mention %q", tt.id, missing)
			}
		})
	}
}
