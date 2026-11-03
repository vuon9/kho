// Package cli is kho without the screen: commands that print JSON or plain
// text, so scripts and agents can read the same state the TUI shows.
package cli

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

// Exit codes. An agent can branch on them without parsing the output.
const (
	ExitOK     = 0
	ExitError  = 1
	ExitUsage  = 2
	ExitAtRisk = 3
)

// Env is everything the commands touch, so tests can swap the machine out.
type Env struct {
	Version   string
	Providers []provider.Provider
	DB        *vuln.DB
	DBPath    string
	Log       *history.Log
	Out, Err  io.Writer
	Now       func() time.Time
	Scan      func(context.Context, []vuln.Query, map[string]bool) (map[string][]string, map[string]vuln.Advisory, error)
	Audits    func(context.Context, map[string][]string) (map[string]vuln.SkillAudit, error)
	History   func(context.Context, string, string) ([]vuln.Advisory, error)
	// Run runs an install. It gets the command as built by the provider and
	// returns its combined output.
	Run func(*exec.Cmd) (string, error)
	// Skipped names the providers this machine is not set up for, with what
	// was looked for. main fills it from provider.Missing.
	Skipped map[string]string
}

const Usage = `kho - one place for every package manager on your machine

usage:
  kho                                  open the TUI
  kho check [--json] [--refresh]       am I safe? inventory plus known advisories
  kho show <source>/<name> [--json]    one package, with every advisory
  kho install <source>/<name>@<version> [--yes] [--json]
                                       upgrade or downgrade; without --yes it only
                                       says what it would run
  kho history [--json] [--changes] [-n N]
                                       commands kho ran, newest first
  kho list                             every package as JSON
  kho version                          print the version

exit codes: 0 ok or safe, 1 error, 2 usage, 3 at risk
`

func Main(env Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(env.Err, Usage)
		return ExitUsage
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(env.Out, env.Version)
		return ExitOK
	case "check":
		return env.check(args)
	case "show":
		return env.show(args)
	case "install":
		return env.install(args)
	case "history":
		return env.history(args)
	case "list":
		return env.list()
	case "help", "--help", "-h":
		fmt.Fprint(env.Out, Usage)
		return ExitOK
	}
	fmt.Fprint(env.Err, Usage)
	return ExitUsage
}

func (env Env) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Err)
	return fs
}

// parse accepts flags before or after the arguments, as in
// `kho install pipx/ruff@latest --yes`, which Go's flag package alone stops
// reading at the first argument.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return rest, nil
		}
		rest, args = append(rest, fs.Arg(0)), fs.Args()[1:]
	}
}

// inventory lists every provider with latest versions, in parallel.
func (env Env) inventory(ctx context.Context) ([]provider.Package, map[string]string) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var all []provider.Package
	errs := map[string]string{}
	for _, p := range env.Providers {
		wg.Go(func() {
			pkgs, err := p.List(ctx)
			if err == nil {
				pkgs, err = p.Latest(ctx, pkgs)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[p.Name()] = err.Error()
			}
			all = append(all, pkgs...)
		})
	}
	wg.Wait()
	slices.SortFunc(all, func(a, b provider.Package) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.Name, b.Name))
	})
	return all, errs
}

// secure brings the security cache up to date for pkgs: OSV for packages and
// their known dependencies, skills.sh for skills. refresh ignores the cache.
func (env Env) secure(ctx context.Context, pkgs []provider.Package, refresh bool) error {
	var queries []vuln.Query
	bySource := map[string][]string{}
	var audited []string
	for _, p := range pkgs {
		if q, ok := provider.Query(p); ok {
			queries = append(queries, q)
		}
		queries = append(queries, provider.DepQueries(p)...)
		if p.Source == "skills" && p.Repo != "" {
			k := p.Repo + "/" + p.Name
			if t, ok := env.DB.AuditedAt[k]; refresh || !ok || env.Now().Sub(t) > vuln.MaxAge {
				bySource[p.Repo] = append(bySource[p.Repo], p.Name)
				audited = append(audited, k)
			}
		}
	}
	if !refresh {
		queries = env.DB.Stale(queries, env.Now())
	}
	var errs []error
	if len(queries) > 0 {
		known := map[string]bool{}
		for id := range env.DB.Advisories {
			known[id] = true
		}
		hits, advs, err := env.Scan(ctx, queries, known)
		if err != nil {
			errs = append(errs, err)
		} else {
			env.DB.Merge(hits, advs, env.Now())
		}
	}
	if len(bySource) > 0 {
		audits, err := env.Audits(ctx, bySource)
		if err != nil {
			errs = append(errs, err)
		}
		for _, k := range audited {
			env.DB.AuditedAt[k] = env.Now()
		}
		for k, a := range audits {
			env.DB.Audits[k] = a
		}
	}
	if env.DBPath != "" {
		env.DB.Save(env.DBPath)
	}
	return errors.Join(errs...)
}

type Advisory struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Summary  string   `json:"summary"`
	FixedIn  string   `json:"fixedIn,omitempty"`
	URL      string   `json:"url"`
}

type Finding struct {
	Source        string     `json:"source"`
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	Latest        string     `json:"latest,omitempty"`
	Pinned        bool       `json:"pinned,omitempty"`
	Dependency    string     `json:"dependency,omitempty"`
	FixedIn       string     `json:"fixedIn,omitempty"`
	LatestIsClear *bool      `json:"latestIsClear,omitempty"`
	Fix           string     `json:"fix,omitempty"`
	Advisories    []Advisory `json:"advisories"`
}

type RiskySkill struct {
	Name   string `json:"name"`
	Repo   string `json:"repo"`
	Gen    string `json:"gen,omitempty"`
	Socket string `json:"socket,omitempty"`
	Snyk   string `json:"snyk,omitempty"`
	Report string `json:"report"`
}

type Outdated struct {
	Source  string `json:"source"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Latest  string `json:"latest"`
	Pinned  bool   `json:"pinned,omitempty"`
}

type Summary struct {
	Packages           int `json:"packages"`
	Vulnerable         int `json:"vulnerable"`
	WithVulnerableDeps int `json:"withVulnerableDeps"`
	RiskySkills        int `json:"riskySkills"`
	Outdated           int `json:"outdated"`
	Pinned             int `json:"pinned"`
}

// Report is what `kho check --json` prints. Safe is false when an installed
// package has a known advisory or a skill failed an audit. Advisories in
// dependencies are listed for review but don't decide Safe, since OSV
// matches them by module and the vulnerable code may never run. Safe speaks
// only for what was checked: Skipped names the managers this machine does not
// have, so a reader can see what the verdict does not cover.
type Report struct {
	Kho            string            `json:"kho"`
	CheckedAt      time.Time         `json:"checkedAt"`
	Safe           bool              `json:"safe"`
	Summary        Summary           `json:"summary"`
	Vulnerable     []Finding         `json:"vulnerable"`
	VulnerableDeps []Finding         `json:"vulnerableDeps"`
	RiskySkills    []RiskySkill      `json:"riskySkills"`
	Outdated       []Outdated        `json:"outdated"`
	NotCovered     []string          `json:"notCovered"`
	Skipped        map[string]string `json:"skipped,omitempty"`
	Complete       bool              `json:"complete"`
	Errors         map[string]string `json:"errors,omitempty"`
}

func advisories(advs []vuln.Advisory, version string) []Advisory {
	var out []Advisory
	for _, a := range advs {
		out = append(out, Advisory{ID: a.ID, Aliases: a.Aliases, Severity: a.Severity, Summary: a.Summary, FixedIn: a.FixedAfter(version), URL: a.URL()})
	}
	return out
}

// fixFor is the lowest version that fixes every advisory, or "" when one of
// them has no fix yet.
func fixFor(advs []vuln.Advisory, version string) string {
	best := ""
	for _, a := range advs {
		f := a.FixedAfter(version)
		if f == "" {
			return ""
		}
		if vuln.Compare(f, best) > 0 {
			best = f
		}
	}
	return best
}

func (env Env) finding(p provider.Package, advs []vuln.Advisory) Finding {
	f := Finding{Source: p.Source, Name: p.Name, Version: p.Version, Latest: p.Latest, Pinned: p.Pinned, Advisories: advisories(advs, p.Version)}
	f.FixedIn = fixFor(advs, p.Version)
	if p.Latest != "" {
		clear := true
		for _, a := range advs {
			if a.Affects(p.Latest) {
				clear = false
			}
		}
		f.LatestIsClear = &clear
		if clear && !p.Pinned {
			f.Fix = fmt.Sprintf("kho install %s/%s@%s --yes", p.Source, p.Name, p.Latest)
		}
	}
	return f
}

func (env Env) report(pkgs []provider.Package, errs map[string]string) Report {
	r := Report{Kho: env.Version, CheckedAt: env.Now(), Errors: errs, Skipped: env.Skipped,
		Vulnerable: []Finding{}, VulnerableDeps: []Finding{}, RiskySkills: []RiskySkill{}, Outdated: []Outdated{}, NotCovered: []string{}}
	covered := map[string]bool{}
	for _, p := range pkgs {
		r.Summary.Packages++
		if p.Pinned {
			r.Summary.Pinned++
		}
		if p.Outdated {
			r.Summary.Outdated++
			r.Outdated = append(r.Outdated, Outdated{p.Source, p.Name, p.Version, p.Latest, p.Pinned})
		}
		if q, ok := provider.Query(p); ok {
			covered[p.Source] = true
			if advs := env.DB.For(q); len(advs) > 0 {
				r.Vulnerable = append(r.Vulnerable, env.finding(p, advs))
			}
		} else if p.Source != "skills" && !slices.Contains(r.NotCovered, p.Source) {
			r.NotCovered = append(r.NotCovered, p.Source)
		}
		depHit := false
		for _, d := range p.Deps {
			q := vuln.Query{Ecosystem: provider.Ecosystem(p), Name: d.Name, Version: d.Version}
			if advs := env.DB.For(q); len(advs) > 0 {
				f := Finding{Source: p.Source, Name: p.Name, Version: p.Version, Dependency: d.Name + "@" + d.Version,
					FixedIn: fixFor(advs, d.Version), Advisories: advisories(advs, d.Version)}
				r.VulnerableDeps = append(r.VulnerableDeps, f)
				depHit = true
			}
		}
		if depHit {
			r.Summary.WithVulnerableDeps++
		}
		if a, ok := env.DB.Audits[p.Repo+"/"+p.Name]; ok && p.Source == "skills" && vuln.Verdict(a.Worst()) == "Fail" {
			r.RiskySkills = append(r.RiskySkills, RiskySkill{p.Name, p.Repo, a.Gen, a.Socket, a.Snyk, vuln.SkillPage(p.Repo, p.Name)})
		}
	}
	r.NotCovered = slices.DeleteFunc(r.NotCovered, func(s string) bool { return covered[s] })
	r.Summary.Vulnerable, r.Summary.RiskySkills = len(r.Vulnerable), len(r.RiskySkills)
	r.Safe = len(r.Vulnerable) == 0 && len(r.RiskySkills) == 0
	// Complete is false when a manager was skipped, so a script can tell a full
	// scan from one that only read part of the machine.
	r.Complete = len(r.Skipped) == 0
	return r
}

func (env Env) printJSON(v any) {
	enc := json.NewEncoder(env.Out)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func (env Env) check(args []string) int {
	fs := env.flags("check")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	refresh := fs.Bool("refresh", false, "ask OSV and skills.sh again, skipping the cache")
	if _, err := parse(fs, args); err != nil {
		return ExitUsage
	}
	ctx := context.Background()
	pkgs, errs := env.inventory(ctx)
	if err := env.secure(ctx, pkgs, *refresh); err != nil {
		errs["security"] = err.Error()
	}
	r := env.report(pkgs, errs)
	if *asJSON {
		env.printJSON(r)
	} else {
		env.printReport(r)
	}
	if !r.Safe {
		return ExitAtRisk
	}
	return ExitOK
}

func (env Env) printReport(r Report) {
	w := env.Out
	verdict := "✓ safe: no known advisories affect what's installed"
	if !r.Safe {
		verdict = "⚠ at risk: " + plural(r.Summary.Vulnerable, "vulnerable package") + ", " + plural(r.Summary.RiskySkills, "risky skill")
	}
	if r.Safe && !r.Complete {
		verdict = "✓ safe for what was read: " + plural(len(r.Skipped), "manager") + " could not be checked"
	}
	fmt.Fprintf(w, "%s\n%d packages · %d outdated · %d pinned · %d with vulnerable dependencies\n",
		verdict, r.Summary.Packages, r.Summary.Outdated, r.Summary.Pinned, r.Summary.WithVulnerableDeps)
	for _, f := range r.Vulnerable {
		fmt.Fprintf(w, "\n%s/%s %s\n", f.Source, f.Name, f.Version)
		for _, a := range f.Advisories {
			fmt.Fprintf(w, "  %-8s %s  %s (fixed in %s)\n", cmp.Or(a.Severity, "UNKNOWN"), a.ID, a.Summary, cmp.Or(a.FixedIn, "no fix yet"))
		}
		if f.Fix != "" {
			fmt.Fprintf(w, "  fix: %s\n", f.Fix)
		}
	}
	for _, s := range r.RiskySkills {
		fmt.Fprintf(w, "\nskill %s (%s): Gen %s, Socket %s, Snyk %s\n  report: %s\n", s.Name, s.Repo, s.Gen, s.Socket, s.Snyk, s.Report)
	}
	if len(r.NotCovered) > 0 {
		fmt.Fprintf(w, "\nnot covered by OSV: %s\n", strings.Join(r.NotCovered, ", "))
	}
	if len(r.Skipped) > 0 {
		var skipped []string
		for src, why := range r.Skipped {
			skipped = append(skipped, src+" ("+why+")")
		}
		slices.Sort(skipped)
		fmt.Fprintf(w, "\nnot checked, %s left out: %s\n", plural(len(skipped), "manager"), strings.Join(skipped, ", "))
	}
	for src, err := range r.Errors {
		fmt.Fprintf(w, "error from %s: %s\n", src, err)
	}
}

func plural(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// find looks up an installed package by "source/name".
func find(pkgs []provider.Package, ref string) (provider.Package, error) {
	source, name, ok := strings.Cut(ref, "/")
	if !ok {
		return provider.Package{}, fmt.Errorf("%q is not source/name, like pipx/ruff", ref)
	}
	for _, p := range pkgs {
		if p.Source == source && p.Name == name {
			return p, nil
		}
	}
	return provider.Package{}, fmt.Errorf("%s is not installed", ref)
}

func (env Env) provider(p provider.Package) provider.Provider {
	for _, pr := range env.Providers {
		if pr.Name() == provider.ProviderOf(p) {
			return pr
		}
	}
	return nil
}

type Detail struct {
	provider.Package
	Advisories     []Advisory  `json:"advisories"`
	VulnerableDeps []Finding   `json:"vulnerableDeps"`
	Audit          *RiskySkill `json:"audit,omitempty"`
	Fix            string      `json:"fix,omitempty"`
}

func (env Env) show(args []string) int {
	fs := env.flags("show")
	asJSON := fs.Bool("json", false, "print as JSON")
	rest, err := parse(fs, args)
	if err != nil || len(rest) != 1 {
		fmt.Fprintln(env.Err, "usage: kho show <source>/<name> [--json]")
		return ExitUsage
	}
	ctx := context.Background()
	pkgs, _ := env.inventory(ctx)
	p, err := find(pkgs, rest[0])
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return ExitError
	}
	env.secure(ctx, []provider.Package{p}, false)
	r := env.report([]provider.Package{p}, nil)
	d := Detail{Package: p, Advisories: []Advisory{}, VulnerableDeps: r.VulnerableDeps}
	if len(r.Vulnerable) > 0 {
		d.Advisories, d.Fix = r.Vulnerable[0].Advisories, r.Vulnerable[0].Fix
	}
	if a, ok := env.DB.Audits[p.Repo+"/"+p.Name]; ok {
		d.Audit = &RiskySkill{p.Name, p.Repo, a.Gen, a.Socket, a.Snyk, vuln.SkillPage(p.Repo, p.Name)}
	}
	if *asJSON {
		env.printJSON(d)
		return ExitOK
	}
	fmt.Fprintf(env.Out, "%s/%s %s (latest %s)\n%s\n", p.Source, p.Name, p.Version, cmp.Or(p.Latest, "unknown"), p.Desc)
	for _, a := range d.Advisories {
		fmt.Fprintf(env.Out, "  %-8s %s  %s (fixed in %s)\n  %s\n", cmp.Or(a.Severity, "UNKNOWN"), a.ID, a.Summary, cmp.Or(a.FixedIn, "no fix yet"), a.URL)
	}
	if d.Fix != "" {
		fmt.Fprintf(env.Out, "fix: %s\n", d.Fix)
	}
	return ExitOK
}

type InstallResult struct {
	Package string   `json:"package"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Command []string `json:"command"`
	Ran     bool     `json:"ran"`
	Error   string   `json:"error,omitempty"`
}

// install moves an installed package to a published version. It checks the
// version against what the registry lists, so nothing but a real version
// reaches the package manager, and runs only with --yes.
func (env Env) install(args []string) int {
	fs := env.flags("install")
	yes := fs.Bool("yes", false, "run it; without this kho only prints what it would run")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	rest, err := parse(fs, args)
	if err != nil || len(rest) != 1 {
		fmt.Fprintln(env.Err, "usage: kho install <source>/<name>@<version|latest> [--yes] [--json]")
		return ExitUsage
	}
	ref, version, ok := strings.Cut(rest[0], "@")
	if !ok || version == "" {
		fmt.Fprintln(env.Err, "say which version: kho install <source>/<name>@<version|latest>")
		return ExitUsage
	}
	ctx := context.Background()
	pkgs, _ := env.inventory(ctx)
	p, err := find(pkgs, ref)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return ExitError
	}
	if version == "latest" {
		version = p.Latest
	}
	cmd, err := provider.InstallCmd(p, version)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return ExitError
	}
	if p.Source != "brew" && p.Source != "cask" && p.Source != "skills" {
		if err := env.published(ctx, p, version); err != nil {
			fmt.Fprintln(env.Err, err)
			return ExitError
		}
	}
	res := InstallResult{Package: ref, From: p.Version, To: version, Command: cmd.Args}
	if *yes {
		start := env.Now()
		out, err := env.Run(cmd)
		res.Ran = true
		e := history.Entry{At: start, Kind: history.Change, Command: cmd.Args, Took: env.Now().Sub(start), Output: out}
		if err != nil {
			res.Error, e.Err = err.Error(), err.Error()
		}
		env.Log.Add(e)
	}
	if *asJSON {
		env.printJSON(res)
	} else if !res.Ran {
		fmt.Fprintf(env.Out, "would run: %s\nadd --yes to run it\n", strings.Join(cmd.Args, " "))
	}
	if res.Error != "" {
		if !*asJSON {
			fmt.Fprintln(env.Err, res.Error)
		}
		return ExitError
	}
	return ExitOK
}

func (env Env) published(ctx context.Context, p provider.Package, version string) error {
	pr := env.provider(p)
	if pr == nil {
		return fmt.Errorf("no provider for %s", p.Source)
	}
	rels, err := pr.Versions(ctx, p)
	if err != nil {
		return fmt.Errorf("could not list %s versions: %w", p.Name, err)
	}
	for _, r := range rels {
		if r.Version == version || provider.TagVersion(r.Version) == provider.TagVersion(version) {
			return nil
		}
	}
	return fmt.Errorf("%s has no published version %q", p.Name, version)
}

func (env Env) history(args []string) int {
	fs := env.flags("history")
	asJSON := fs.Bool("json", false, "print as JSON")
	changes := fs.Bool("changes", false, "only commands that changed the machine")
	n := fs.Int("n", 50, "how many to show")
	if _, err := parse(fs, args); err != nil {
		return ExitUsage
	}
	var es []history.Entry
	for _, e := range env.Log.Entries() {
		if (!*changes || e.Kind == history.Change) && len(es) < *n {
			es = append(es, e)
		}
	}
	if *asJSON {
		if es == nil {
			es = []history.Entry{}
		}
		env.printJSON(es)
		return ExitOK
	}
	for _, e := range es {
		result := "ok"
		if e.Err != "" {
			result = e.Err
		}
		fmt.Fprintf(env.Out, "%s  %-6s  %s  (%s)\n", e.At.Format("2006-01-02 15:04:05"), e.Kind, strings.Join(e.Command, " "), result)
	}
	return ExitOK
}

func (env Env) list() int {
	pkgs, errs := env.inventory(context.Background())
	if pkgs == nil {
		pkgs = []provider.Package{}
	}
	env.printJSON(pkgs)
	for src, err := range errs {
		fmt.Fprintf(env.Err, "%s: %s\n", src, err)
	}
	if len(errs) > 0 {
		return ExitError
	}
	return ExitOK
}

// RunCommand runs an install for real, streaming its output to w and keeping
// the last 64KB for the history.
func RunCommand(w io.Writer) func(*exec.Cmd) (string, error) {
	return func(cmd *exec.Cmd) (string, error) {
		pr, pw := io.Pipe()
		cmd.Stdout, cmd.Stderr = pw, pw
		var out strings.Builder
		done := make(chan struct{})
		go func() {
			sc := bufio.NewScanner(pr)
			for sc.Scan() {
				fmt.Fprintln(w, sc.Text())
				out.WriteString(sc.Text() + "\n")
			}
			close(done)
		}()
		err := cmd.Run()
		pw.Close()
		<-done
		s := out.String()
		if len(s) > 64<<10 {
			s = s[len(s)-64<<10:]
		}
		return s, err
	}
}
