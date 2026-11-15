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
	"maps"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/project"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

// Exit codes. An agent can branch on them without parsing the output.
const (
	ExitOK         = 0
	ExitError      = 1
	ExitUsage      = 2
	ExitAtRisk     = 3
	ExitIncomplete = 4
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
	// BrewScan runs Homebrew's own vulnerability scan over the installed
	// formulae. main fills it.
	BrewScan func(context.Context) (vuln.BrewResult, error)
	// Run runs an install. It gets the command as built by the provider and
	// returns its combined output.
	Run func(*exec.Cmd) (string, error)
	// Skipped names the providers this machine is not set up for, with what
	// was looked for. main fills it from provider.Detect.
	Skipped map[string]string
	// Major names a higher major module path that serves a version, so a Go
	// tool that moved to /v2 is reported instead of "no published version".
	Major func(context.Context, string, string) string
	// FindProject reads a folder's lockfiles, and Latest looks up the newest
	// version of a project's direct packages. main fills them.
	FindProject func(context.Context, string) (project.Scan, error)
	Latest      func(context.Context, []provider.Package) []provider.Package
	// FindImages reads the images a folder's Dockerfiles and compose files
	// name, LocalImages lists what docker holds, and InspectImages fills in
	// what the registries and lifecycle pages say. main fills them.
	FindImages    func(context.Context, string) (image.Scan, error)
	LocalImages   func(context.Context) ([]image.LocalImage, error)
	InspectImages func(context.Context, []image.Ref, []image.LocalImage, bool) []image.Ref
	// RefreshImages drops what the registries said before, for --refresh.
	RefreshImages func()
}

const Usage = `kho - one place for every package manager on your machine

usage:
  kho                                  open the TUI
  kho <folder>                         open the TUI on a folder, to read its project
  kho check [--json] [--refresh] [--require-complete] [--require uv,npm]
                                       am I safe? inventory plus known advisories
  kho check --project [folder] [--prod-only] [--json] [--refresh] [--require-images]
                                       is this project safe? reads its lockfiles
                                       and its images, not the machine;
                                       --prod-only leaves out dev dependencies
  kho search <query...> [--source brew,npm] [--limit N] [--json]
                                       find packages this machine does not have;
                                       --source narrows it, --limit caps each
                                       source
  kho show <source>/<name> [--json]    one package, with every advisory
  kho install <source>/<name>@<version> [--yes] [--json]
                                       install, upgrade or downgrade to that
                                       version; without --yes it only says what
                                       it would run
  kho remove <source>/<name> [--yes] [--force] [--json]
                                       uninstall it; without --yes it only says
                                       what it would run; --force overrides
                                       Homebrew's dependency refusal
  kho history [--json] [--changes] [-n N]
                                       commands kho ran, newest first
  kho list                             every package as JSON
  kho version                          print the version
  kho help                             print this

exit codes: 0 ok or safe, 1 error, 2 usage, 3 at risk, 4 incomplete scan under --require or --require-complete
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
	case "search":
		return env.search(args)
	case "install":
		return env.install(args)
	case "remove":
		return env.remove(args)
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

// IsCommand says whether name is one of Main's commands, so a folder with
// the same name never shadows it.
func IsCommand(name string) bool {
	return slices.Contains([]string{"version", "check", "show", "search", "install", "remove", "history", "list", "help"}, name) || strings.HasPrefix(name, "-")
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

// inventory lists every provider with latest versions, in parallel. A failed
// list is filed under the provider's name, and a failed latest lookup under
// "<name> latest", since its packages were still read and can be checked.
func (env Env) inventory(ctx context.Context) ([]provider.Package, map[string]string) {
	return env.gather(ctx, true)
}

// inventoryList is inventory without the network: removing a package needs
// what is installed, and asking every registry for the newest version first
// would make an uninstall wait on the internet.
func (env Env) inventoryList(ctx context.Context) ([]provider.Package, map[string]string) {
	return env.gather(ctx, false)
}

func (env Env) gather(ctx context.Context, latest bool) ([]provider.Package, map[string]string) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var all []provider.Package
	errs := map[string]string{}
	for _, p := range env.Providers {
		wg.Go(func() {
			pkgs, err := p.List(ctx)
			var latestErr error
			if err == nil && latest {
				pkgs, latestErr = p.Latest(ctx, pkgs)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[p.Name()] = err.Error()
			}
			if latestErr != nil {
				errs[p.Name()+" latest"] = latestErr.Error()
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
// their known dependencies, Homebrew for formulae, skills.sh for skills.
// refresh ignores the cache.
func (env Env) secure(ctx context.Context, pkgs []provider.Package, refresh bool) error {
	var queries []vuln.Query
	bySource := map[string][]string{}
	for _, p := range pkgs {
		if q, ok := provider.Query(p); ok {
			queries = append(queries, q)
		}
		queries = append(queries, provider.DepQueries(p)...)
		if p.Source == "skills" && p.Repo != "" {
			bySource[p.Repo] = append(bySource[p.Repo], p.Name)
		}
	}
	if !refresh {
		queries = env.DB.Stale(queries, env.Now())
		bySource = env.DB.StaleAudits(bySource, env.Now())
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
		env.DB.MergeAudits(bySource, audits, err, env.Now())
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := env.brew(ctx, pkgs, refresh); err != nil {
		errs = append(errs, err)
	}
	if env.DBPath != "" {
		env.DB.Save(env.DBPath)
	}
	return errors.Join(errs...)
}

// brew scans the installed formulae with Homebrew's own scanner. A brew too
// old for `brew vulns` is recorded as a coverage gap, not as an error.
func (env Env) brew(ctx context.Context, pkgs []provider.Package, refresh bool) error {
	queries := provider.BrewQueries(pkgs)
	if len(queries) == 0 || env.BrewScan == nil {
		return nil
	}
	if !refresh && len(env.DB.Stale(queries, env.Now())) == 0 {
		return nil
	}
	result, err := env.BrewScan(ctx)
	switch {
	case errors.Is(err, provider.ErrBrewVulnsUnsupported):
		env.DB.SetBrewUnsupported(err.Error(), env.Now())
		return nil
	case err != nil:
		return fmt.Errorf("brew vulns: %w", err)
	}
	env.DB.MergeBrew(result, queries, env.Now())
	return nil
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
	Source        string `json:"source"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Latest        string `json:"latest,omitempty"`
	Status        string `json:"status"`
	Pinned        bool   `json:"pinned,omitempty"`
	Dependency    string `json:"dependency,omitempty"`
	FixedIn       string `json:"fixedIn,omitempty"`
	LatestIsClear *bool  `json:"latestIsClear,omitempty"`
	Fix           string `json:"fix,omitempty"`
	// Lockfile, Dev and Via describe a project package: where it was read,
	// whether only development needs it, and what pulls it in.
	Lockfile   string     `json:"lockfile,omitempty"`
	Dev        bool       `json:"dev,omitempty"`
	Via        []string   `json:"via,omitempty"`
	Advisories []Advisory `json:"advisories"`
}

// ProjectReport is what `kho check --project` read.
type ProjectReport struct {
	Root      string           `json:"root"`
	Lockfiles []LockfileReport `json:"lockfiles"`
	Capped    string           `json:"capped,omitempty"`
}

type LockfileReport struct {
	Path     string `json:"path"`
	Manager  string `json:"manager"`
	Packages int    `json:"packages"`
	Missing  string `json:"missing,omitempty"`
	Error    string `json:"error,omitempty"`
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
	// Images counts the container images a project names, and how many of
	// them are behind or past their line. Zero on the machine report.
	Images      int `json:"images,omitempty"`
	ImagesStale int `json:"imagesStale,omitempty"`
	ImagesEOL   int `json:"imagesEol,omitempty"`
	ImagesGone  int `json:"imagesGone,omitempty"`
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
	Project        *ProjectReport    `json:"project,omitempty"`
	// Images are the container images the project names. kho reads their
	// references and their registry metadata, never their contents.
	Images []image.Ref `json:"images,omitempty"`
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
	f := Finding{Source: p.Source, Name: p.Name, Version: p.Version, Latest: p.Latest, Status: "vulnerable",
		Pinned: p.Pinned, Lockfile: p.Lockfile, Dev: p.Dev, Via: p.Via, Advisories: advisories(advs, p.Version)}
	f.FixedIn = fixFor(advs, p.Version)
	if p.Lockfile != "" {
		// kho never changes a project, so the fix is the project's own command.
		target := f.FixedIn
		if p.Latest != "" {
			clear := !slices.ContainsFunc(advs, func(a vuln.Advisory) bool { return a.Affects(p.Latest) })
			f.LatestIsClear = &clear
			if target == "" && clear {
				target = p.Latest
			}
		}
		if target != "" {
			f.Fix = project.FixCommand(p, target)
		}
		return f
	}
	if p.Latest != "" {
		clear := true
		for _, a := range advs {
			if a.Affects(p.Latest) {
				clear = false
			}
		}
		// Homebrew reports a finding without the ranges OSV uses, so a
		// finding with no released fix cannot say the newest formula is clear.
		if p.Source == "brew" && f.FixedIn == "" {
			clear = false
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
	brewSeen := false
	notCovered := func(what string) {
		if !slices.Contains(r.NotCovered, what) {
			r.NotCovered = append(r.NotCovered, what)
		}
	}
	for _, p := range pkgs {
		r.Summary.Packages++
		if p.Pinned {
			r.Summary.Pinned++
		}
		if p.Outdated {
			r.Summary.Outdated++
			r.Outdated = append(r.Outdated, Outdated{p.Source, p.Name, p.Version, p.Latest, p.Pinned})
		}
		q, osv := provider.Query(p)
		bq, brew := provider.BrewQuery(p)
		switch {
		case osv:
			covered[p.Source] = true
			if advs := env.DB.For(q); len(advs) > 0 {
				r.Vulnerable = append(r.Vulnerable, env.finding(p, advs))
			}
		case brew:
			brewSeen = true
			if advs := env.DB.For(bq); len(advs) > 0 && env.coverage(p) == "" {
				r.Vulnerable = append(r.Vulnerable, env.finding(p, advs))
			}
		case p.Source == "skills":
			// skills.sh answers for skills, not OSV.
		default:
			if why := provider.Coverage(p); why != "" {
				notCovered(p.Source + " (" + why + ")")
			} else {
				notCovered(p.Source)
			}
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
		if a, ok := env.DB.Audits[vuln.AuditKey(p.Repo, p.Name)]; ok && p.Source == "skills" && vuln.Verdict(a.Worst()) == vuln.Fail {
			r.RiskySkills = append(r.RiskySkills, RiskySkill{p.Name, p.Repo, a.Gen, a.Socket, a.Snyk, vuln.SkillPage(p.Repo, p.Name)})
		}
	}
	if brewSeen {
		switch note := env.DB.BrewNote(); {
		case note != "":
			notCovered("brew (" + note + ")")
		case !env.DB.BrewScanned():
			notCovered("brew")
		default:
			for _, p := range pkgs {
				if p.Source != "brew" {
					continue
				}
				if why := env.DB.BrewSkip(p.Name); why != "" {
					notCovered("brew/" + p.Name + " (" + why + ")")
				}
			}
		}
	}
	r.NotCovered = slices.DeleteFunc(r.NotCovered, func(s string) bool { return covered[s] })
	r.Summary.Vulnerable, r.Summary.RiskySkills = len(r.Vulnerable), len(r.RiskySkills)
	r.Safe = len(r.Vulnerable) == 0 && len(r.RiskySkills) == 0
	// Complete is false when a manager was skipped, a source failed, or
	// Homebrew could not check every installed formula, so a script can tell a
	// full scan from one that only read part of the machine.
	r.Complete = len(r.Skipped) == 0 && len(r.Errors) == 0 && (!brewSeen || env.DB.BrewComplete())
	return r
}

// coverage says why kho has no advisories for p, or "" when it asked.
func (env Env) coverage(p provider.Package) string {
	if p.Source != "brew" {
		return provider.Coverage(p)
	}
	if note := env.DB.BrewNote(); note != "" {
		return note
	}
	return env.DB.BrewSkip(p.Name)
}

func (env Env) printJSON(v any) {
	enc := json.NewEncoder(env.Out)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func (env Env) check(args []string) int {
	fs := env.flags("check")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	refresh := fs.Bool("refresh", false, "ask OSV, Homebrew and skills.sh again, skipping the cache")
	inProject := fs.Bool("project", false, "check a project's lockfiles, in the folder given or the current one, instead of the machine")
	prodOnly := fs.Bool("prod-only", false, "with --project, leave out dev dependencies")
	// A script that branches on the exit code cannot tell a clean scan from a
	// partial one, so it can name the managers it depends on, or ask for a full
	// scan, and get a failure when that did not happen.
	requireComplete := fs.Bool("require-complete", false, "fail when a manager or source could not be read")
	require := fs.String("require", "", "comma separated sources that must be readable, like uv,npm")
	requireImages := fs.Bool("require-images", false, "with --project, also fail on a stale image, and on an image kho could not read")
	rest, err := parse(fs, args)
	if err != nil {
		return ExitUsage
	}
	if *inProject {
		if *require != "" {
			fmt.Fprintln(env.Err, "--require names machine package managers; with --project, use --require-complete")
			return ExitUsage
		}
		return env.checkProject(rest, *refresh, *prodOnly, *asJSON, *requireComplete, *requireImages)
	}
	required, unknown := splitSources(*require)
	if len(unknown) > 0 {
		fmt.Fprintf(env.Err, "unknown source in --require: %s\n", strings.Join(unknown, ", "))
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
	missingRequired := unreadable(r, required)
	partial := len(missingRequired) > 0 || (*requireComplete && !r.Complete)
	if partial {
		// Say what was not read even when the scan is also at risk, so a partial
		// answer never looks like a complete one.
		if len(missingRequired) > 0 {
			fmt.Fprintf(env.Err, "scan was not complete for %s\n", strings.Join(missingRequired, ", "))
		} else {
			fmt.Fprintf(env.Err, "scan was not complete: %s\n", whyIncomplete(r))
		}
	}
	if !r.Safe {
		return ExitAtRisk
	}
	if partial {
		return ExitIncomplete
	}
	return ExitOK
}

// images reads the images a folder's Dockerfiles and compose files name, and
// asks the registries and lifecycle pages about them. It never pulls, builds
// or runs anything, so a state here is never a claim about what is inside an
// image.
func (env Env) images(ctx context.Context, dir string) ([]image.Ref, map[string]string) {
	errs := map[string]string{}
	if env.FindImages == nil {
		return nil, errs
	}
	scan, err := env.FindImages(ctx, dir)
	if err != nil {
		errs["images"] = err.Error()
		return nil, errs
	}
	if scan.Capped != "" {
		errs["images"] = scan.Capped
	}
	if len(scan.Refs) == 0 {
		return nil, errs
	}
	var local []image.LocalImage
	asked := false
	if env.LocalImages != nil {
		if l, err := env.LocalImages(ctx); err == nil {
			local, asked = l, true
		}
	}
	if env.InspectImages == nil {
		return scan.Refs, errs
	}
	return env.InspectImages(ctx, scan.Refs, local, asked), errs
}

// imageRisk splits what images say into what makes a scan unsafe and what
// makes it incomplete. A closed line or an unpublished tag is a real
// problem; a stale tag is a hint, unless the caller asked for it to count.
func imageRisk(refs []image.Ref, staleCounts bool) (atRisk, incomplete bool) {
	for _, r := range refs {
		switch {
		case r.Unresolved:
			incomplete = true
		case r.State == image.EOL || r.State == image.Gone:
			atRisk = true
		case r.State == image.Unknown:
			incomplete = true
		case staleCounts && r.State == image.Stale:
			atRisk = true
		}
	}
	return atRisk, incomplete
}

// checkProject is `kho check --project`: the packages in a folder's
// lockfiles, checked the same way as the machine's. A lockfile that could not
// be read, a manifest with no lockfile, or a scan that stopped early leaves
// the report incomplete, so a clean verdict never covers what wasn't read.
func (env Env) checkProject(args []string, refresh, prodOnly, asJSON, requireComplete, requireImages bool) int {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	ctx := context.Background()
	scan, err := env.FindProject(ctx, dir)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return ExitError
	}
	pr := &ProjectReport{Root: scan.Root, Capped: scan.Capped, Lockfiles: []LockfileReport{}}
	errs := map[string]string{}
	var unread []string
	var pkgs []provider.Package
	for _, p := range scan.Projects {
		for _, lf := range p.Lockfiles {
			pr.Lockfiles = append(pr.Lockfiles, LockfileReport{lf.Path, lf.Manager, len(lf.Packages), lf.Missing, lf.Err})
			if lf.Err != "" {
				errs[lf.Path] = lf.Err
			}
			if lf.Missing != "" {
				unread = append(unread, lf.Path+" ("+lf.Missing+")")
			}
			for _, pkg := range lf.Packages {
				if !prodOnly || !pkg.Dev {
					pkgs = append(pkgs, pkg)
				}
			}
		}
	}
	if scan.Capped != "" {
		errs["scan"] = scan.Capped
	}
	for _, dir := range scan.Shallow {
		unread = append(unread, dir+" (kho doesn't look deeper than this)")
	}
	pkgs = env.Latest(ctx, pkgs)
	if err := env.secure(ctx, pkgs, refresh); err != nil {
		errs["security"] = err.Error()
	}
	if refresh && env.RefreshImages != nil {
		env.RefreshImages()
	}
	refs, imageErrs := env.images(ctx, dir)
	for k, v := range imageErrs {
		errs[k] = v
	}
	r := env.report(pkgs, errs)
	r.Images = refs
	r.Summary.Images = len(refs)
	for _, ref := range refs {
		switch ref.State {
		case image.Stale:
			r.Summary.ImagesStale++
		case image.EOL:
			r.Summary.ImagesEOL++
		case image.Gone:
			r.Summary.ImagesGone++
		}
	}
	atRisk, imageIncomplete := imageRisk(refs, requireImages)
	if atRisk {
		r.Safe = false
	}
	r.Skipped, r.Project = nil, pr
	r.NotCovered = append(r.NotCovered, unread...)
	if len(pr.Lockfiles) == 0 {
		unread = append(unread, "no lockfiles found in "+scan.Root)
		r.NotCovered = append(r.NotCovered, unread[len(unread)-1])
	}
	r.Complete = len(errs) == 0 && len(unread) == 0 && !(requireImages && imageIncomplete)
	if asJSON {
		env.printJSON(r)
	} else {
		env.printReport(r)
	}
	if (requireComplete || requireImages) && !r.Complete {
		fmt.Fprintf(env.Err, "check was not complete: %s\n", whyProjectIncomplete(r, unread))
	}
	switch {
	case !r.Safe:
		return ExitAtRisk
	case (requireComplete || requireImages) && !r.Complete:
		return ExitIncomplete
	}
	return ExitOK
}

// whyProjectIncomplete names what kept a project check from reading it all.
func whyProjectIncomplete(r Report, unread []string) string {
	reasons := slices.Clone(unread)
	for _, src := range slices.Sorted(maps.Keys(r.Errors)) {
		reasons = append(reasons, src+": "+r.Errors[src])
	}
	return strings.Join(reasons, ", ")
}

// splitSources reads the --require list as provider names, so "cask" from the
// JSON means brew, and returns the names kho does not know, so a typo fails
// loudly instead of passing as "nothing to check".
func splitSources(list string) (known, unknown []string) {
	sources := map[string]bool{}
	for _, p := range provider.All() {
		sources[p.Name()] = true
	}
	for _, name := range strings.Split(list, ",") {
		name = provider.ProviderOf(provider.Package{Source: strings.TrimSpace(name)})
		if name == "" {
			continue
		}
		if !sources[name] {
			unknown = append(unknown, name)
		} else if !slices.Contains(known, name) {
			known = append(known, name)
		}
	}
	return known, unknown
}

// unreadable names the required sources this scan could not read, with why.
func unreadable(r Report, required []string) []string {
	var missing []string
	for _, name := range required {
		if why, ok := r.Skipped[name]; ok {
			missing = append(missing, name+" ("+why+")")
		} else if err, ok := r.Errors[name]; ok {
			missing = append(missing, name+" failed: "+err)
		}
	}
	return missing
}

// whyIncomplete names what stopped a scan from reading the whole machine.
func whyIncomplete(r Report) string {
	var reasons []string
	for _, src := range slices.Sorted(maps.Keys(r.Skipped)) {
		reasons = append(reasons, src+" ("+r.Skipped[src]+")")
	}
	for _, src := range slices.Sorted(maps.Keys(r.Errors)) {
		reasons = append(reasons, src+" failed: "+r.Errors[src])
	}
	if len(reasons) == 0 {
		reasons = append(reasons, r.NotCovered...)
	} else {
		// A skipped manager should not hide the formulae Homebrew could not
		// check, so name the coverage gaps too, with the formulae counted.
		brew := 0
		for _, n := range r.NotCovered {
			if strings.HasPrefix(n, "brew/") {
				brew++
				continue
			}
			reasons = append(reasons, n)
		}
		if brew > 0 {
			reasons = append(reasons, fmt.Sprintf("brew (%s not covered)", plural(brew, "formula")))
		}
	}
	if len(reasons) == 0 {
		return "nothing to read"
	}
	return strings.Join(reasons, ", ")
}

func (env Env) printReport(r Report) {
	w := env.Out
	verdict := "✓ safe: no known advisories affect what's installed"
	if r.Project != nil {
		fmt.Fprintf(w, "project %s, %s\n", r.Project.Root, plural(len(r.Project.Lockfiles), "lockfile"))
		verdict = "✓ safe: no known advisories affect what the lockfiles pin"
	}
	if !r.Safe {
		verdict = "⚠ at risk: " + plural(r.Summary.Vulnerable, "vulnerable package") + ", " + plural(r.Summary.RiskySkills, "risky skill")
		if r.Project != nil {
			verdict = "⚠ at risk: " + plural(r.Summary.Vulnerable, "vulnerable package")
		}
		if r.Summary.ImagesEOL > 0 || r.Summary.ImagesGone > 0 {
			var why []string
			if r.Summary.ImagesEOL > 0 {
				why = append(why, plural(r.Summary.ImagesEOL, "image")+" past its line")
			}
			if r.Summary.ImagesGone > 0 {
				why = append(why, plural(r.Summary.ImagesGone, "image tag")+" gone")
			}
			verdict = "⚠ at risk: " + strings.Join(why, ", ")
			if r.Summary.Vulnerable > 0 {
				verdict += ", " + plural(r.Summary.Vulnerable, "vulnerable package")
			}
		}
	}
	if r.Safe && !r.Complete {
		verdict = "✓ safe for what was read: part of the machine could not be checked"
		if r.Project != nil {
			verdict = "✓ safe for what was read: part of the project could not be checked"
		}
	}
	fmt.Fprintf(w, "%s\n%d packages · %d outdated · %d pinned · %d with vulnerable dependencies\n",
		verdict, r.Summary.Packages, r.Summary.Outdated, r.Summary.Pinned, r.Summary.WithVulnerableDeps)
	for _, f := range r.Vulnerable {
		fmt.Fprintf(w, "\n%s/%s %s%s\n", f.Source, f.Name, f.Version, where(f))
		for _, a := range f.Advisories {
			fmt.Fprintf(w, "  %-8s %s  %s (fixed in %s)\n", cmp.Or(a.Severity, "UNKNOWN"), a.ID, a.Summary, cmp.Or(a.FixedIn, "no fix yet"))
		}
		if f.Fix != "" && f.Lockfile != "" && path.Dir(f.Lockfile) != "." {
			fmt.Fprintf(w, "  fix, in %s: %s\n", path.Dir(f.Lockfile), f.Fix)
		} else if f.Fix != "" {
			fmt.Fprintf(w, "  fix: %s\n", f.Fix)
		}
	}
	for _, s := range r.RiskySkills {
		fmt.Fprintf(w, "\nskill %s (%s): Gen %s, Socket %s, Snyk %s\n  report: %s\n", s.Name, s.Repo, s.Gen, s.Socket, s.Snyk, s.Report)
	}
	if len(r.Images) > 0 {
		fmt.Fprintf(w, "\n%d images · %d stale · %d past their line · %d gone\n", len(r.Images), r.Summary.ImagesStale, r.Summary.ImagesEOL, r.Summary.ImagesGone)
		for _, img := range r.Images {
			line := fmt.Sprintf("  %s %-34s %-13s", img.Presence.Mark(), img.Image, stateWord(img))
			if img.Upstream != "" {
				line += " " + img.Upstream
			}
			if img.File != "" {
				line += "  (" + img.File + ":" + itoa(img.Line) + ")"
			}
			fmt.Fprintln(w, line)
			if img.Unresolved {
				fmt.Fprintf(w, "    chosen at build time by %s, so kho cannot say which image this is\n", img.Via)
			}
			if img.State == image.EOL {
				fmt.Fprintf(w, "    %s stopped getting fixes on %s\n", img.Repo, img.EOL.Format("2006-01-02"))
			}
		}
	}
	if len(r.NotCovered) > 0 {
		fmt.Fprintf(w, "\nnot covered: %s\n", strings.Join(r.NotCovered, ", "))
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

// where says, for a project package, which lockfile it is from and what
// pulls it in.
func where(f Finding) string {
	if f.Lockfile == "" {
		return ""
	}
	parts := []string{f.Lockfile}
	if f.Dev {
		parts = append(parts, "dev")
	}
	if len(f.Via) > 0 {
		parts = append(parts, "via "+strings.Join(f.Via, " > "))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// stateWord is what a person reads for an image state.
func stateWord(r image.Ref) string {
	switch r.State {
	case image.Fresh:
		return "fresh"
	case image.Stale:
		return "stale"
	case image.EOL:
		return "past its line"
	case image.Gone:
		return "tag gone"
	case image.Pinned:
		return "pinned"
	case image.Local:
		return "built here"
	case image.None:
		return "nothing to ask"
	case image.Unknown:
		return "could not ask"
	}
	return "build time"
}

func itoa(n int) string { return strconv.Itoa(n) }

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
	if a, ok := env.DB.Audits[vuln.AuditKey(p.Repo, p.Name)]; ok {
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
	if len(d.Advisories) == 0 {
		if why := env.coverage(p); why != "" {
			fmt.Fprintf(env.Out, "not covered: %s\n", why)
		}
	}
	if d.Fix != "" {
		fmt.Fprintf(env.Out, "fix: %s\n", d.Fix)
	}
	return ExitOK
}

// searchTimeout bounds a search, so one slow registry cannot hold the command
// open. A registry answers in a second or two; twenty is generous.
const searchTimeout = 20 * time.Second

// noProvider is the report's reason for a requested manager that is neither
// ready nor listed as skipped. That is an inconsistent Env, but the report says
// something instead of dropping the source silently.
const noProvider = "not on this machine"

// SearchReport is what `kho search --json` prints. Version is empty in every
// result, because search lists what the machine does not have. Latest is the
// newest version the registry gave, or empty when it gave none.
type SearchReport struct {
	Query       string             `json:"query"`
	Results     []provider.Package `json:"results"`
	NotSearched []string           `json:"notSearched"`
	Skipped     map[string]string  `json:"skipped"`
	Errors      map[string]string  `json:"errors"`
}

// searchTask is one source a search asks, and what it may answer for.
type searchTask struct {
	manager  string
	labels   []string
	find     bool
	label    string
	provider provider.Provider
	fail     error
}

// searchAnswer is one source's answer: its packages, or why it failed.
type searchAnswer struct {
	pkgs []provider.Package
	err  error
}

// search finds packages the machine does not have. One source that fails never
// hides the ones that answered: its error goes to stderr and into the JSON, and
// the exit is 1 only when nothing answered.
func (env Env) search(args []string) int {
	fs := env.flags("search")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	source := fs.String("source", "", "comma separated sources to search, like brew,npm")
	limit := fs.Int("limit", provider.DefaultSearchLimit, "how many results to ask each source for")
	rest, err := parse(fs, args)
	if err != nil {
		return ExitUsage
	}
	query := strings.TrimSpace(strings.Join(rest, " "))
	if query == "" {
		fmt.Fprintln(env.Err, "usage: kho search <query...> [--source brew,npm] [--limit N] [--json]")
		return ExitUsage
	}
	// One character is too broad to be a search; registries would answer with
	// hundreds of names nobody asked for.
	if utf8.RuneCountInString(query) < 2 {
		fmt.Fprintln(env.Err, "search needs at least 2 characters")
		return ExitUsage
	}
	if *limit < 1 {
		fmt.Fprintln(env.Err, "--limit must be at least 1")
		return ExitUsage
	}
	labels, ok := env.searchLabels(*source)
	if !ok {
		return ExitUsage
	}
	ones, skipped := env.searchPlan(labels)
	start := env.Now()
	answers := runSearch(ones, query, *limit)
	report := SearchReport{Query: query, Results: []provider.Package{}, NotSearched: []string{}, Skipped: skipped, Errors: map[string]string{}}
	var searched []string
	answered := 0
	for i, one := range ones {
		if answers[i].err != nil {
			report.Errors[one.manager] = answers[i].err.Error()
			continue
		}
		answered++
		searched = append(searched, one.labels...)
		report.Results = append(report.Results, answers[i].pkgs...)
	}
	if labels == nil {
		// A manager with only an exact-name lookup is still useful, so name it
		// rather than dropping it silently.
		for _, p := range provider.Finders(env.Providers) {
			if _, ok := p.(provider.Searcher); ok {
				continue
			}
			report.NotSearched = append(report.NotSearched, p.Name())
		}
	}
	if *asJSON {
		env.printJSON(report)
	} else {
		env.printSearch(report, searched, env.Now().Sub(start))
	}
	for _, manager := range slices.Sorted(maps.Keys(report.Errors)) {
		fmt.Fprintf(env.Err, "%s could not search: %s\n", manager, report.Errors[manager])
	}
	if labels != nil {
		env.printNotOnMachine(labels, report.Skipped)
	}
	switch {
	case answered > 0:
		return ExitOK
	case len(ones) == 0 && labels == nil:
		fmt.Fprintln(env.Err, "no package manager on this machine can search by keyword")
	default:
		fmt.Fprintln(env.Err, "could not search any package manager")
	}
	return ExitError
}

// searchLabels reads --source as source labels and says whether each one can be
// searched. An empty list means no narrowing, so every ready source is asked.
func (env Env) searchLabels(list string) ([]string, bool) {
	if strings.TrimSpace(list) == "" {
		return nil, true
	}
	var labels, unknown, deferred []string
	for _, raw := range strings.Split(list, ",") {
		label := strings.TrimSpace(raw)
		if label == "" {
			continue
		}
		if !provider.IsSource(label) {
			if !slices.Contains(unknown, label) {
				unknown = append(unknown, label)
			}
			continue
		}
		// The label is a source kho knows. A deferred manager is a usage
		// error; anything else is accepted and the plan says whether it can
		// search, resolve an exact name, or is skipped on this machine.
		manager := provider.ProviderOf(provider.Package{Source: label})
		if provider.DeferredSource(manager) {
			if !slices.Contains(deferred, label) {
				deferred = append(deferred, label)
			}
			continue
		}
		if !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintf(env.Err, "unknown source in --source: %s\n", strings.Join(unknown, ", "))
		return nil, false
	}
	if len(deferred) > 0 {
		fmt.Fprintf(env.Err, "--source %s is not supported yet\n", strings.Join(deferred, ", "))
		return nil, false
	}
	if len(labels) == 0 {
		fmt.Fprintln(env.Err, "no source named in --source")
		return nil, false
	}
	return labels, true
}

// searchPlan says what one search will ask. No --source asks every ready
// searcher. A --source narrows to the managers it names, and a name-only
// manager resolves the query as an exact name instead of searching for words.
func (env Env) searchPlan(labels []string) ([]searchTask, map[string]string) {
	skipped := map[string]string{}
	if labels == nil {
		for name, why := range env.Skipped {
			skipped[name] = why
		}
		var ones []searchTask
		for _, p := range provider.Searchers(env.Providers) {
			ones = append(ones, searchTask{manager: p.Name(), labels: sourceLabels(p.Name()), provider: p})
		}
		return ones, skipped
	}
	var ones []searchTask
	seen := map[string]bool{}
	for _, label := range labels {
		manager := provider.ProviderOf(provider.Package{Source: label})
		if seen[manager] {
			continue
		}
		seen[manager] = true
		var group []string
		for _, other := range labels {
			if provider.ProviderOf(provider.Package{Source: other}) == manager {
				group = append(group, other)
			}
		}
		p := provider.ProviderNamed(env.Providers, manager)
		if p == nil {
			// Not in Providers means this machine is not set up for it.
			if why, ok := env.Skipped[manager]; ok {
				skipped[manager] = why
			} else {
				skipped[manager] = noProvider
			}
			continue
		}
		one := searchTask{manager: manager, labels: group, provider: p}
		if _, ok := p.(provider.Searcher); ok {
			// keyword search
		} else if _, ok := p.(provider.Finder); ok {
			one.find, one.label = true, group[0]
		} else {
			one.fail = fmt.Errorf("%s cannot search yet", manager)
		}
		ones = append(ones, one)
	}
	return ones, skipped
}

// runSearch asks every source at once under one deadline, so a single slow
// manager cannot hold the command open. Answers keep the plan's order.
func runSearch(ones []searchTask, query string, limit int) []searchAnswer {
	ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
	defer cancel()
	answers := make([]searchAnswer, len(ones))
	var wg sync.WaitGroup
	for i, one := range ones {
		if one.fail != nil {
			answers[i] = searchAnswer{err: one.fail}
			continue
		}
		wg.Go(func() {
			answers[i] = askSource(ctx, one, query, limit)
		})
	}
	wg.Wait()
	return answers
}

// askSource asks one manager. A keyword manager may return packages for more
// than one label, as brew does for formulae and casks, so its answer is
// narrowed to the labels this search asked for.
func askSource(ctx context.Context, one searchTask, query string, limit int) searchAnswer {
	if one.find {
		f, ok := one.provider.(provider.Finder)
		if !ok {
			return searchAnswer{err: fmt.Errorf("%s cannot resolve an exact name yet", one.manager)}
		}
		p, err := f.Find(ctx, one.label, query)
		if err != nil || p.Name == "" {
			// A name-only manager either resolves the name or does not; a miss
			// is no match, as the panel shows, not a failed source.
			return searchAnswer{}
		}
		return searchAnswer{pkgs: []provider.Package{p}}
	}
	s, ok := one.provider.(provider.Searcher)
	if !ok {
		return searchAnswer{err: fmt.Errorf("%s cannot search by keyword yet", one.manager)}
	}
	pkgs, err := s.Search(ctx, query, limit)
	if err != nil {
		return searchAnswer{err: err}
	}
	out := make([]provider.Package, 0, len(pkgs))
	for _, p := range pkgs {
		if slices.Contains(one.labels, p.Source) {
			out = append(out, p)
		}
	}
	return searchAnswer{pkgs: out}
}

// sourceLabels names every label a manager answers for, so a full search says
// brew and cask when brew answered.
func sourceLabels(manager string) []string {
	if manager == "brew" {
		return []string{"brew", "cask"}
	}
	return []string{manager}
}

// printSearch is the text form: one copyable source/name row, then what was
// searched, then the managers that can only install by exact name.
func (env Env) printSearch(r SearchReport, searched []string, took time.Duration) {
	if len(searched) > 0 {
		if len(r.Results) > 0 {
			env.printSearchRows(r.Results)
			fmt.Fprintln(env.Out)
		} else {
			fmt.Fprintf(env.Out, "no packages match %q\n", r.Query)
		}
		fmt.Fprintf(env.Out, "searched %s in %s\n", strings.Join(searched, ", "), secs(took))
	}
	if len(r.NotSearched) > 0 {
		fmt.Fprintf(env.Out, "%s cannot search by keyword; install one by exact name, like kho install %s/ruff@latest\n",
			joinWords(r.NotSearched), r.NotSearched[0])
	}
}

func (env Env) printSearchRows(pkgs []provider.Package) {
	refs, versions, descs := make([]string, len(pkgs)), make([]string, len(pkgs)), make([]string, len(pkgs))
	refW, verW := 0, 0
	for i, p := range pkgs {
		refs[i] = oneLine(p.Source + "/" + p.Name)
		versions[i] = cmp.Or(oneLine(p.Latest), "?")
		descs[i] = oneLine(p.Desc)
		refW = max(refW, utf8.RuneCountInString(refs[i]))
		verW = max(verW, utf8.RuneCountInString(versions[i]))
	}
	for i := range pkgs {
		line := fmt.Sprintf("%-*s  %-*s", refW, refs[i], verW, versions[i])
		if descs[i] != "" {
			line += "  " + descs[i]
		}
		fmt.Fprintln(env.Out, strings.TrimRight(line, " "))
	}
}

// printNotOnMachine names the named sources this machine does not have, so a
// narrowed search that could not ask says why instead of only failing.
func (env Env) printNotOnMachine(labels []string, skipped map[string]string) {
	seen := map[string]bool{}
	for _, label := range labels {
		manager := provider.ProviderOf(provider.Package{Source: label})
		if seen[manager] {
			continue
		}
		seen[manager] = true
		why, ok := skipped[manager]
		if !ok {
			continue
		}
		if why == noProvider {
			fmt.Fprintf(env.Err, "%s is not on this machine\n", manager)
			continue
		}
		fmt.Fprintf(env.Err, "%s is not on this machine (%s)\n", manager, why)
	}
}

// secs is a duration the way a person reads a wait: one decimal and a unit.
func secs(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
}

// joinWords joins names the way a sentence does: "a, b and c".
func joinWords(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// ansiEscape matches the terminal escape sequences a registry can slip into a
// name or a description: colour codes, cursor moves and title settings.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b\\][^\x07]*\x07|\x1b.")

// oneLine strips terminal escapes and control characters and folds text from a
// registry to one line, so a description can never move the cursor or redraw
// the terminal.
func oneLine(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// drop it
		default:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

type InstallResult struct {
	Package string   `json:"package"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Command []string `json:"command"`
	Ran     bool     `json:"ran"`
	Error   string   `json:"error,omitempty"`
	// New is true when kho installs a package the machine did not have, so
	// From is empty and the command came from InstallNewCmd.
	New bool `json:"new,omitempty"`
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
	// Split on the last @, because a scoped npm or Go module name carries one
	// of its own: npm/@scope/tool@1.2.3 is one ref and one version, not two.
	at := strings.LastIndex(rest[0], "@")
	ref, version := rest[0], ""
	if at > 0 {
		ref, version = rest[0][:at], rest[0][at+1:]
	}
	if version == "" {
		fmt.Fprintln(env.Err, "say which version: kho install <source>/<name>@<version|latest>")
		return ExitUsage
	}
	ctx := context.Background()
	pkgs, errs := env.inventory(ctx)
	var res InstallResult
	var cmd *exec.Cmd
	if p, err := find(pkgs, ref); err == nil {
		if version == "latest" {
			version = p.Latest
		}
		cmd, err = provider.InstallCmd(p, version)
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
		res = InstallResult{Package: ref, From: p.Version, To: version, Command: cmd.Args}
	} else {
		// Not installed: this is a new package, resolved through its registry
		// rather than through the machine's inventory.
		var code int
		res, cmd, code = env.installNew(ctx, ref, version, errs)
		if code != ExitOK {
			return code
		}
	}
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

// installNew resolves a ref the machine does not have through its registry and
// builds the command that installs it. The version is resolved and checked
// before the command is printed, as for an installed package. It prints its own
// reason and returns the exit code to use when the ref cannot be resolved.
func (env Env) installNew(ctx context.Context, ref, version string, errs map[string]string) (InstallResult, *exec.Cmd, int) {
	res := InstallResult{Package: ref, New: true}
	source, name, ok := strings.Cut(ref, "/")
	if !ok {
		fmt.Fprintf(env.Err, "%q is not source/name, like pipx/ruff\n", ref)
		return res, nil, ExitError
	}
	if !provider.IsSource(source) {
		fmt.Fprintf(env.Err, "%q is not a source kho knows; try %s\n", source, provider.SourceList())
		return res, nil, ExitError
	}
	manager := provider.ProviderOf(provider.Package{Source: source})
	// A manager that failed to read may hold the package already, so this is
	// not the moment to install over it.
	if why := errs[manager]; why != "" {
		fmt.Fprintf(env.Err, "%s could not be read: %s\n", source, why)
		return res, nil, ExitError
	}
	if why, ok := env.Skipped[manager]; ok {
		fmt.Fprintf(env.Err, "%s is not on this machine (%s)\n", source, why)
		return res, nil, ExitError
	}
	p := provider.ProviderNamed(env.Providers, manager)
	if p == nil {
		fmt.Fprintf(env.Err, "%s is not on this machine\n", source)
		return res, nil, ExitError
	}
	finder, ok := p.(provider.Finder)
	if !ok {
		fmt.Fprintf(env.Err, "kho can't install new %s packages yet\n", source)
		return res, nil, ExitError
	}
	candidate, err := finder.Find(ctx, source, name)
	if err != nil {
		fmt.Fprintf(env.Err, "could not find %s in %s: %s\n", name, source, err)
		return res, nil, ExitError
	}
	if candidate.Name == "" {
		candidate.Name = name
	}
	if candidate.Source == "" {
		candidate.Source = source
	}
	if version == "latest" {
		if candidate.Latest == "" {
			fmt.Fprintf(env.Err, "no latest version known for %s\n", name)
			return res, nil, ExitError
		}
		version = candidate.Latest
	}
	cmd, err := provider.InstallNewCmd(candidate, version)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return res, nil, ExitError
	}
	res.To = version
	if candidate.Source != "brew" && candidate.Source != "cask" && candidate.Source != "skills" {
		if err := env.published(ctx, candidate, version); err != nil {
			if candidate.Source != "go" {
				fmt.Fprintln(env.Err, err)
				return res, nil, ExitError
			}
			// A Go package path is not a module path, so the proxy may not
			// list the version kho asked for. go install changes nothing when
			// that check fails, so the command is the final check.
			fmt.Fprintf(env.Err, "note: %s; go install is the final check\n", err)
		}
	}
	res.Command = cmd.Args
	return res, cmd, ExitOK
}

type RemoveResult struct {
	Package string   `json:"package"`
	Version string   `json:"version"`
	Command []string `json:"command"`
	Ran     bool     `json:"ran"`
	Error   string   `json:"error,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// remove uninstalls one package through its own package manager. Like install,
// it changes nothing without --yes, and a package it cannot see is an error
// rather than a silent success.
func (env Env) remove(args []string) int {
	fs := env.flags("remove")
	// The flag package would print its own error and a flag dump to stderr;
	// kho prints one line instead, and none of it when JSON was asked for.
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "run it; without this kho only prints what it would run")
	force := fs.Bool("force", false, "override Homebrew's refusal when another installed formula needs it")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	rest, err := parse(fs, args)
	if err != nil || len(rest) != 1 {
		// A caller that asked for JSON gets JSON even when the arguments are
		// wrong, so nothing has to parse the usage text.
		reason := "usage: kho remove <source>/<name> [--yes] [--force] [--json]"
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			reason = err.Error()
		}
		// A flag parse stops at the first unknown flag, so --json may not have
		// been read yet when the arguments are already wrong.
		return env.removeFail(*asJSON || hasFlag(args, "--json"), "", "", reason, ExitUsage)
	}
	ref := rest[0]
	source, _, hasSource := strings.Cut(ref, "/")
	switch {
	case !hasSource:
		return env.removeFail(*asJSON, ref, "", fmt.Sprintf("%q is not source/name, like pipx/ruff", ref), ExitUsage)
	case !provider.IsSource(source):
		return env.removeFail(*asJSON, ref, "", fmt.Sprintf("%q is not a source kho knows; try %s", source, provider.SourceList()), ExitUsage)
	case *force && source != "brew":
		return env.removeFail(*asJSON, ref, "", fmt.Sprintf("--force is for Homebrew formulae; %s has no dependency check to override", source), ExitUsage)
	}
	// Only what is installed matters here, so the registries are not asked.
	packages, errs := env.inventoryList(context.Background())
	p, err := find(packages, ref)
	if err != nil {
		reason, code := env.removeMiss(ref, packages, errs)
		return env.removeFail(*asJSON, ref, "", reason, code)
	}
	cmd, err := provider.RemoveCmd(p, *force)
	if err != nil {
		return env.removeFail(*asJSON, ref, p.Version, err.Error(), ExitError)
	}
	var notes []string
	if p.Dependency {
		switch {
		case *force:
			notes = append(notes, fmt.Sprintf("%s is installed as another package's dependency; removing it leaves that package broken until it is installed again", p.Name))
		case p.Source == "brew":
			notes = append(notes, fmt.Sprintf("%s is installed as another package's dependency; the manager may refuse, and --force goes ahead anyway", p.Name))
		default:
			notes = append(notes, fmt.Sprintf("%s is installed as another package's dependency", p.Name))
		}
	}
	if p.Source == "mise" {
		// mise keeps what mise.toml asks for, so an uninstall alone can be
		// undone by the next `mise install`.
		notes = append(notes, "kho can't remove it from mise.toml, so mise may install it again")
		var others []string
		for _, v := range p.Versions {
			if v != p.Version {
				others = append(others, v)
			}
		}
		if len(others) > 0 {
			notes = append(notes, fmt.Sprintf("%s also has %s installed; kho removes only %s", p.Name, strings.Join(others, ", "), p.Version))
		}
	}
	// Notes are for a person reading a terminal; a caller that asked for JSON
	// gets the object, notes included.
	if !*asJSON {
		for _, n := range notes {
			fmt.Fprintf(env.Err, "note: %s\n", n)
		}
	}
	res := RemoveResult{Package: ref, Version: p.Version, Command: cmd.Args, Notes: notes}
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
	switch {
	case *asJSON:
		env.printJSON(res)
	case !res.Ran:
		fmt.Fprintf(env.Out, "would run: %s\nadd --yes to run it\n", joinArgs(cmd.Args))
	case res.Error != "":
		// the manager's failure is the whole story, and it goes to stderr
	case p.Version == "":
		fmt.Fprintf(env.Out, "removed %s\n", ref)
	default:
		fmt.Fprintf(env.Out, "removed %s %s\n", ref, p.Version)
	}
	if res.Error != "" {
		if !*asJSON {
			fmt.Fprintln(env.Err, res.Error)
		}
		return ExitError
	}
	return ExitOK
}

// sameVersion says whether a version typed in a ref names what is installed.
// A bare prefix is not enough: "2" is not the installed 26.13.0, and telling a
// person to remove node would remove a package they did not name.
func sameVersion(installed, typed string) bool {
	if installed == typed {
		return true
	}
	for _, sep := range []string{".", "-", "_", "+"} {
		if strings.HasPrefix(installed, typed+sep) {
			return true
		}
	}
	return false
}

// hasFlag reports whether args name flag before any "--", since a flag after it
// is a positional argument.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		// Go's flag package takes --json and -json, but a bare "json" is a
		// positional argument and must not switch the output on.
		if a == name || a == "-"+strings.TrimLeft(name, "-") {
			return true
		}
	}
	return false
}

// removeFail says why nothing was removed, as JSON when that was asked for, so
// a caller reading stdout never has to parse prose.
func (env Env) removeFail(asJSON bool, ref, version, reason string, code int) int {
	if asJSON {
		env.printJSON(RemoveResult{Package: ref, Version: version, Error: reason})
		return code
	}
	fmt.Fprintln(env.Err, reason)
	return code
}

// joinArgs prints argv quoted the way a shell would need it, so the dry run
// line can be copied and still be the one command kho would run.
func joinArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && strings.IndexFunc(a, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%_+=:,./-", r))
		}) < 0 {
			out[i] = a
			continue
		}
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(out, " ")
}

// removeMiss says why a ref did not resolve. A manager that failed or is not
// on this machine is not the same as a package that isn't installed, a version
// in the ref is a usage error rather than a missing package, and a name that is
// installed under another manager is worth naming.
func (env Env) removeMiss(ref string, packages []provider.Package, errs map[string]string) (string, int) {
	source, name, _ := strings.Cut(ref, "/")
	manager := provider.ProviderOf(provider.Package{Source: source})
	if why := errs[manager]; why != "" {
		return source + " could not be read: " + why, ExitError
	}
	if why := env.Skipped[manager]; why != "" {
		return source + " is not on this machine (" + why + ")", ExitError
	}
	// A scoped npm name carries an @ of its own, so the version is the last one.
	if at := strings.LastIndex(ref, "@"); at > 0 {
		base, suffix := ref[:at], ref[at+1:]
		if p, err := find(packages, base); err == nil {
			// Homebrew names carry an @ of their own (node@24, python@3.12), so
			// a suffix that is not the installed version is part of the name,
			// and naming the base would point at a different package.
			if (p.Version != "" && sameVersion(p.Version, suffix)) || (source != "brew" && source != "cask") {
				return "remove takes the installed version, so leave @version off: kho remove " + base, ExitUsage
			}
		}
	}
	for _, other := range packages {
		if other.Name == name && other.Source != source {
			return fmt.Sprintf("%s is installed as %s/%s, not %s/%s", name, other.Source, other.Name, source, name), ExitUsage
		}
	}
	return ref + " is not installed", ExitError
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
	if p.Source == "go" && env.Major != nil {
		if path := env.Major(ctx, p.Origin, version); path != "" {
			return fmt.Errorf("%s has no published version %q in %s, but %s does; kho cannot install across a major module yet",
				p.Name, version, p.Origin, path)
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

// ListedPackage is a package as `kho list` prints it: the package itself, and
// the status word the table shows, so a caller does not have to infer it.
type ListedPackage struct {
	provider.Package
	Status string `json:"status"`
}

func (env Env) list() int {
	pkgs, errs := env.inventory(context.Background())
	if pkgs == nil {
		pkgs = []provider.Package{}
	}
	listed := make([]ListedPackage, 0, len(pkgs))
	for _, p := range pkgs {
		listed = append(listed, ListedPackage{Package: p, Status: provider.StatusWord(p)})
	}
	env.printJSON(listed)
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
		if len(s) > history.MaxOutput {
			s = s[len(s)-history.MaxOutput:]
		}
		return s, err
	}
}
