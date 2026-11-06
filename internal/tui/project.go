package tui

import (
	"cmp"
	"context"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/vuon9/kho/internal/project"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

// projKey files the project's packages in m.pkgs. No provider has this name.
const projKey = "\x00project"

// The project lookups, swapped out in tests.
var (
	findProject   = project.Find
	projectLatest = provider.FillLatest
	watchEvery    = 3 * time.Second
)

const (
	projReading  = "reading lockfiles"
	projChecking = "checking"
)

type projectMsg struct {
	gen  int
	scan project.Scan
	err  error
}

type projectLatestMsg struct {
	gen  int
	pkgs []provider.Package
}

type watchMsg struct {
	gen     int
	changed bool
}

// findCmd reads the project's lockfiles. gen tells its answer apart from one
// for a scan that has since been started again.
func (m model) findCmd() tea.Cmd {
	gen, dir := m.projGen, m.dir
	return func() tea.Msg {
		scan, err := findProject(context.Background(), dir)
		return projectMsg{gen, scan, err}
	}
}

// scanProject reads the project again, as when a lockfile changed.
func (m *model) scanProject() tea.Cmd {
	if m.dir == "" {
		return nil
	}
	m.projGen++
	m.projBusy = projReading
	return m.findCmd()
}

func (m *model) gotProject(msg projectMsg) tea.Cmd {
	if msg.gen != m.projGen {
		return nil
	}
	m.proj, m.projErr = &msg.scan, msg.err
	var pkgs []provider.Package
	for _, p := range msg.scan.Projects {
		for _, lf := range p.Lockfiles {
			pkgs = append(pkgs, lf.Packages...)
		}
	}
	m.forget(projKey)
	m.pkgs[projKey] = pkgs
	m.projStamps = stamps(msg.scan)
	m.reindex()
	if len(pkgs) == 0 {
		m.projBusy = ""
		return m.watch()
	}
	m.projBusy = projChecking
	gen, latest := m.projGen, slices.Clone(pkgs)
	return tea.Batch(func() tea.Msg {
		return projectLatestMsg{gen, projectLatest(context.Background(), latest)}
	}, m.secure(pkgs, false), m.watch())
}

func (m *model) gotProjectLatest(msg projectLatestMsg) {
	if msg.gen != m.projGen {
		return
	}
	m.pkgs[projKey] = msg.pkgs
	m.projBusy = ""
	m.reindex()
}

// lockfileOf is the lockfile a manager writes, which a manifest without one
// is waiting for.
var lockfileOf = map[string]string{
	"npm": "package-lock.json", "composer": "composer.lock", "uv": "uv.lock",
	"poetry": "poetry.lock", "cargo": "Cargo.lock",
}

// stamps are the modification times of every lockfile the scan read, and of
// the lockfile each bare manifest is missing, so creating one counts too.
func stamps(scan project.Scan) map[string]time.Time {
	out := map[string]time.Time{}
	for _, p := range scan.Projects {
		for _, lf := range p.Lockfiles {
			file := lf.Path
			if lf.Missing != "" {
				name, ok := lockfileOf[lf.Manager]
				if !ok {
					continue
				}
				file = path.Join(path.Dir(lf.Path), name)
			}
			out[file] = modTime(filepath.Join(scan.Root, filepath.FromSlash(file)))
		}
	}
	return out
}

func modTime(file string) time.Time {
	fi, err := os.Stat(file)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// watch looks at the lockfiles again in a while, and says whether any changed.
func (m model) watch() tea.Cmd {
	if m.proj == nil || len(m.projStamps) == 0 {
		return nil
	}
	gen, root, was := m.projGen, m.proj.Root, m.projStamps
	return tea.Tick(watchEvery, func(time.Time) tea.Msg {
		now := map[string]time.Time{}
		for file := range was {
			now[file] = modTime(filepath.Join(root, filepath.FromSlash(file)))
		}
		return watchMsg{gen, !maps.Equal(was, now)}
	})
}

func (m *model) gotWatch(msg watchMsg) tea.Cmd {
	switch {
	case msg.gen != m.projGen:
		return nil
	case msg.changed:
		return m.scanProject()
	}
	return m.watch()
}

// projName is the folder the project section is named after.
func (m model) projName() string {
	if m.proj != nil {
		return filepath.Base(m.proj.Root)
	}
	return filepath.Base(m.dir)
}

// projReady says the project section has something to select.
func (m model) projReady() bool {
	return m.proj != nil && m.projBusy != projReading && len(m.proj.Projects) > 0
}

func (m model) projPkgs() []provider.Package { return m.pkgs[projKey] }

// projParts are the rows under the project header: one per lockfile when
// there is one project, one per project folder when there are several.
func (m model) projParts() []railRow {
	if !m.projReady() {
		return nil
	}
	var rows []railRow
	if len(m.proj.Projects) == 1 {
		lfs := m.proj.Projects[0].Lockfiles
		for _, lf := range lfs {
			name := lf.Manager
			if slices.ContainsFunc(lfs, func(o project.Lockfile) bool { return o.Manager == lf.Manager && o.Path != lf.Path }) {
				name += " " + path.Base(lf.Path)
			}
			rows = append(rows, railRow{kind: rowPart, name: name, icon: lf.Manager, key: "project:" + lf.Path, lockfile: lf.Path})
		}
		return rows
	}
	for _, p := range m.proj.Projects {
		rows = append(rows, railRow{kind: rowPart, name: cmp.Or(p.Dir, "."), icon: "folder", key: "project:" + p.Dir + "/", dir: p.Dir, inDir: true})
	}
	return rows
}

// partPkgs is what one row under the project header stands for.
func (m model) partPkgs(r railRow) []provider.Package {
	var out []provider.Package
	for _, p := range m.projPkgs() {
		if r.lockfile != "" && p.Lockfile == r.lockfile || r.inDir && dirOf(p.Lockfile) == r.dir {
			out = append(out, p)
		}
	}
	return out
}

func dirOf(file string) string {
	if d := path.Dir(file); d != "." {
		return d
	}
	return ""
}

// lockfile is the scan's entry for path, for its note or error.
func (m model) lockfile(file string) (project.Lockfile, bool) {
	if m.proj == nil {
		return project.Lockfile{}, false
	}
	for _, p := range m.proj.Projects {
		for _, lf := range p.Lockfiles {
			if lf.Path == file {
				return lf, true
			}
		}
	}
	return project.Lockfile{}, false
}

// projectFix is the command that clears p's advisories in its project: to
// the lowest version that fixes them all, or to the latest when it is clear.
func (m model) projectFix(p provider.Package) string {
	advs := m.vulns[pkgKey(p)]
	if p.Lockfile == "" || len(advs) == 0 {
		return ""
	}
	target := fixFor(advs, p.Version)
	if target == "" && p.Latest != "" && !slices.ContainsFunc(advs, func(a vuln.Advisory) bool { return a.Affects(p.Latest) }) {
		target = p.Latest
	}
	if target == "" {
		return ""
	}
	return project.FixCommand(p, target)
}

// versionsFrom is where a project package's versions come from. These read
// registries, not the project, so the machine needn't have the manager.
func versionsFrom(p provider.Package) provider.Provider {
	switch p.Source {
	case "npm":
		return provider.Npm{}
	case "composer":
		return provider.Composer{}
	case "go":
		return provider.GoBin{}
	case "uv", "poetry", "pip":
		return provider.Pipx{}
	}
	return nil
}
