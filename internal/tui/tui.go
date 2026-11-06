package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

func Run(log *history.Log, version string) error {
	ready, _ := provider.Detect()
	m := newModel(ready, vuln.Path())
	m.log, m.version = log, version
	m.themePath = filepath.Join(filepath.Dir(history.Path()), "theme")
	if name, err := os.ReadFile(m.themePath); err == nil {
		if t, ok := themeNamed(strings.TrimSpace(string(name))); ok {
			th, m.themePicked = t, true
		}
	}
	return serve(m, listen(), os.Stderr)
}

// listen hears the signals that would end kho. Bubble Tea quits on the
// first SIGINT or SIGTERM, ignores them while a command runs in the
// terminal, and then stops listening, and Go's default for SIGHUP, as when
// the terminal closes, kills kho on the spot. Listening to all three for as
// long as kho runs keeps a later signal from killing it before an install
// is stopped and logged.
func listen() chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return sigs
}

// ErrHangup is what Run returns when the terminal went away, so kho can
// exit the way a hung-up program does.
var ErrHangup = errors.New("the terminal hung up")

// serve runs the program until it quits, which a hangup on sigs makes it
// do, then stops an install still running and waits until it is logged.
func serve(m tea.Model, sigs <-chan os.Signal, stderr io.Writer, opts ...tea.ProgramOption) error {
	p := tea.NewProgram(m, opts...)
	var hung atomic.Bool
	go func() {
		for s := range sigs {
			if s == syscall.SIGHUP {
				hung.Store(true)
				p.Quit()
			}
		}
	}()
	_, err := p.Run()
	if hung.Load() {
		err = ErrHangup
	}
	live.Lock()
	live.leaving = true
	in := live.in
	live.Unlock()
	if in != nil {
		select {
		case <-in.logged:
		default:
			fmt.Fprintf(stderr, "kho: stopping %s\n", strings.Join(in.cmd.Args, " "))
			in.finish(5 * time.Second)
		}
	}
	return err
}

const (
	focusRail = iota
	focusTable
	focusSide
)

const (
	tabInfo = iota
	tabVersions
	tabSecurity
	tabSkill
	tabReadme
	tabLinks
)

var tabNames = map[int]string{tabInfo: "Info", tabVersions: "Versions", tabSecurity: "Security", tabSkill: "Skill", tabReadme: "Readme", tabLinks: "Links"}

const (
	colName = iota
	colSource
	colVersion
	colLatest
	colStatus
)

type listedMsg struct {
	name string
	pkgs []provider.Package
	err  error
}

type checkedMsg listedMsg

type depsMsg struct {
	key  string
	deps []provider.Dep
	err  error
}

type versionsMsg struct {
	key  string
	rels []provider.Release
	err  error
}

type docMsg struct {
	key string
	doc provider.SkillDoc
	err error
}

type scanMsg struct {
	hits       map[string][]string
	advisories map[string]vuln.Advisory
	err        error
}

type historyMsg struct {
	ecosystem, name string
	advisories      []vuln.Advisory
	err             error
}

type auditMsg struct {
	asked  map[string][]string
	audits map[string]vuln.SkillAudit
	err    error
}

type openedMsg struct {
	url string
	err error
}

type tickMsg struct{}

type lazy[T any] struct {
	val  T
	err  error
	done bool
}

// depAdvisory is an advisory against one of a package's dependencies.
type depAdvisory struct {
	dep provider.Dep
	adv vuln.Advisory
}

type model struct {
	providers []provider.Provider
	pkgs      map[string][]provider.Package
	busy      map[string]string
	errs      map[string]error
	deps      map[string]*lazy[[]provider.Dep]
	versions  map[string]*lazy[[]provider.Release]
	docs      map[string]*lazy[provider.SkillDoc]
	// links are the selected skill's agents as the Links tab lists them,
	// read again by readLinks when linksOf stops naming the selection.
	links   []provider.SkillLink
	linksOf string

	db       *vuln.DB
	dbPath   string
	scanning int
	secErr   error
	advising map[string]bool
	log      *history.Log
	vulns    map[string][]vuln.Advisory
	depVulns map[string][]depAdvisory

	focus int
	tab   int
	rail  int
	// railTop is the first rail row shown when the rows don't all fit.
	railTop int
	cursor  int
	offset  int
	// picked is whether the person has done anything since kho started or
	// rescanned. Until then the cursor stays on the first row as the
	// sources answer; after, it stays on the package they are looking at.
	picked     bool
	selected   string
	sidePart   int
	sideCursor int
	sideOffset int
	bodyOffset int

	sortCol   int
	sortDesc  bool
	filters   map[string]string
	statuses  map[string]int
	filtering bool
	showDeps  bool
	help      bool
	helpTop   int
	confirm   *confirm
	inst      *installing
	depCursor int
	depPop    *depPopup
	allAgents bool
	sel       *textSel
	railW     int
	sideW     int
	split     int
	resizing  int
	grab      int

	version     string
	themePath   string
	themePicked bool

	showHistory bool
	hCursor     int
	hOffset     int
	hKind       int
	hFilter     string
	notice      string
	frame       int
	ticking     bool
	width       int
	height      int
	md          *mdCache
}

var openURL = func(url string) error {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	return exec.Command(opener, url).Start()
}

var now = time.Now

// The network lookups, swapped out in tests.
var (
	scanOSV      = vuln.Scan
	fetchHistory = vuln.History
	fetchAudits  = vuln.SkillAudits
)

func newModel(ps []provider.Provider, dbPath string) model {
	m := model{providers: ps, focus: focusTable, sortCol: colSource, dbPath: dbPath, db: vuln.Load(dbPath), md: newMDCache(), ticking: true, log: history.Open(""), version: "dev",
		filters: map[string]string{}, statuses: map[string]int{}}
	m.reset()
	return m
}

// Init lists every provider and starts the spinner, which newModel already
// counts as ticking.
func (m model) Init() tea.Cmd {
	return tea.Batch(m.scan(), tick(), tea.RequestBackgroundColor)
}

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model) reset() {
	m.pkgs = map[string][]provider.Package{}
	m.busy = map[string]string{}
	m.errs = map[string]error{}
	m.deps = map[string]*lazy[[]provider.Dep]{}
	m.versions = map[string]*lazy[[]provider.Release]{}
	m.docs = map[string]*lazy[provider.SkillDoc]{}
	m.advising = map[string]bool{}
	m.picked = false
	for _, p := range m.providers {
		m.busy[p.Name()] = "listing"
	}
	m.reindex()
}

// relist scans one provider again after kho changed something it manages.
func (m *model) relist(name string) tea.Cmd {
	p := m.provider(name)
	if p == nil {
		return nil
	}
	m.busy[name] = "listing"
	return func() tea.Msg {
		pkgs, err := p.List(context.Background())
		return listedMsg{name, pkgs, err}
	}
}

// forget drops the dependencies and releases kho loaded for a provider's
// packages, which a new listing can change while a package's own version
// stays: a brew formula's dependencies have versions of their own, and its
// newest version can move. A load still on its way for an older version
// lands under that version's key, never on the new one.
func (m *model) forget(name string) {
	for _, p := range m.pkgs[name] {
		delete(m.deps, cacheKey(p))
		delete(m.versions, cacheKey(p))
	}
}

func (m model) scan() tea.Cmd {
	var cmds []tea.Cmd
	for _, p := range m.providers {
		cmds = append(cmds, func() tea.Msg {
			pkgs, err := p.List(context.Background())
			return listedMsg{p.Name(), pkgs, err}
		})
	}
	return tea.Batch(cmds...)
}

func (m model) working() bool {
	return len(m.busy) > 0 || m.scanning > 0 || m.inst.running()
}

// startTicking runs the spinner while something is loading.
func (m *model) startTicking() tea.Cmd {
	if m.ticking {
		return nil
	}
	m.ticking = true
	return tick()
}

func (m model) provider(name string) provider.Provider {
	for _, p := range m.providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func pkgKey(p provider.Package) string {
	return p.Source + "\x00" + p.Name
}

// cacheKey names what kho loaded about one version of a package: its
// dependencies, releases and skill files.
func cacheKey(p provider.Package) string {
	return pkgKey(p) + "\x00" + p.Version
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg.(type) {
	case tea.KeyPressMsg, tea.PasteMsg, tea.MouseClickMsg, tea.MouseWheelMsg:
		m.picked = true
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.BackgroundColorMsg:
		if !m.themePicked {
			th = defaultTheme(msg.IsDark())
		}
	case tickMsg:
		m.frame++
		m.ticking = m.working()
		if m.ticking {
			cmds = append(cmds, tick())
		}
	case listedMsg:
		m.forget(msg.name)
		m.pkgs[msg.name] = msg.pkgs
		if msg.name == "skills" {
			m.linksOf = ""
		}
		if msg.err != nil {
			m.errs[msg.name] = msg.err
			delete(m.busy, msg.name)
			break
		}
		m.busy[msg.name] = "checking"
		p, pkgs := m.provider(msg.name), slices.Clone(msg.pkgs)
		cmds = append(cmds, func() tea.Msg {
			pkgs, err := p.Latest(context.Background(), pkgs)
			return checkedMsg{p.Name(), pkgs, err}
		}, m.secure(msg.pkgs, false))
		m.reindex()
	case checkedMsg:
		m.pkgs[msg.name] = msg.pkgs
		if msg.err != nil {
			m.errs[msg.name] = msg.err
		}
		delete(m.busy, msg.name)
		m.reindex()
	case depsMsg:
		m.deps[msg.key] = &lazy[[]provider.Dep]{msg.deps, msg.err, true}
	case versionsMsg:
		m.versions[msg.key] = &lazy[[]provider.Release]{msg.rels, msg.err, true}
	case docMsg:
		m.docs[msg.key] = &lazy[provider.SkillDoc]{msg.doc, msg.err, true}
	case scanMsg:
		m.scanning--
		m.secErr = msg.err
		if msg.err == nil {
			m.db.Merge(msg.hits, msg.advisories, now())
			m.save()
		}
		m.reindex()
	case historyMsg:
		delete(m.advising, msg.ecosystem+"/"+msg.name)
		if msg.err == nil {
			m.db.MergeHistory(msg.ecosystem, msg.name, msg.advisories, now())
			m.save()
		}
	case auditMsg:
		m.scanning--
		m.secErr = msg.err
		m.db.MergeAudits(msg.asked, msg.audits, msg.err, now())
		m.save()
		m.reindex()
	case installStartedMsg:
		m.inst = msg.installing
		cmds = append(cmds, m.inst.next(), m.startTicking())
	case outputMsg:
		m.inst.lines = msg
		cmds = append(cmds, m.inst.next())
	case installedMsg:
		// A rerun in the terminal comes back after its popup has closed.
		if m.inst != nil {
			m.inst.done, m.inst.end, m.inst.lines = &msg, now(), m.inst.screen()
		}
		m.notice = fmt.Sprintf("%s is now %s", msg.name, msg.version)
		if msg.err != nil {
			m.notice = fmt.Sprintf("%s %s failed: %v", msg.name, msg.version, msg.err)
		}
		cmds = append(cmds, m.relist(msg.provider))
	case linkedMsg:
		m.notice, m.linksOf = msg.done, ""
		if msg.err != nil {
			m.notice = msg.err.Error()
		}
		cmds = append(cmds, m.relist("skills"))
	case openedMsg:
		m.notice = "opened " + msg.url
		if msg.err != nil {
			m.notice = "could not open " + msg.url + ": " + msg.err.Error()
		}
	case tea.PasteMsg:
		if m.filtering {
			m.setFilter(m.filter() + strings.TrimSpace(msg.Content))
			m.cursor, m.offset = 0, 0
		}
	case tea.KeyPressMsg:
		cmd, quit := m.press(msg)
		if quit {
			return m, tea.Quit
		}
		cmds = append(cmds, cmd)
	case tea.MouseClickMsg:
		if msg.Button == tea.MouseLeft {
			cmds = append(cmds, m.click(msg.X, msg.Y))
		}
	case tea.MouseMotionMsg:
		switch {
		case m.resizing != resizeNone:
			m.resize(msg.X, msg.Y)
		case msg.Button == tea.MouseLeft:
			m.dragSelect(msg.X, msg.Y)
		}
	case tea.MouseReleaseMsg:
		if m.resizing != resizeNone {
			m.resizing = resizeNone
			break
		}
		cmds = append(cmds, m.endSelect(msg.X, msg.Y))
	case tea.MouseWheelMsg:
		switch msg.Button {
		case tea.MouseWheelUp:
			m.wheel(msg.X, msg.Y, -1)
		case tea.MouseWheelDown:
			m.wheel(msg.X, msg.Y, 1)
		}
	}
	switch msg.(type) {
	case listedMsg, checkedMsg, scanMsg, auditMsg:
		if m.picked {
			m.reselect()
		}
	}
	m.clamp()
	cmds = append(cmds, m.load())
	if m.working() {
		cmds = append(cmds, m.startTicking())
	}
	return m, tea.Batch(cmds...)
}

func (m model) save() {
	if m.dbPath != "" {
		m.db.Save(m.dbPath)
	}
}

// secure asks OSV about the packages and dependencies whose results are
// missing or stale, and skills.sh about skills, unless force asks again.
func (m *model) secure(pkgs []provider.Package, force bool) tea.Cmd {
	var queries []vuln.Query
	audits := map[string][]string{}
	for _, p := range pkgs {
		if q, ok := provider.Query(p); ok {
			queries = append(queries, q)
		}
		queries = append(queries, provider.DepQueries(p)...)
		if p.Source == "skills" && p.Repo != "" {
			audits[p.Repo] = append(audits[p.Repo], p.Name)
		}
	}
	if !force {
		queries = m.db.Stale(queries, now())
		audits = m.db.StaleAudits(audits, now())
	}
	var cmds []tea.Cmd
	if len(queries) > 0 {
		m.scanning++
		known := map[string]bool{}
		for id := range m.db.Advisories {
			known[id] = true
		}
		cmds = append(cmds, func() tea.Msg {
			hits, advs, err := scanOSV(context.Background(), queries, known)
			return scanMsg{hits, advs, err}
		})
	}
	if len(audits) > 0 {
		m.scanning++
		cmds = append(cmds, func() tea.Msg {
			got, err := fetchAudits(context.Background(), audits)
			return auditMsg{audits, got, err}
		})
	}
	return tea.Batch(cmds...)
}

// reindex works out, from the security cache, which advisories affect each
// installed package and its dependencies.
func (m *model) reindex() {
	m.vulns = map[string][]vuln.Advisory{}
	m.depVulns = map[string][]depAdvisory{}
	for _, pkgs := range m.pkgs {
		for _, p := range pkgs {
			if q, ok := provider.Query(p); ok {
				if advs := m.db.For(q); len(advs) > 0 {
					m.vulns[pkgKey(p)] = advs
				}
			}
			for _, d := range p.Deps {
				advs, _ := m.depAdvisories(p, d)
				for _, a := range advs {
					m.depVulns[pkgKey(p)] = append(m.depVulns[pkgKey(p)], depAdvisory{d, a})
				}
			}
		}
	}
}

func (m model) audit(p provider.Package) (vuln.SkillAudit, bool) {
	a, ok := m.db.Audits[p.Repo+"/"+p.Name]
	return a, ok
}

// load fetches what the sidebar needs for the selected package, unless it is
// cached or already on the way.
func (m *model) load() tea.Cmd {
	p, ok := m.current()
	if !ok {
		return nil
	}
	prov, key := m.provider(provider.ProviderOf(p)), cacheKey(p)
	if prov == nil {
		return nil
	}
	var cmds []tea.Cmd
	tab := m.activeTab()
	if m.deps[key] == nil {
		m.deps[key] = &lazy[[]provider.Dep]{}
		cmds = append(cmds, func() tea.Msg {
			deps, err := prov.Deps(context.Background(), p)
			return depsMsg{key, deps, err}
		})
	}
	if tab == tabVersions && m.versions[key] == nil {
		m.versions[key] = &lazy[[]provider.Release]{}
		cmds = append(cmds, func() tea.Msg {
			rels, err := prov.Versions(context.Background(), p)
			return versionsMsg{key, rels, err}
		})
	}
	if (tab == tabSkill || tab == tabReadme) && m.docs[key] == nil {
		m.docs[key] = &lazy[provider.SkillDoc]{}
		cmds = append(cmds, func() tea.Msg {
			doc, err := provider.ReadSkill(p)
			return docMsg{key, doc, err}
		})
	}
	eco, name := provider.Ecosystem(p), provider.OSVName(p)
	hkey := eco + "/" + name
	if eco != "" && (tab == tabVersions || tab == tabSecurity) && !m.advising[hkey] && !m.db.HistoryFresh(eco, name, now()) {
		m.advising[hkey] = true
		cmds = append(cmds, func() tea.Msg {
			advs, err := fetchHistory(context.Background(), eco, name)
			return historyMsg{eco, name, advs, err}
		})
	}
	return tea.Batch(cmds...)
}

func (m *model) press(msg tea.KeyPressMsg) (tea.Cmd, bool) {
	key := msg.String()
	if key == "ctrl+c" {
		if m.inst.running() {
			m.inst.stop()
			return nil, false
		}
		return nil, true
	}
	switch m.popup() {
	case popHelp:
		switch key {
		case "?", "esc", "q", "enter":
			m.help = false
		case "up", "k":
			m.helpTop--
		case "down", "j":
			m.helpTop++
		}
		return nil, false
	case popInstall:
		in := m.inst
		switch {
		case in.running():
		case key == "enter" || key == "esc" || key == "q":
			m.inst = nil
		case key == "t" && in.phase() == instFailed:
			m.inst = nil
			done := *in.done
			return runExec(&terminalRun{cmd: again(in.cmd), log: m.log}, func(err error) tea.Msg {
				done.err = err
				return done
			}), false
		}
		return nil, false
	case popDep:
		switch key {
		case "esc", "enter", "q":
			m.depPop, m.sel = nil, nil
		case "up", "k":
			m.depPop.top--
		case "down", "j":
			m.depPop.top++
		case "c":
			if m.sel != nil {
				return m.copy(m.selectedText()), false
			}
			return m.copyArea(), false
		}
		return nil, false
	case popConfirm:
		c := m.confirm
		switch key {
		case "y", "enter":
			m.confirm = nil
			return c.run, false
		case "n", "esc", "q":
			m.confirm = nil
		}
		return nil, false
	}
	if m.filtering {
		m.typeFilter(key, msg.Text)
		return nil, false
	}
	if m.showHistory {
		if cmd, done := m.pressHistory(key); done {
			return cmd, false
		}
	}
	tabs := m.tabs()
	switch key {
	case "q":
		return nil, true
	case "?":
		m.help, m.helpTop = true, 0
	case "H":
		m.showHistory = true
	case "A":
		if m.activeTab() == tabLinks {
			m.allAgents, m.sideCursor, m.sideOffset, m.linksOf = !m.allAgents, 0, 0, ""
		}
	case "t":
		m.setTheme(themeIndex() + 1)
	case "T":
		m.setTheme(themeIndex() - 1)
	case "tab":
		m.focus = (m.focus + 1) % 3
	case "shift+tab":
		m.focus = (m.focus + 2) % 3
	case "left", "h":
		m.focus = max(m.focus-1, focusRail)
	case "right", "l":
		m.focus = min(m.focus+1, focusSide)
	case "/":
		m.filtering = true
	case "esc":
		if m.focus == focusSide && m.sidePart == 1 {
			m.sidePart = 0
		} else {
			m.setFilter("")
		}
	case "o":
		m.toggleStatus(statusOutdated)
	case "!":
		m.toggleStatus(statusVulnerable)
	case "f":
		m.setStatus(m.status() + 1)
	case "F":
		m.setStatus(m.status() - 1)
	case "d":
		m.showDeps = !m.showDeps
		m.cursor, m.offset = 0, 0
	case "s":
		m.sortCol = (m.sortCol + 1) % 5
	case "S":
		m.sortDesc = !m.sortDesc
	case "c":
		return m.copyArea(), false
	case "<":
		m.grow(-2)
	case ">":
		m.grow(2)
	case "{":
		m.moveSplit(-1)
	case "}":
		m.moveSplit(1)
	case "=":
		m.railW, m.sideW, m.split = 0, 0, 0
	case "1", "2", "3", "4", "5", "6":
		if i := int(key[0] - '1'); i < len(tabs) {
			m.setTab(tabs[i])
		}
	case "i":
		m.setTab(tabInfo)
	case "v":
		m.setTab(tabVersions)
	case "a":
		m.setTab(tabSecurity)
	case "]":
		m.setTab(tabs[(slices.Index(tabs, m.activeTab())+1)%len(tabs)])
	case "[":
		m.setTab(tabs[(slices.Index(tabs, m.activeTab())+len(tabs)-1)%len(tabs)])
	case "J", "ctrl+d":
		m.scrollDetail(map[string]int{"J": 1, "ctrl+d": m.layout().bottomRows / 2}[key])
	case "K", "ctrl+u":
		m.scrollDetail(-map[string]int{"K": 1, "ctrl+u": m.layout().bottomRows / 2}[key])
	case "w":
		return m.openHome(), false
	case "y":
		return m.openReleasePage(), false
	case "r":
		m.reset()
		return m.scan(), false
	case "R":
		var all []provider.Package
		for _, pkgs := range m.pkgs {
			all = append(all, pkgs...)
		}
		m.notice = "refreshing security data"
		return m.secure(all, true), false
	default:
		m.move(key)
	}
	return nil, false
}

const (
	popNone = iota
	popHelp
	popInstall
	popDep
	popConfirm
)

// popup names the dialog on top. It takes every key, click and turn of the
// wheel until it closes, so press, click, wheel, View and the footer all ask
// it which one that is.
func (m model) popup() int {
	switch {
	case m.help:
		return popHelp
	case m.inst != nil:
		return popInstall
	case m.depPop != nil:
		return popDep
	case m.confirm != nil:
		return popConfirm
	}
	return popNone
}

// setTheme switches to the i-th theme and remembers it for next time.
func (m *model) setTheme(i int) {
	th = themes[(i+len(themes))%len(themes)]
	m.themePicked = true
	m.notice = "theme: " + th.name
	if m.themePath != "" {
		os.MkdirAll(filepath.Dir(m.themePath), 0o755)
		os.WriteFile(m.themePath, []byte(th.name+"\n"), 0o644)
	}
}

func (m *model) setTab(t int) {
	if t != m.activeTab() {
		m.tab, m.sel = t, nil
		m.sidePart, m.sideCursor, m.sideOffset, m.bodyOffset, m.depCursor = 0, 0, 0, 0, 0
	}
}

// move handles the keys that act on the focused panel.
func (m *model) move(key string) {
	page := max(m.layout().rows-1, 1)
	step := map[string]int{"up": -1, "k": -1, "down": 1, "j": 1, "pgup": -page, "pgdown": page, "space": page}[key]
	switch m.focus {
	case focusRail:
		switch key {
		case "enter":
			m.focus = focusTable
		case "home", "g":
			m.setRail(0)
		case "end", "G":
			m.setRail(len(m.railRows()) - 1)
		default:
			m.setRail(m.rail + step)
		}
	case focusTable:
		switch key {
		case "enter":
			m.focus = focusSide
		case "home", "g":
			m.cursor = 0
		case "end", "G":
			m.cursor = len(m.rows()) - 1
		default:
			m.cursor += step
		}
	case focusSide:
		m.moveSide(key, step)
	}
}

// moveSide scrolls the sidebar. In a list tab the arrows move through the
// list and enter acts on the selection: install a version, toggle a link, or
// step down into an advisory.
func (m *model) moveSide(key string, step int) {
	list := m.sideListLen() >= 0
	switch {
	case key == "enter" && list && m.sidePart == 0:
		switch m.activeTab() {
		case tabVersions:
			m.askInstall()
		case tabLinks:
			m.askLink()
		default:
			m.sidePart = 1
		}
	case key == "enter" && m.depList() != nil:
		m.openDep(m.depCursor)
	case key == "enter":
		m.sidePart = 0
	case key == "home" || key == "g":
		m.sideCursor, m.sideOffset, m.bodyOffset, m.depCursor = 0, 0, 0, 0
	case list && m.sidePart == 0:
		m.sideCursor += step
		m.bodyOffset = 0
	case m.depList() != nil:
		m.depCursor += step
	case m.hasBottom():
		m.bodyOffset += step
	default:
		m.sideOffset += step
	}
}

// scrollDetail scrolls the sidebar's reading area: the bottom half, or the
// whole sidebar for a tab that has no bottom. A dependency list scrolls with
// its cursor, so the cursor moves instead.
func (m *model) scrollDetail(n int) {
	n = max(abs(n), 1) * sign(n)
	switch {
	case m.depList() != nil:
		m.depCursor += n
	case m.hasBottom():
		m.bodyOffset += n
	default:
		m.sideOffset += n
	}
}

func abs(n int) int { return max(n, -n) }

func sign(n int) int {
	if n < 0 {
		return -1
	}
	return 1
}

func (m *model) typeFilter(key, text string) {
	f := m.filter()
	switch key {
	case "esc":
		f, m.filtering = "", false
	case "enter":
		m.filtering = false
	case "backspace":
		if f != "" {
			f = f[:len(f)-1]
		}
	default:
		f += text
	}
	m.setFilter(f)
	m.cursor, m.offset = 0, 0
}

func open(url string) tea.Cmd {
	return func() tea.Msg { return openedMsg{url, openURL(url)} }
}

func (m *model) openHome() tea.Cmd {
	p, ok := m.current()
	if !ok {
		return nil
	}
	if u := homeURL(p); u != "" {
		return open(u)
	}
	m.notice = "no homepage known for " + p.Name
	return nil
}

func homeURL(p provider.Package) string {
	switch {
	case p.Homepage != "":
		return p.Homepage
	case p.Repo != "":
		return "https://github.com/" + p.Repo
	case p.Source == "npm":
		return "https://www.npmjs.com/package/" + p.Name
	case p.Source == "pipx", p.Source == "uv":
		return "https://pypi.org/project/" + p.Name + "/"
	case p.Source == "go":
		return "https://pkg.go.dev/" + p.Origin
	}
	return ""
}

// openReleasePage opens the selected version's page when kho has no notes
// to show for it.
func (m *model) openReleasePage() tea.Cmd {
	if m.activeTab() != tabVersions {
		return nil
	}
	r, ok := at(m.currentVersions(), m.sideCursor)
	if !ok || r.URL == "" {
		return nil
	}
	return open(r.URL)
}

// clamp pulls every cursor and offset back in range after a move. The
// package cursor goes first, since the layout and the links depend on what
// it selects.
func (m *model) clamp() {
	m.clampHistory()
	m.cursor = max(min(m.cursor, len(m.rows())-1), 0)
	l := m.layout()
	m.railTop = scroll(m.railTop, m.rail, l.bodyH-2)
	m.offset = scroll(m.offset, m.cursor, l.rows)
	if p, ok := m.current(); ok && pkgKey(p) != m.selected {
		m.selected, m.sel = pkgKey(p), nil
		m.sidePart, m.sideCursor, m.sideOffset, m.bodyOffset, m.depCursor = 0, 0, 0, 0, 0
	}
	m.readLinks()
	if n := m.sideListLen(); n >= 0 {
		m.sideCursor = max(min(m.sideCursor, n-1), 0)
		m.sideOffset = scroll(m.sideOffset, m.sideCursor, l.topRows-1)
	} else {
		m.sideOffset = max(m.sideOffset, 0)
	}
	m.bodyOffset = max(m.bodyOffset, 0)
	m.helpTop = max(min(m.helpTop, m.helpHidden()), 0)
	if deps := m.depList(); deps != nil {
		m.depCursor = max(min(m.depCursor, len(deps)-1), 0)
		m.bodyOffset = scroll(m.bodyOffset, m.depCursor, l.bottomRows)
	}
	if m.depPop != nil {
		m.depPop.top = max(min(m.depPop.top, len(m.depPopView())-popupText(m.depRect()).h), 0)
	}
}

// reselect puts the cursor back on the selected package after a listing or a
// security result has added or moved rows. The cursor is a row number, so
// otherwise it would land on whichever package took that row.
func (m *model) reselect() {
	for i, p := range m.rows() {
		if pkgKey(p) == m.selected {
			m.cursor = i
			return
		}
	}
}

// at is s[i], or false when i is out of range.
func at[T any](s []T, i int) (T, bool) {
	if i < 0 || i >= len(s) {
		var zero T
		return zero, false
	}
	return s[i], true
}

// scroll keeps cursor inside a window of h rows that starts at offset.
func scroll(offset, cursor, h int) int {
	if cursor < offset {
		return cursor
	}
	if h > 0 && cursor >= offset+h {
		return cursor - h + 1
	}
	return offset
}

func (m model) current() (provider.Package, bool) {
	return at(m.rows(), m.cursor)
}

func (m model) tabs() []int {
	if p, ok := m.current(); ok && p.Source == "skills" {
		return []int{tabInfo, tabVersions, tabSkill, tabReadme, tabLinks, tabSecurity}
	}
	return []int{tabInfo, tabVersions, tabSecurity}
}

func (m model) activeTab() int {
	if slices.Contains(m.tabs(), m.tab) {
		return m.tab
	}
	return tabInfo
}

func (m model) currentDeps() []provider.Dep {
	p, ok := m.current()
	if !ok || m.deps[cacheKey(p)] == nil {
		return nil
	}
	return m.deps[cacheKey(p)].val
}

func (m model) currentVersions() []provider.Release {
	p, ok := m.current()
	if !ok || m.versions[cacheKey(p)] == nil {
		return nil
	}
	return m.versions[cacheKey(p)].val
}

// visible applies the dependency, status and keyword filters.
func (m model) visible(pkgs []provider.Package) []provider.Package {
	var out []provider.Package
	for _, p := range pkgs {
		switch {
		case m.hiddenDep(p):
		case !m.matchStatus(p):
		case m.filter() != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(m.filter())):
		default:
			out = append(out, p)
		}
	}
	return out
}

func (m model) rows() []provider.Package {
	rows := m.visible(m.rowPkgs(m.curRow()))
	m.sort(rows)
	return rows
}
