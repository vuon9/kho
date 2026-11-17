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
	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/project"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/trivy"
	"github.com/vuon9/kho/internal/vuln"
)

func Run(log *history.Log, version, dir string, ask image.Asker) error {
	ready, _ := provider.Detect()
	m := newModel(ready, vuln.Path())
	m.log, m.version, m.dir, m.imgAsk = log, version, dir, ask
	// The docker row is part of the sidebar from the first frame, the way a
	// provider's row is, and spins until its images are read.
	m.imgBusy = true
	if dir != "" {
		m.projBusy = projReading
	}
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

var ErrHangup = errors.New("the terminal hung up")

// A hangup on sigs quits the program; an install still running is stopped
// and logged before serve returns.
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

type skillDocDueMsg struct {
	gen int
	key string
}

// Swapped in tests.
var settleTick = tea.Tick

// So arrowing through results does not ask GitHub, or Homebrew, for each row.
const settleDelay = 300 * time.Millisecond

type brewCheckDueMsg struct {
	gen  int
	name string
}

type brewCheckMsg struct {
	name  string
	check brewCheck
	err   error
}

type scanMsg struct {
	hits       map[string][]string
	advisories map[string]vuln.Advisory
	err        error
}

// queries are the formulae the scan covered, so a formula with no findings is
// marked fresh too.
type brewScanMsg struct {
	result  vuln.BrewResult
	queries []vuln.Query
	err     error
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

type depAdvisory struct {
	dep provider.Dep
	adv vuln.Advisory
}

type model struct {
	providers    []provider.Provider
	pkgs         map[string][]provider.Package
	busy         map[string]string
	errs         map[string]error
	deps         map[string]*lazy[[]provider.Dep]
	versions     map[string]*lazy[[]provider.Release]
	docs         map[string]*lazy[provider.SkillDoc]
	brewChecks   map[string]*lazy[brewCheck]
	brewCheckFor string
	brewCheckGen int
	// Read again by readLinks when linksOf stops naming the selection.
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
	// A key, not an index, so the selection follows the row when rows above it
	// come and go.
	railKey string
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
	// skillDocGen drops the timer of a selection that moved on.
	skillDocFor string
	skillDocGen int

	sortCol  int
	sortDesc bool
	filters  map[string]string
	statuses map[string]int

	images       []image.Ref
	machineImgs  []image.Ref
	localImgs    []image.LocalImage
	factCh       <-chan imageFactMsg
	imgTags      map[string][]image.Tag
	imgVulns     map[string][]trivy.Vuln
	imgScanning  map[string]bool
	imgTagBusy   map[string]bool
	imgTagErr    map[string]string
	imgTagTried  map[string]bool
	imgUsers     map[string][]image.Container
	imgUsersBusy map[string]bool
	imgUsersErr  map[string]string
	imgSort      int
	imgScanErr   map[string]string
	// scanShown is the image whose Security tab is on screen, so a failed
	// scan is asked again when the tab opens, not on every redraw.
	scanShown string
	imgErr    error
	imgBusy   bool
	imgGen    int
	imgAsk    image.Asker
	// pulledImg is the image a Docker Hub pull just fetched, selected once it lists.
	pulledImg   string
	imgStatuses map[string]int
	filtering   bool
	// Nil in the installed mode. It never joins pkgs.
	search    *searchState
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

	version string
	// projGen counts scans, so an answer for an older one is dropped.
	dir         string
	proj        *project.Scan
	projErr     error
	projBusy    string
	projOpen    bool
	projGen     int
	projStamps  map[string]time.Time
	prodOnly    bool
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

// Swapped out in tests.
var (
	scanOSV      = vuln.Scan
	scanBrew     = provider.ScanBrewVulns
	scanFormula  = provider.ScanBrewFormula
	fetchHistory = vuln.History
	fetchAudits  = vuln.SkillAudits
)

func newModel(ps []provider.Provider, dbPath string) model {
	m := model{providers: ps, focus: focusTable, sortCol: colSource, dbPath: dbPath, db: vuln.Load(dbPath), md: newMDCache(), ticking: true, log: history.Open(""), version: "dev",
		filters: map[string]string{}, statuses: map[string]int{}, imgStatuses: map[string]int{},
		imgTags: map[string][]image.Tag{}, imgVulns: map[string][]trivy.Vuln{},
		imgScanning: map[string]bool{}, imgScanErr: map[string]string{}, imgTagBusy: map[string]bool{},
		imgTagErr:    map[string]string{},
		imgTagTried:  map[string]bool{},
		imgUsers:     map[string][]image.Container{},
		imgUsersBusy: map[string]bool{},
		imgUsersErr:  map[string]string{}}
	m.reset()
	return m
}

// newModel already counts the spinner as ticking.
func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.scan(), tick(), tea.RequestBackgroundColor, m.imagesCmd()}
	if m.projBusy == projReading {
		cmds = append(cmds, m.findCmd())
	}
	return tea.Batch(cmds...)
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
	m.brewChecks = map[string]*lazy[brewCheck]{}
	m.advising = map[string]bool{}
	m.picked = false
	for _, p := range m.providers {
		m.busy[p.Name()] = "listing"
	}
	m.reindex()
}

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
	return len(m.busy) > 0 || m.scanning > 0 || m.projBusy != "" || m.inst.running() || m.searchWorking() ||
		m.imgBusy || m.anyOf(m.imgTagBusy) || m.anyOf(m.imgScanning) || m.anyOf(m.imgUsersBusy) || m.anyOf(m.advising) ||
		loading(m.deps) || loading(m.versions) || loading(m.docs)
}

func loading[T any](set map[string]*lazy[T]) bool {
	for _, l := range set {
		if !l.done {
			return true
		}
	}
	return false
}

func (m model) anyOf(set map[string]bool) bool {
	for _, on := range set {
		if on {
			return true
		}
	}
	return false
}

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
	// A lockfile can hold two versions of one package, and two lockfiles the
	// same one, so a project package is known by all three.
	if p.Lockfile != "" {
		return p.Lockfile + "\x00" + p.Name + "\x00" + p.Version
	}
	return p.Source + "\x00" + p.Name
}

func cacheKey(p provider.Package) string {
	return pkgKey(p) + "\x00" + p.Version
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	if mm, ok := next.(model); ok {
		if ask := mm.wantTags(); ask != nil {
			cmd = tea.Batch(cmd, ask)
		}
		if ask := mm.wantUsers(); ask != nil {
			cmd = tea.Batch(cmd, ask)
		}
	}
	return next, cmd
}

func (m model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
	case imageTagsMsg:
		delete(m.imgTagBusy, msg.key)
		if msg.err != nil {
			m.imgTagErr[msg.key] = msg.err.Error()
			if m.imgTagTried[msg.key] {
				return m, nil
			}
			m.imgTagTried[msg.key] = true
			key := msg.key
			return m, tea.Tick(1500*time.Millisecond, func(time.Time) tea.Msg {
				return imageTagsRetryMsg{key: key}
			})
		}
		delete(m.imgTagErr, msg.key)
		switch {
		case len(msg.tags) > 0:
			m.imgTags[msg.key] = msg.tags
		case m.imgTags[msg.key] == nil:
			// An empty answer is still an answer, or the tab would ask again forever.
			m.imgTags[msg.key] = []image.Tag{}
		}
		if r, ok := m.currentImg(); ok && r.Canonical() == msg.key {
			m.pointAtSuggested()
		}
		return m, nil
	case imageUsersMsg:
		delete(m.imgUsersBusy, msg.key)
		if msg.err != nil {
			m.imgUsersErr[msg.key] = msg.err.Error()
			return m, nil
		}
		if msg.users == nil {
			msg.users = []image.Container{}
		}
		m.imgUsers[msg.key] = msg.users
		return m, nil
	case imageRemoveMsg:
		m.askImageRemove(msg)
		return m, nil
	case imageTagsRetryMsg:
		r, ok := m.currentImg()
		if !ok || r.Canonical() != msg.key || m.imgTags[msg.key] != nil || m.imgTagBusy[msg.key] {
			return m, nil
		}
		return m, m.tagsCmd()
	case imageScanMsg:
		m.imgScanning[msg.key] = false
		if msg.err != nil {
			m.imgScanErr[msg.key] = msg.err.Error()
		} else {
			delete(m.imgScanErr, msg.key)
			m.imgVulns[msg.key] = msg.vulns
		}
		return m, nil
	case imagesMsg:
		m.gotImages(msg)
		m.selectPulled()
		if msg.local != nil && msg.err == nil {
			return m, m.factsCmd()
		}
		return m, nil
	case imageFactMsg:
		m.applyFact(msg)
		m.selectPulled()
		if msg.gen != m.imgGen {
			return m, nil
		}
		return m, readFact(m.factCh, m.imgGen)
	case imageFactsDoneMsg:
		if msg.gen == m.imgGen {
			m.imgBusy = false
			m.reindex()
		}
		return m, nil
	case projectMsg:
		cmds = append(cmds, m.gotProject(msg))
	case projectLatestMsg:
		m.gotProjectLatest(msg)
	case watchMsg:
		cmds = append(cmds, m.gotWatch(msg))
	case depsMsg:
		m.deps[msg.key] = &lazy[[]provider.Dep]{msg.deps, msg.err, true}
	case versionsMsg:
		m.versions[msg.key] = &lazy[[]provider.Release]{msg.rels, msg.err, true}
	case searchMsg:
		m.gotSearch(msg)
	case findMsg:
		m.gotFind(msg)
	case docMsg:
		m.docs[msg.key] = &lazy[provider.SkillDoc]{msg.doc, msg.err, true}
	case brewCheckDueMsg:
		p, ok := m.current()
		if !ok || !m.inResults() || !m.isCandidate(p) || p.Source != "brew" ||
			msg.gen != m.brewCheckGen || msg.name != p.Name || m.brewChecks[p.Name] != nil {
			break
		}
		cmds = append(cmds, m.startBrewCheck(p.Name))
	case brewCheckMsg:
		m.brewChecks[msg.name] = &lazy[brewCheck]{msg.check, msg.err, true}
	case skillDocDueMsg:
		p, ok := m.current()
		if !ok || !m.inResults() || !m.isCandidate(p) || p.Source != "skills" ||
			msg.gen != m.skillDocGen || msg.key != cacheKey(p) {
			break
		}
		if m.docs[msg.key] != nil {
			break
		}
		m.docs[msg.key] = &lazy[provider.SkillDoc]{}
		cmds = append(cmds, func() tea.Msg {
			doc, err := provider.ReadRemoteSkill(context.Background(), p)
			return docMsg{msg.key, doc, err}
		})
	case scanMsg:
		m.scanning--
		m.secErr = msg.err
		if msg.err == nil {
			m.db.Merge(msg.hits, msg.advisories, now())
			m.save()
		}
		m.reindex()
	case brewScanMsg:
		m.scanning--
		switch {
		case errors.Is(msg.err, provider.ErrBrewVulnsUnsupported):
			m.db.SetBrewUnsupported(msg.err.Error(), now())
			m.save()
		case msg.err != nil:
			m.secErr = msg.err
		default:
			m.db.MergeBrew(msg.result, msg.queries, now())
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
		switch {
		case msg.err != nil && msg.removed:
			m.notice = fmt.Sprintf("%s was not removed: %v", msg.name, msg.err)
		case msg.err != nil:
			m.notice = fmt.Sprintf("%s %s failed: %v", msg.name, msg.version, msg.err)
		case msg.removed:
			m.notice = msg.name + " is removed"
		case msg.provider == "skills" && msg.version == provider.SkillNewest:
			m.notice = msg.name + " is installed"
		case msg.pulled:
			m.notice = "pulled " + msg.name
		default:
			m.notice = fmt.Sprintf("%s is now %s", msg.name, msg.version)
		}
		if msg.err == nil && !msg.removed {
			m.gotInstalled(msg)
		}
		if msg.err == nil && msg.pulled {
			m.pulledImg = image.Parse(msg.name).Canonical()
			if m.hubResults() {
				m.closeSearch()
			}
		}
		cmds = append(cmds, m.relist(msg.provider))
		if msg.provider == "docker" {
			m.imgGen++
			m.imgBusy = true
			cmds = append(cmds, m.imagesCmd())
		}
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
		switch {
		case m.filtering:
			m.setFilter(m.filter() + strings.TrimSpace(msg.Content))
			m.cursor, m.offset = 0, 0
		case m.search != nil && (m.search.mode == modePrompt || m.search.editing):
			m.search.draft += printablePaste(msg.Content)
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
	case listedMsg, checkedMsg, scanMsg, auditMsg, projectMsg, projectLatestMsg:
		if m.picked {
			m.reselect()
		}
	}
	m.clamp()
	cmds = append(cmds, m.load())
	if m.working() {
		cmds = append(cmds, m.startTicking())
	}
	if cmd := m.autoScan(); cmd != nil {
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

func (m model) save() {
	if m.dbPath != "" {
		m.db.Save(m.dbPath)
	}
}

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
	if brew := provider.BrewQueries(pkgs); len(brew) > 0 && scanBrew != nil && (force || len(m.db.Stale(brew, now())) > 0) {
		m.scanning++
		cmds = append(cmds, func() tea.Msg {
			result, err := scanBrew(context.Background())
			return brewScanMsg{result, brew, err}
		})
	}
	return tea.Batch(cmds...)
}

func securityQuery(p provider.Package) (vuln.Query, bool) {
	if q, ok := provider.Query(p); ok {
		return q, true
	}
	return provider.BrewQuery(p)
}

func (m model) coverage(p provider.Package) string {
	if p.Source != "brew" {
		return provider.Coverage(p)
	}
	if note := m.db.BrewNote(); note != "" {
		return note
	}
	return m.db.BrewSkip(p.Name)
}

func (m *model) reindex() {
	m.vulns = map[string][]vuln.Advisory{}
	m.depVulns = map[string][]depAdvisory{}
	for _, pkgs := range m.pkgs {
		for _, p := range pkgs {
			if q, ok := securityQuery(p); ok {
				if advs := m.db.For(q); len(advs) > 0 && m.coverage(p) == "" {
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
	a, ok := m.db.Audits[vuln.AuditKey(p.Repo, p.Name)]
	return a, ok
}

func (m *model) load() tea.Cmd {
	p, ok := m.current()
	if !ok {
		return nil
	}
	if !(m.inResults() && m.isCandidate(p) && p.Source == "skills") {
		m.skillDocFor = ""
	}
	if m.inResults() && m.isCandidate(p) {
		return m.loadCandidate(p)
	}
	prov, key := m.provider(provider.ProviderOf(p)), cacheKey(p)
	if p.Lockfile != "" {
		m.deps[key] = &lazy[[]provider.Dep]{val: m.pulledIn(p), done: true}
		if m.activeTab() == tabVersions && m.versions[key] == nil {
			m.versions[key] = &lazy[[]provider.Release]{}
			return func() tea.Msg {
				rels, err := projectVersions(context.Background(), p)
				return versionsMsg{key, rels, err}
			}
		}
		return nil
	}
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
	if (tab == tabSkill || tab == tabReadme || (tab == tabInfo && p.Source == "skills")) && m.docs[key] == nil {
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
	if m.search != nil {
		return m.pressSearch(key, msg)
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
	case "n":
		m.openSearch()
	case "esc":
		if m.focus == focusSide && m.sidePart == 1 {
			m.sidePart = 0
		} else {
			m.setFilter("")
		}
	case "o":
		if !isImageRow(m.curRow().kind) {
			m.toggleStatus(statusOutdated)
		}
	case "!":
		if !isImageRow(m.curRow().kind) {
			m.toggleStatus(statusVulnerable)
		}
	case "f":
		if m.curRow().kind == rowImages {
			m.cycleImgStatus()
			return nil, false
		}
		m.setStatus(m.status() + 1)
	case "F":
		if isImageRow(m.curRow().kind) {
			m.stepImgStatus(-1)
			return nil, false
		}
		m.setStatus(m.status() - 1)
	case "d":
		m.showDeps = !m.showDeps
		m.cursor, m.offset = 0, 0
	case "D":
		if isImageRow(m.curRow().kind) {
			return m.removeImage(), false
		}
		m.askRemove()
	case "p":
		m.prodOnly = !m.prodOnly
		m.cursor, m.offset = 0, 0
	case "s":
		if isImageRow(m.curRow().kind) {
			m.imgSort = (m.imgSort + 1) % len(imageColumns)
			m.cursor, m.offset = 0, 0
			return nil, false
		}
		m.sortCol = (m.sortCol + 1) % 5
	case "S":
		if isImageRow(m.curRow().kind) && m.imgSort == imgColFile {
			// file order has no reverse, so start from the name column
			m.imgSort, m.sortDesc = imgColName, true
			m.cursor, m.offset = 0, 0
			return nil, false
		}
		m.sortDesc = !m.sortDesc
	case "c":
		if p, ok := m.current(); ok && m.activeTab() == tabSecurity && m.projectFix(p) != "" {
			return m.copy(m.projectFix(p)), false
		}
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
			return m.tabTo(tabs[i]), false
		}
	case "i":
		m.setTab(tabInfo)
	case "v":
		return m.tabTo(tabVersions), false
	case "a":
		m.setTab(tabSecurity)
	case "]":
		return m.tabTo(tabs[(slices.Index(tabs, m.activeTab())+1)%len(tabs)]), false
	case "[":
		return m.tabTo(tabs[(slices.Index(tabs, m.activeTab())+len(tabs)-1)%len(tabs)]), false
	case "J", "ctrl+d":
		m.scrollDetail(map[string]int{"J": 1, "ctrl+d": m.layout().bottomRows / 2}[key])
	case "K", "ctrl+u":
		m.scrollDetail(-map[string]int{"K": 1, "ctrl+u": m.layout().bottomRows / 2}[key])
	case "w":
		if r, ok := m.currentImg(); ok && isImageRow(m.curRow().kind) {
			return m.copy(r.Image), false
		}
		return m.openHome(), false
	case "y":
		if r, ok := m.currentImg(); ok && isImageRow(m.curRow().kind) && m.imageTab() == tabVersions {
			if t, ok := at(m.sortedTags(r), m.sideCursor); ok {
				if u := tagURL(r, t.Name); u != "" {
					return open(u), false
				}
			}
			return nil, false
		}
		return m.openReleasePage(), false
	case "r":
		m.reset()
		m.imgGen++
		m.imgBusy = m.dir != ""
		return tea.Batch(m.scan(), m.scanProject(), m.imagesCmd()), false
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

func (m *model) move(key string) {
	page := max(m.layout().rows-1, 1)
	step := map[string]int{"up": -1, "k": -1, "down": 1, "j": 1, "pgup": -page, "pgdown": page, "space": page}[key]
	switch m.focus {
	case focusRail:
		switch key {
		case "enter":
			if m.curRow().kind == rowProject {
				m.projOpen = !m.projOpen
			} else {
				m.focus = focusTable
			}
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
			m.cursor = m.rowLen() - 1
		default:
			m.cursor += step
		}
	case focusSide:
		m.moveSide(key, step)
	}
}

func (m *model) moveSide(key string, step int) {
	if isImageRow(m.curRow().kind) {
		m.moveImageSide(key, step)
		return
	}
	// A skill candidate has only Info, and its install is the newest commit,
	// so enter there asks the install instead of opening a list.
	if key == "enter" && m.sidePart == 0 && m.inResults() {
		if p, ok := m.current(); ok && m.isCandidate(p) && p.Source == "skills" && m.activeTab() == tabInfo {
			m.askInstall()
			return
		}
	}
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

// A dependency list scrolls with its cursor, so the cursor moves instead.
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
		return repoURL(p.Repo)
	}
	switch provider.Ecosystem(p) {
	case vuln.NPM:
		return "https://www.npmjs.com/package/" + p.Name
	case vuln.PyPI:
		return "https://pypi.org/project/" + p.Name + "/"
	case vuln.Go:
		return "https://pkg.go.dev/" + p.Origin
	}
	return ""
}

func repoURL(repo string) string { return "https://github.com/" + repo }

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

// The package cursor goes first, since the layout and the links depend on
// what it selects.
func (m *model) clamp() {
	m.clampHistory()
	m.keepRail()
	// Search belongs to the rail row it was opened on: a row switch drops it.
	if m.search != nil && m.search.scope != m.curRow().key {
		m.search = nil
	}
	m.cursor = max(min(m.cursor, m.rowLen()-1), 0)
	l := m.layout()
	m.railTop = m.railTopFor(l.bodyH - 2)
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

// The cursor is a row number, so without this it would land on whichever
// package took that row.
func (m *model) reselect() {
	for i, p := range m.rows() {
		if pkgKey(p) == m.selected {
			m.cursor = i
			return
		}
	}
}

func at[T any](s []T, i int) (T, bool) {
	if i < 0 || i >= len(s) {
		var zero T
		return zero, false
	}
	return s[i], true
}

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
	if p, ok := m.current(); ok && m.isCandidate(p) {
		// A package that is not installed has nothing to show on Skill,
		// Readme or Links: those come from an installed skill's files. A skill
		// has no versions either, so Info is all there is to show.
		if p.Source == "skills" {
			return []int{tabInfo}
		}
		return []int{tabInfo, tabVersions, tabSecurity}
	}
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

func (m model) visible(pkgs []provider.Package) []provider.Package {
	var out []provider.Package
	for _, p := range pkgs {
		switch {
		case m.hidden(p):
		case !m.matchStatus(p):
		case m.filter() != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(m.filter())):
		default:
			out = append(out, p)
		}
	}
	return out
}

func (m model) rows() []provider.Package {
	if m.inResults() {
		return m.searchRows()
	}
	rows := m.visible(m.rowPkgs(m.curRow()))
	m.sort(rows)
	return rows
}
