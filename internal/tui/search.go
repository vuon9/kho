package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/provider"
)

// The transient modes of a machine package panel. The default, installed, is
// no search at all: prompt and results live in m.search, and neither touches
// the installed list's counts, filters or security index.
const (
	modePrompt = iota
	modeResults
)

const (
	// searchLimit caps what one source returns, so one busy registry can't
	// bury the others. The help screen says the limit.
	searchLimit = provider.DefaultSearchLimit
	// searchMinLen is the shortest query a search runs on.
	searchMinLen = 2
	// searchTimeout keeps one unreachable registry from holding its answer.
	searchTimeout = 20 * time.Second
)

// searchState is the selected panel's transient search. The prompt lives over
// the installed table; results replace it. Nothing fetches until enter.
type searchState struct {
	mode int
	// scope is the rail row's key, so a search never follows a row switch.
	scope string
	// draft is what typing edits; query is what results were asked for.
	draft string
	query string
	// editing says results mode has the query box open for an edit in place.
	editing bool
	// gen names one search, so an answer for an older one is dropped.
	gen int
	// busy is true from enter until every asked source has answered.
	busy    bool
	finding bool
	// asks and answered name the managers, so the status bar can say which
	// answer is still out and what a failure was.
	asks     []string
	answered map[string]bool
	errs     map[string]string
	// rows are the results, each with Version empty until the row is installed:
	// a search never turns an installed package into a candidate or the other
	// way round by itself.
	rows              []provider.Package
	installed         map[string]string
	started           time.Time
	took              time.Duration
	savedCursor       int
	savedOffset       int
	opened            bool
	installedName     string
	installedProvider string
}

// searchMsg is one manager's answer to a keyword search.
type searchMsg struct {
	gen     int
	manager string
	pkgs    []provider.Package
	err     error
	// exact is a name lookup for a manager that has no keyword search, where
	// "not found" reads as no match rather than as a failed source.
	exact bool
}

// findMsg is a candidate's newest version, resolved when opening the row.
type findMsg struct {
	gen     int
	manager string
	source  string
	name    string
	pkg     provider.Package
	err     error
}

func (m model) inPrompt() bool  { return m.search != nil && m.search.mode == modePrompt }
func (m model) inResults() bool { return m.search != nil && m.search.mode == modeResults }

// searchWorking says the spinner has to run: a search or a version lookup is
// still on its way.
func (m model) searchWorking() bool {
	return m.search != nil && (m.search.busy || m.search.finding)
}

// providerCanSearch says a manager's panel has a search at all. pipx, uv and
// go have only an exact-name lookup; mise and skills are deferred.
func (m model) providerCanSearch(name string) bool {
	p := m.provider(name)
	if p == nil {
		return false
	}
	if _, ok := p.(provider.Searcher); ok {
		return true
	}
	_, ok := p.(provider.Finder)
	return ok
}

// providerHasKeywordSearch says a manager can be asked a query, as the All
// panel asks every source that can.
func (m model) providerHasKeywordSearch(name string) bool {
	p := m.provider(name)
	if p == nil {
		return false
	}
	_, ok := p.(provider.Searcher)
	return ok
}

// openSearch opens the prompt on a machine package panel. It is silently
// ignored elsewhere: kho never changes a project, and an image is not a
// package.
func (m *model) openSearch() {
	r := m.curRow()
	if r.kind != rowAll && r.kind != rowProvider {
		return
	}
	if r.kind == rowProvider && !m.providerCanSearch(r.name) {
		m.notice = r.name + " can't search yet"
		return
	}
	m.search = &searchState{
		mode: modePrompt, scope: r.key, draft: m.filter(),
		savedCursor: m.cursor, savedOffset: m.offset,
	}
	m.focus = focusTable
	m.notice = ""
}

// searchScopeLabel names the scope on the status bar's left side.
func (m model) searchScopeLabel() string {
	if m.curRow().kind == rowAll {
		return "every package manager"
	}
	return m.curRow().name
}

// searchBar is the bottom bar in prompt and results: the word search, then the
// draft or the query. The search tone on its glyph, cursor and the rule above
// it says which input this is; the manager's name is already in the title and
// the status bar. A long query keeps its tail on screen.
func (m model) searchBar() string {
	st := m.search
	w := max(m.layout().tableW-2, 12)
	cursor := ""
	prefix := " " + searchTone().Render("⌕ search ")
	hint := ""
	switch {
	case st.mode == modePrompt:
		cursor = searchTone().Render("▏")
		if utf8.RuneCountInString(strings.TrimSpace(st.draft)) == 1 {
			hint = faint().Render("  type one more character")
		}
	case st.editing:
		cursor = searchTone().Render("▏")
	}
	return fitBar(prefix, st.draftOrQuery(), cursor, hint, w)
}

// draftOrQuery is what the bar shows: the draft while typing, the query in
// results.
func (st *searchState) draftOrQuery() string {
	if st.mode == modePrompt || st.editing {
		return st.draft
	}
	return st.query
}

// fitBar keeps the tail of a long text on screen and cuts its head instead, so
// the characters just typed stay visible.
func fitBar(prefix, text, cursor, hint string, w int) string {
	width := lipgloss.Width(prefix) + lipgloss.Width(cursor) + lipgloss.Width(hint)
	room := w - width
	if room < 1 {
		return ansi.Truncate(prefix+cursor+hint, w, "…")
	}
	if lipgloss.Width(text) > room {
		runes := []rune(text)
		keep := room - 1
		if keep < 0 {
			keep = 0
		}
		text = "…" + string(runes[max(len(runes)-keep, 0):])
	}
	return prefix + text + cursor + hint
}

// submitSearch turns the draft into a search. A query shorter than two
// characters says what is missing and fetches nothing.
func (m *model) submitSearch() tea.Cmd {
	st := m.search
	q := strings.TrimSpace(st.draft)
	switch n := utf8.RuneCountInString(q); {
	case n == 0:
		m.notice = "type a name to search"
		return nil
	case n < searchMinLen:
		m.notice = "type one more character"
		return nil
	}
	keep := st.mode == modeResults && len(st.rows) > 0
	st.gen++
	st.mode, st.query, st.draft, st.editing = modeResults, q, q, false
	st.errs = map[string]string{}
	st.answered = map[string]bool{}
	st.asks, st.took = nil, 0
	st.busy, st.finding, st.opened = true, false, false
	st.installedName, st.installedProvider = "", ""
	st.started = now()
	if !keep {
		st.rows, m.cursor, m.offset = nil, 0, 0
	}
	m.notice = ""
	return m.searchRun(st.gen, q)
}

// searchRun asks the panel's scope: the All row asks every keyword source, a
// manager's row asks that manager, and a manager with only an exact-name
// lookup resolves the query as a name or path.
func (m *model) searchRun(gen int, q string) tea.Cmd {
	st := m.search
	r := m.curRow()
	var cmds []tea.Cmd
	switch r.kind {
	case rowAll:
		for _, p := range provider.Searchers(m.providers) {
			p := p
			st.asks = append(st.asks, p.Name())
			cmds = append(cmds, m.searchCmd(p, gen, q))
		}
	case rowProvider:
		p := m.provider(r.name)
		if p == nil {
			break
		}
		if _, ok := p.(provider.Searcher); ok {
			st.asks = append(st.asks, p.Name())
			cmds = append(cmds, m.searchCmd(p, gen, q))
		} else if _, ok := p.(provider.Finder); ok {
			st.asks = append(st.asks, p.Name())
			cmds = append(cmds, m.exactCmd(p, r.name, gen, q))
		}
	}
	if len(cmds) == 0 {
		st.busy = false
		return nil
	}
	return tea.Batch(cmds...)
}

func (m model) searchCmd(p provider.Provider, gen int, q string) tea.Cmd {
	s, name := p.(provider.Searcher), p.Name()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
		defer cancel()
		pkgs, err := s.Search(ctx, q, searchLimit)
		return searchMsg{gen: gen, manager: name, pkgs: pkgs, err: err}
	}
}

func (m model) exactCmd(p provider.Provider, source string, gen int, q string) tea.Cmd {
	f, name := p.(provider.Finder), p.Name()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
		defer cancel()
		found, err := f.Find(ctx, source, q)
		if err != nil {
			return searchMsg{gen: gen, manager: name, err: err, exact: true}
		}
		return searchMsg{gen: gen, manager: name, pkgs: []provider.Package{found}, exact: true}
	}
}

// gotSearch files one answer. An answer for an older search is dropped, and a
// row keeps the manager's own order.
func (m *model) gotSearch(msg searchMsg) {
	st := m.search
	if st == nil || st.mode != modeResults || msg.gen != st.gen {
		return
	}
	st.answered[msg.manager] = true
	// A refinement keeps the other managers' rows and replaces this manager's,
	// so an old answer never sits beside a new one.
	st.rows = rowsWithoutManager(st.rows, msg.manager)
	if msg.err != nil && !msg.exact {
		st.errs[msg.manager] = msg.err.Error()
	} else {
		pkgs := msg.pkgs
		if len(pkgs) > searchLimit {
			pkgs = pkgs[:searchLimit]
		}
		for _, p := range pkgs {
			if p.Name == "" || p.Source == "" {
				continue
			}
			st.rows = append(st.rows, p)
		}
	}
	// Keep the panels in their rail order whatever order the answers arrived:
	// a manager's own order inside that is untouched.
	sort.SliceStable(st.rows, func(i, j int) bool {
		return m.providerIndex(providerOfSource(st.rows[i].Source)) <
			m.providerIndex(providerOfSource(st.rows[j].Source))
	})
	if len(st.answered) >= len(st.asks) {
		st.busy = false
		st.took = now().Sub(st.started)
	}
}

// rowsWithoutManager drops a manager's rows before its new answer replaces
// them. A manager can serve more than one source, as brew does for casks.
func rowsWithoutManager(rows []provider.Package, manager string) []provider.Package {
	out := rows[:0]
	for _, p := range rows {
		if providerOfSource(p.Source) != manager {
			out = append(out, p)
		}
	}
	return out
}

// providerIndex is the provider's place in the rail order, for a stable result
// order across answers that arrive at different times.
func (m model) providerIndex(name string) int {
	for i, p := range m.providers {
		if p.Name() == name {
			return i
		}
	}
	return len(m.providers)
}

// gotFind fills the opened candidate's newest version, which some managers'
// search does not return.
func (m *model) gotFind(msg findMsg) {
	st := m.search
	if st == nil || st.mode != modeResults || msg.gen != st.gen {
		return
	}
	st.finding = false
	if msg.err != nil {
		st.errs[msg.manager] = msg.err.Error()
		return
	}
	for i := range st.rows {
		p := &st.rows[i]
		if p.Source != msg.source || p.Name != msg.name {
			continue
		}
		for _, v := range []struct {
			to   *string
			from string
		}{
			{&p.Latest, msg.pkg.Latest}, {&p.Desc, msg.pkg.Desc}, {&p.Homepage, msg.pkg.Homepage},
			{&p.Repo, msg.pkg.Repo}, {&p.Origin, msg.pkg.Origin}, {&p.Entry, msg.pkg.Entry},
		} {
			if *v.to == "" {
				*v.to = v.from
			}
		}
	}
}

// searchPending lists the managers whose answer is still out, in ask order.
func (m model) searchPending() []string {
	st := m.search
	if st == nil {
		return nil
	}
	var out []string
	for _, name := range st.asks {
		if !st.answered[name] {
			out = append(out, name)
		}
	}
	return out
}

// searchAnswers is how many asked managers have answered.
func (m model) searchAnswers() int {
	st := m.search
	if st == nil {
		return 0
	}
	n := 0
	for _, name := range st.asks {
		if st.answered[name] {
			n++
		}
	}
	return n
}

// searchTitle names the mode: the panel, then search, then the count.
func (m model) searchTitle() string {
	st := m.search
	r := m.curRow()
	title := icon(r.icon) + " " + r.name + " · search · "
	switch {
	case st.busy && len(st.rows) == 0:
		return title + m.spin() + " searching…"
	case st.busy && r.kind == rowAll:
		return fmt.Sprintf("%s%s %d of %d sources answered", title, m.spin(), m.searchAnswers(), len(st.asks))
	case st.busy:
		return title + m.spin() + " searching…"
	}
	return fmt.Sprintf("%s%d results", title, len(st.rows))
}

// searchStatusBar counts the results and carries the spinner and any source
// failure on its right side.
func (m model) searchStatusBar() string {
	st := m.search
	left := " " + pillOn(fmt.Sprintf("%d results · %s", len(st.rows), m.searchScopeLabel()), th.subtle, th.selFg)
	var right []string
	switch {
	case st.busy:
		right = append(right, m.spin()+faint().Render(" searching "+strings.Join(m.searchPending(), ", ")+" "))
	case st.finding:
		// Opening a result reads its newest version when the search did not
		// carry one; the title still says the result count.
		right = append(right, m.spin()+faint().Render(" resolving the newest version "))
	case len(st.errs) > 0:
		for _, name := range sortedErrKeys(st.errs) {
			right = append(right, red().Render("⚠ "+name+": ")+faint().Render(shortReason(st.errs[name]))+" ")
		}
	}
	right = append(right, faint().Render("🎨 "+th.name+" "))
	tail := strings.Join(right, "")
	return left + strings.Repeat(" ", max(m.width-lipgloss.Width(left)-lipgloss.Width(tail), 1)) + tail
}

// shortReason keeps a source's error to one short line on the status bar.
func shortReason(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return ansi.Truncate(s, 40, "…")
}

// sortedErrKeys names failed managers in a stable order.
func sortedErrKeys(errs map[string]string) []string {
	out := make([]string, 0, len(errs))
	for name := range errs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// resultColumns fits NAME, LATEST and STATUS to the package panel. Names give
// room first, and the source tag goes before a name is cut short.
func (m model) resultColumns() []column {
	inner := m.layout().tableW - 4
	latestW := 8
	statusW := min(max(inner-2-8-10, 11), 18)
	nameW := max(inner-2-latestW-statusW, 8)
	return []column{{colName, nameW}, {colLatest, latestW}, {colStatus, statusW}}
}

func resultRow(cols []column, cells [5]string) string {
	var parts []string
	for _, c := range cols {
		parts = append(parts, pad(cells[c.id], c.width))
	}
	return strings.Join(parts, " ")
}

// searchLines draws the results table with its states, the body hints the
// prompt and results add, and the query on the bottom bar.
func (m model) searchLines() []string {
	cols := m.resultColumns()
	var head [5]string
	head[colName], head[colLatest], head[colStatus] = "NAME", "LATEST", "STATUS"
	lines := []string{"  " + faint().Bold(true).Render(resultRow(cols, head))}
	rows := m.searchRows()
	end := min(m.offset+m.layout().rows, len(rows))
	inner := m.layout().tableW - 2
	for i := m.offset; i < end; i++ {
		p := rows[i]
		name := printable(p.Name)
		if prefix := m.searchSourcePrefix(p); prefix != "" {
			name = faint().Render(printable(prefix)+"/") + name
		}
		latest := printable(p.Latest)
		if latest == "" {
			latest = "?"
		}
		var cells [5]string
		cells[colName], cells[colLatest], cells[colStatus] = name, latest, m.searchStatusCell(p)
		line := "  " + resultRow(cols, cells)
		if i == m.cursor {
			line = selected(line, inner, m.focus == focusTable)
		}
		lines = append(lines, line)
	}
	lines = append(lines, m.searchHints(len(rows))...)
	return append(m.fitBody(lines), m.barRule(inner), m.searchBar())
}

// searchHints is the table body when it has no rows: what is still on its way,
// what failed, or that nothing matched.
func (m model) searchHints(n int) []string {
	st := m.search
	if n > 0 {
		return nil
	}
	out := []string{""}
	switch {
	case st.busy:
		pending := strings.Join(m.searchPending(), ", ")
		return append(out, " "+m.spin()+faint().Render(" searching "+pending+"…"))
	case len(st.asks) > 0 && len(st.errs) == len(st.asks):
		out = append(out, " "+red().Render("could not search any package manager"))
		for _, name := range sortedErrKeys(st.errs) {
			out = append(out, red().Render(" "+name+": "+shortReason(st.errs[name])))
		}
		return out
	}
	if r := m.curRow(); r.kind == rowProvider && !m.providerHasKeywordSearch(r.name) {
		return append(out, faint().Render(" no package named \""+printable(st.query)+"\" on "+exactNameWhere(r.name)))
	}
	out = append(out, faint().Render(" no packages match \""+printable(st.query)+"\""))
	if len(st.asks) > 0 {
		out = append(out, faint().Render(" searched "+strings.Join(st.asks, ", ")+" in "+tookText(st.took)))
	}
	for _, name := range sortedErrKeys(st.errs) {
		out = append(out, red().Render(" "+name+": "+shortReason(st.errs[name])))
	}
	if r := m.curRow(); r.kind == rowAll {
		if names := m.nameOnlyManagers(); len(names) > 0 {
			out = append(out, faint().Render(" "+joinWords(names)+" install by exact name only"))
		}
	}
	return out
}

// nameOnlyManagers are the ready managers that install by exact name only.
func (m model) nameOnlyManagers() []string {
	var out []string
	for _, p := range m.providers {
		if _, ok := p.(provider.Searcher); ok {
			continue
		}
		if _, ok := p.(provider.Finder); ok {
			out = append(out, p.Name())
		}
	}
	return out
}

// joinWords reads a list as a sentence: "a, b and c".
func joinWords(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// exactNameWhere names the registry a name was looked up in.
func exactNameWhere(manager string) string {
	switch manager {
	case "pipx", "uv":
		return "PyPI"
	case "go":
		return "the Go proxy"
	}
	return "its registry"
}

// tookText writes a search's time the way the no-match line reads.
func tookText(d time.Duration) string {
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// searchRows are the result rows as the table sees them: an installed hit
// resolves to the installed package, so its sidebar and status are today's.
func (m model) searchRows() []provider.Package {
	st := m.search
	if st == nil {
		return nil
	}
	out := make([]provider.Package, 0, len(st.rows))
	for _, p := range st.rows {
		if q, ok := m.searchInstalled(p); ok {
			if q.Latest == "" {
				q.Latest = p.Latest
			}
			if q.Desc == "" {
				q.Desc = p.Desc
			}
			if q.Homepage == "" {
				q.Homepage = p.Homepage
			}
			if q.Repo == "" {
				q.Repo = p.Repo
			}
			if q.Origin == "" {
				q.Origin = p.Origin
			}
			out = append(out, q)
			continue
		}
		out = append(out, p)
	}
	return out
}

// installedFor finds the installed package a result names under its own source.
func (m model) installedFor(p provider.Package) (provider.Package, bool) {
	for _, q := range m.pkgs[providerOfSource(p.Source)] {
		if q.Name == p.Name && q.Source == p.Source {
			return q, true
		}
	}
	return provider.Package{}, false
}

// searchInstalled resolves a result to its installed package, or to the
// version kho just installed while the relist is still on its way.
func (m model) searchInstalled(p provider.Package) (provider.Package, bool) {
	if q, ok := m.installedFor(p); ok {
		return q, true
	}
	if m.search != nil && m.search.installed != nil {
		if v, ok := m.search.installed[pkgKey(p)]; ok {
			q := p
			q.Version = v
			return q, true
		}
	}
	return provider.Package{}, false
}

// isCandidate says the selected row is a package the machine does not have.
func (m model) isCandidate(p provider.Package) bool {
	if !m.inResults() {
		return false
	}
	_, installed := m.searchInstalled(p)
	return !installed
}

// otherInstall finds the same name installed through another manager, which
// the candidate's status and confirm dialog warn about.
func (m model) otherInstall(p provider.Package) (provider.Package, bool) {
	for _, prov := range m.providers {
		for _, q := range m.pkgs[prov.Name()] {
			if q.Name == p.Name && q.Source != p.Source {
				return q, true
			}
		}
	}
	return provider.Package{}, false
}

// searchSourcePrefix names the row's source in the name column when it is not
// the panel's own, so a cask in the brew panel and every row in All keep it
// even when the name has to be cut short.
func (m model) searchSourcePrefix(p provider.Package) string {
	r := m.curRow()
	if r.kind == rowProvider && p.Source == r.name {
		return ""
	}
	return p.Source
}

// searchStatusCell is the results table's status: not installed, installed, or
// installed with a newer version waiting.
func (m model) searchStatusCell(p provider.Package) string {
	if m.isCandidate(p) {
		return faint().Render("· not installed")
	}
	switch {
	case p.Pinned && p.Outdated:
		return cyan().Render("⚑ newer " + printable(p.Version))
	case p.Outdated:
		return yellow().Render("↑ newer " + printable(p.Version))
	}
	return green().Render("✓ installed " + printable(p.Version))
}

// closeSearch drops the search and goes back to the installed list. A row
// installed during the search is the one selected when results close.
func (m *model) closeSearch() {
	st := m.search
	if st == nil {
		return
	}
	m.search = nil
	m.focus = focusTable
	if st.mode != modeResults {
		return
	}
	if st.installedName != "" {
		m.cursor, m.offset = 0, 0
		for i, p := range m.rows() {
			if providerOfSource(p.Source) == st.installedProvider && p.Name == st.installedName {
				m.cursor = i
				break
			}
		}
		m.focus = focusTable
		return
	}
	m.cursor, m.offset = st.savedCursor, st.savedOffset
}

// openResult opens the selected result in the sidebar. A candidate whose
// search returned no newest version has it resolved there first: this is the
// first network step for the row.
func (m *model) openResult() tea.Cmd {
	st := m.search
	p, ok := m.current()
	if !ok {
		return nil
	}
	st.opened = true
	m.focus = focusSide
	if !m.isCandidate(p) {
		return nil
	}
	if st.finding {
		return nil
	}
	if p.Latest != "" {
		return nil
	}
	prov := m.provider(providerOfSource(p.Source))
	f, ok := prov.(provider.Finder)
	if !ok {
		return nil
	}
	st.finding = true
	gen, source, name := st.gen, p.Source, p.Name
	manager := providerOfSource(p.Source)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
		defer cancel()
		found, err := f.Find(ctx, source, name)
		return findMsg{gen: gen, manager: manager, source: source, name: name, pkg: found, err: err}
	}
}

// openCandidateHome opens the selected candidate's homepage. Home returns the
// repo, and a registry page when kho knows one.
func (m *model) openCandidateHome() tea.Cmd {
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

// pressSearch takes every key while a prompt or results are showing, so the
// machine actions stay off: kho changes the machine only from the installed
// list, or after the install dialog says yes.
func (m *model) pressSearch(key string, msg tea.KeyPressMsg) (tea.Cmd, bool) {
	st := m.search
	if st == nil {
		return nil, false
	}
	if st.mode == modePrompt || st.editing {
		switch key {
		case "esc":
			if st.mode == modePrompt {
				m.search = nil
			} else {
				st.editing, st.draft = false, st.query
			}
		case "enter":
			return m.submitSearch(), false
		case "backspace":
			st.draft = dropLastRune(st.draft)
		case "up":
			if st.mode == modePrompt {
				m.move("up")
			}
		case "down":
			if st.mode == modePrompt {
				m.move("down")
			}
		case "tab":
			m.focus = (m.focus + 1) % 3
		case "shift+tab":
			m.focus = (m.focus + 2) % 3
		case "left":
			m.focus = max(m.focus-1, focusRail)
		case "right":
			m.focus = min(m.focus+1, focusSide)
		default:
			if text := printableKey(msg); text != "" {
				st.draft += text
			}
		}
		return nil, false
	}
	switch key {
	case "q":
		return nil, true
	case "?":
		m.help, m.helpTop = true, 0
	case "t":
		m.setTheme(themeIndex() + 1)
	case "T":
		m.setTheme(themeIndex() - 1)
	case "esc":
		if m.focus == focusSide && m.sidePart == 1 {
			m.sidePart = 0
		} else {
			m.closeSearch()
		}
	case "/":
		st.editing, st.draft = true, st.query
	case "w":
		return m.openCandidateHome(), false
	case "enter":
		switch m.focus {
		case focusTable:
			return m.openResult(), false
		case focusRail:
			m.move("enter")
		default:
			m.moveSide("enter", 0)
		}
	case "tab":
		m.focus = (m.focus + 1) % 3
	case "shift+tab":
		m.focus = (m.focus + 2) % 3
	case "left", "h":
		m.focus = max(m.focus-1, focusRail)
	case "right", "l":
		m.focus = min(m.focus+1, focusSide)
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
		if i := int(key[0] - '1'); i < len(m.tabs()) {
			return m.tabTo(m.tabs()[i]), false
		}
	case "i":
		st.opened = true
		m.setTab(tabInfo)
	case "v":
		return m.tabTo(tabVersions), false
	case "a":
		st.opened = true
		m.setTab(tabSecurity)
	case "]":
		tabs := m.tabs()
		return m.tabTo(tabs[(indexOf(tabs, m.activeTab())+1)%len(tabs)]), false
	case "[":
		tabs := m.tabs()
		return m.tabTo(tabs[(indexOf(tabs, m.activeTab())+len(tabs)-1)%len(tabs)]), false
	case "J", "ctrl+d":
		m.scrollDetail(map[string]int{"J": 1, "ctrl+d": m.layout().bottomRows / 2}[key])
	case "K", "ctrl+u":
		m.scrollDetail(-map[string]int{"K": 1, "ctrl+u": m.layout().bottomRows / 2}[key])
	default:
		m.move(key)
	}
	return nil, false
}

func indexOf(s []int, v int) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// printableKey is the text a key adds to a draft: nothing for a control key or
// a move.
func printableKey(msg tea.KeyPressMsg) string {
	if msg.Text == "" {
		return ""
	}
	for _, r := range msg.Text {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return msg.Text
}

func dropLastRune(s string) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}
	return string(runes[:len(runes)-1])
}

// candidateInfoLines is the Info tab for a package the machine does not have:
// what it is, where it comes from, what would run, and whether the machine
// already has it another way. Nothing here is read; the fields came with the
// search or the lookup that opened it.
func (m model) candidateInfoLines(p provider.Package) []line {
	lines := plain(" "+icon(providerOfSource(p.Source))+" "+accent().Render(printable(p.Name))+faint().Render(" · "+printable(p.Source)), "")
	add := func(label, value string) {
		if value == "" {
			return
		}
		lines = append(lines, field(label, value, ""))
	}
	addLink := func(label, value, url string) {
		if value == "" {
			return
		}
		lines = append(lines, line{label: label, text: link(url).Render(printable(value)), url: url, nowrap: false})
	}
	add("about", printable(p.Desc))
	latest := printable(p.Latest)
	if latest == "" {
		latest = "?"
	}
	add("latest", latest)
	status := "not installed"
	if q, ok := m.otherInstall(p); ok {
		status = "installed as " + q.Source + "/" + q.Name + " " + printable(q.Version)
	}
	add("status", status)
	add("security", m.candidateSecurity(p))
	add("from", printable(p.Origin))
	if home := homeURL(p); home != "" {
		addLink("home", home, home)
	}
	if p.Repo != "" {
		u := repoURL(p.Repo)
		if u != homeURL(p) {
			addLink("repo", strings.TrimPrefix(u, "https://"), u)
		}
	}
	if runs := m.candidateRuns(p); runs != "" {
		lines = append(lines, field("runs", runs, ""))
	}
	return lines
}

// candidateSecurity is the sentence the confirm would show about the newest
// version, or why there is none yet.
func (m model) candidateSecurity(p provider.Package) string {
	eco, name := provider.Ecosystem(p), provider.OSVName(p)
	if eco == "" {
		return faint().Render("not covered: OSV has no data for " + p.Source)
	}
	version := p.Latest
	if version == "" {
		return faint().Render("not checked yet")
	}
	hkey := eco + "/" + name
	if !m.db.HistoryFresh(eco, name, now()) {
		if m.advising[hkey] || m.scanning > 0 {
			return faint().Render("checking advisories…")
		}
		return faint().Render("not checked yet")
	}
	affected := 0
	for _, a := range m.db.Known(eco, name) {
		if a.Affects(version) {
			affected++
		}
	}
	switch {
	case affected == 1:
		return red().Render("⚠ 1 known advisory affects " + version)
	case affected > 1:
		return red().Render(fmt.Sprintf("⚠ %d known advisories affect %s", affected, version))
	}
	return green().Render("✓ no known advisories in " + version)
}

// candidateRuns is the exact command installing the newest version would run.
func (m model) candidateRuns(p provider.Package) string {
	version := p.Latest
	if version == "" {
		return faint().Render("resolve a version in Versions")
	}
	cmd, err := provider.InstallNewCmd(p, version)
	if err != nil {
		return faint().Render(err.Error())
	}
	return printable(strings.Join(cmd.Args, " "))
}

// askInstallNew offers to install a candidate at version. The dialog is the
// installed one with the new verb, the source in a word, and the newest nudge.
func (m *model) askInstallNew(p provider.Package, version string) {
	cmd, err := provider.InstallNewCmd(p, version)
	if err != nil {
		m.confirm = &confirm{title: "Can't install " + p.Name, lines: []string{err.Error()}}
		return
	}
	lines := []string{
		bold().Render(printable(p.Name)) + "  " + faint().Render("not installed") + faint().Render(" → ") + green().Render(printable(version)),
		m.sourceLine(p),
		"",
	}
	if q, ok := m.otherInstall(p); ok {
		lines = append(lines, yellow().Render("⚠ "+p.Name+" is installed as "+q.Source+"/"+q.Name+" "+q.Version), "")
	}
	if p.Latest != "" && provider.TagVersion(version) != provider.TagVersion(p.Latest) {
		lines = append(lines, yellow().Render("not the newest, latest is "+printable(p.Latest)), "")
	}
	if line := m.confirmAdvisory(p, version); line != "" {
		lines = append(lines, line, "")
	}
	lines = append(lines, faint().Render("runs  ")+printable(strings.Join(cmd.Args, " ")), "",
		accent().Render("y")+faint().Render(" run it   ")+accent().Render("n")+faint().Render(" cancel"))
	title := "＋ Install " + printable(p.Name)
	m.confirm = &confirm{title: title + "?", lines: lines,
		run: startInstall(title, cmd, m.log, installedMsg{provider: providerOfSource(p.Source), name: p.Name, version: version})}
}

// sourceLine names the manager's install shape, so a person can see which
// registry the name came from before saying yes.
func (m model) sourceLine(p provider.Package) string {
	word := map[string]string{
		"brew": "brew formula", "cask": "brew cask", "npm": "npm global",
		"composer": "composer global", "pipx": "pipx", "uv": "uv tool", "go": "go module",
	}[p.Source]
	if word == "" {
		word = p.Source
	}
	if p.Origin != "" {
		word += " · " + printable(p.Origin)
	}
	return faint().Render(word)
}

// confirmAdvisory is the advisory sentence the installed confirm shows, for a
// version a candidate would install. It is absent until the history is known.
func (m model) confirmAdvisory(p provider.Package, version string) string {
	eco, name := provider.Ecosystem(p), provider.OSVName(p)
	if eco == "" || !m.db.HistoryFresh(eco, name, now()) {
		return ""
	}
	affected := 0
	for _, a := range m.db.Known(eco, name) {
		if a.Affects(version) {
			affected++
		}
	}
	switch {
	case affected == 1:
		return red().Render("⚠ 1 known advisory affects " + version)
	case affected > 1:
		return red().Render(fmt.Sprintf("⚠ %d known advisories affect %s", affected, version))
	}
	return green().Render("✓ no known advisories in " + version)
}

// printablePaste is pasted text as a draft holds it: one line, no control
// characters.
func printablePaste(s string) string {
	return printable(strings.ReplaceAll(strings.TrimSpace(s), "\n", " "))
}

// loadCandidate reads what a candidate's sidebar needs once it is opened: its
// published versions when Versions is showing, and its advisory history for
// the Info status and the confirm. Dependencies are not read: a package
// without an installation has none.
func (m *model) loadCandidate(p provider.Package) tea.Cmd {
	prov, key := m.provider(providerOfSource(p.Source)), cacheKey(p)
	var cmds []tea.Cmd
	if prov != nil && m.activeTab() == tabVersions && m.versions[key] == nil {
		m.versions[key] = &lazy[[]provider.Release]{}
		cmds = append(cmds, func() tea.Msg {
			rels, err := prov.Versions(context.Background(), p)
			return versionsMsg{key, rels, err}
		})
	}
	eco, name := provider.Ecosystem(p), provider.OSVName(p)
	hkey := eco + "/" + name
	if eco != "" && !m.advising[hkey] && !m.db.HistoryFresh(eco, name, now()) {
		m.advising[hkey] = true
		cmds = append(cmds, func() tea.Msg {
			advs, err := fetchHistory(context.Background(), eco, name)
			return historyMsg{eco, name, advs, err}
		})
	}
	return tea.Batch(cmds...)
}

// gotInstalled patches the results row kho just installed, so it reads as
// installed while the machine list is relisted underneath it. The sidebar and
// the installed list follow the relist, as they do for any change.
func (m *model) gotInstalled(msg installedMsg) {
	st := m.search
	if st == nil || st.mode != modeResults {
		return
	}
	for _, p := range st.rows {
		if providerOfSource(p.Source) != msg.provider || p.Name != msg.name {
			continue
		}
		if st.installed == nil {
			st.installed = map[string]string{}
		}
		st.installed[pkgKey(p)] = msg.version
		st.installedName, st.installedProvider = msg.name, msg.provider
	}
}

// providerOfSource names the provider a source label belongs to: a cask is
// brew's, as provider.ProviderOf says for a package.
func providerOfSource(source string) string {
	if source == "cask" {
		return "brew"
	}
	return source
}
