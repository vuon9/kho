package tui

import (
	"fmt"
	"image/color"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/provider"
)

func (m model) View() tea.View {
	v := tea.NewView("")
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.WindowTitle = "kho"
	if m.width == 0 {
		return v
	}
	if m.width < minWidth || m.height < minHeight {
		v.SetContent(fmt.Sprintf("\n  🏮 kho needs at least %dx%d, this terminal is %dx%d.", minWidth, minHeight, m.width, m.height))
		return v
	}
	l := m.layout()
	var body string
	if m.showHistory {
		body = m.historyBody()
	} else {
		body = lipgloss.JoinHorizontal(lipgloss.Top,
			box(icon("Machine")+" Machine", m.railBody(l.bodyH-2), l.railW, l.bodyH, m.focus == focusRail),
			box(m.tableTitle(), m.tableLines(), l.tableW, l.bodyH, m.focus == focusTable),
			m.sideBoxFor(l.sideW, l.bodyH, m.focus == focusSide),
		)
	}
	rule := edge(false).Render(strings.Repeat("─", m.width))
	screen := m.titleBar() + "\n" + body + "\n" + ansi.Truncate(m.statusBar(), m.width, "…") + "\n" + rule + "\n" + ansi.Truncate(m.footer(), m.width, "…")
	switch m.popup() {
	case popHelp:
		r := m.helpRect()
		screen = overlay(screen, popupRows("⌨ Keys", helpLines()[m.helpTop:], r), r.x, r.y, r.w)
	case popInstall:
		r := m.installRect()
		t := popupText(r)
		screen = overlay(screen, popupRows(m.inst.title, m.installLines(t.h, t.w), r), r.x, r.y, r.w)
	case popDep:
		r := m.depRect()
		t := popupText(r)
		view := m.depPopView()
		var lines []string
		for i := m.depPop.top; i < min(len(view), m.depPop.top+t.h); i++ {
			text := view[i].text
			if from, to, ok := m.sel.span(areaPopup, i, t.w); ok {
				text = highlight(text, from, to)
			}
			lines = append(lines, text)
		}
		screen = overlay(screen, popupRows(m.depPopTitle(), lines, r), r.x, r.y, r.w)
	case popConfirm:
		r := m.confirmRect()
		var lines []string
		for _, l := range m.confirm.lines {
			lines = append(lines, " "+l)
		}
		screen = overlay(screen, popupBox(m.confirm.title, lines, r), r.x, r.y, r.w)
	}
	v.SetContent(screen)
	return v
}

func (m model) installLines(rows, width int) []string {
	in := m.inst
	end := in.end
	if in.running() {
		end = now()
	}
	took := end.Sub(in.start).Round(time.Second).String()
	var status string
	switch in.phase() {
	case instRunning:
		status = m.spin() + faint().Render(" running "+took)
	case instStopping:
		status = m.spin() + faint().Render(" stopping after "+took)
	case instFailed:
		status = red().Render("✗ "+in.done.err.Error()) + faint().Render(" after "+took)
	default:
		status = green().Render("✓ done") + faint().Render(" in "+took)
	}
	// The command and the output wrap, so a long error reads in full instead
	// of ending in an ellipsis, and the status keeps the last rows.
	cmd := wrapStyled(faint().Render(" runs  ")+strings.Join(in.cmd.Args, " "), width)
	statusRows := wrapStyled(" "+status, width)
	room := max(rows-len(cmd)-1-len(statusRows), 0)
	var out []string
	for _, l := range in.lines {
		out = append(out, wrapStyled(" "+l, width)...)
	}
	if len(out) > room {
		out = out[max(len(out)-room, 0):]
	}
	lines := append(append([]string{}, cmd...), "")
	lines = append(lines, out...)
	for len(lines) < rows-len(statusRows) {
		lines = append(lines, "")
	}
	return append(lines, statusRows...)
}

func actionable(p provider.Package) bool {
	return p.Outdated && !p.Pinned
}

type tally struct {
	total, outdated, pinned, vulnerable, depVulnerable int
}

func (m model) count(pkgs []provider.Package) tally {
	var t tally
	for _, p := range pkgs {
		t.total++
		if actionable(p) {
			t.outdated++
		}
		if p.Pinned {
			t.pinned++
		}
		if len(m.vulns[pkgKey(p)]) > 0 || m.riskyAudit(p) {
			t.vulnerable++
		}
		if len(m.depVulns[pkgKey(p)]) > 0 {
			t.depVulnerable++
		}
	}
	return t
}

func (m model) allPkgs() []provider.Package {
	var all []provider.Package
	for _, p := range m.providers {
		all = append(all, m.pkgs[p.Name()]...)
	}
	return all
}

func pillOn(text string, bg, fgc color.Color) string {
	return lipgloss.NewStyle().Background(bg).Foreground(fgc).Bold(true).Padding(0, 1).Render(text)
}

func (m model) titleBar() string {
	left := " " + logo() + " " + pillOn(m.version, th.subtle, th.selFg) + faint().Render("  one place for every package manager")
	return ansi.Truncate(left, m.width, "…") + strings.Repeat(" ", max(m.width-lipgloss.Width(left), 0))
}

func (m model) statusBar() string {
	if m.inResults() {
		return m.searchStatusBar()
	}
	if k := m.curRow().kind; k == rowImages || k == rowMachineImages {
		return m.imageStatusBar()
	}
	pkgs, label := m.allPkgs(), "packages"
	if m.inProject() {
		pkgs, label = m.projPkgs(), "in "+m.projName()
	}
	t := m.count(pkgs)
	parts := []string{" " + pillOn(fmt.Sprintf("%d %s", t.total, label), th.subtle, th.selFg)}
	if t.vulnerable > 0 {
		parts = append(parts, pillOn(fmt.Sprintf("⚠ %d vulnerable", t.vulnerable), th.red, th.selFg))
	} else if len(m.db.Checked) > 0 {
		parts = append(parts, pill("✓ no known vulns", th.green))
	}
	if t.depVulnerable > 0 {
		parts = append(parts, pill(fmt.Sprintf("◆ %d with vulnerable deps", t.depVulnerable), th.orange))
	}
	parts = append(parts, pill(fmt.Sprintf("↑ %d outdated", t.outdated), th.yellow), pill(fmt.Sprintf("⚑ %d pinned", t.pinned), th.cyan))
	left := strings.Join(parts, " ")
	right := m.activity() + faint().Render("🎨 "+th.name+" ")
	return left + strings.Repeat(" ", max(m.width-lipgloss.Width(left)-lipgloss.Width(right), 1)) + right
}

func (m model) activity() string {
	var busy []string
	for _, p := range m.providers {
		if m.busy[p.Name()] != "" {
			busy = append(busy, p.Name())
		}
	}
	if m.projBusy != "" {
		busy = append(busy, "lockfiles")
	}
	if m.scanning > 0 {
		busy = append(busy, "security")
	}
	if len(busy) > 0 {
		return m.spin() + faint().Render(" checking "+strings.Join(busy, ", ")+" ")
	}
	if m.secErr != nil {
		return red().Render("security check failed: "+m.secErr.Error()) + " "
	}
	var last time.Time
	for _, t := range m.db.Checked {
		if t.After(last) {
			last = t
		}
	}
	if last.IsZero() {
		return ""
	}
	return faint().Render("osv.dev checked "+ago(last)+" ") + " "
}

func ago(t time.Time) string {
	d := now().Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func keys(pairs ...string) string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, accent().Render(pairs[i])+" "+faint().Render(pairs[i+1]))
	}
	return strings.Join(out, faint().Render("  "))
}

// The footer shows what fits, so a row offers the same actions whether the
// cursor is on it or one of the sidebar's tabs is open.
func (m model) rowKeys() []string {
	var pairs []string
	if m.focus == focusSide {
		pairs = append(pairs, "↑↓", "select")
	} else {
		pairs = append(pairs, "↑↓", "move")
	}
	pairs = append(pairs, "tab", "panel", "[ ]", "tabs", "enter", m.enterLabel())
	switch {
	case isImageRow(m.curRow().kind):
		pairs = append(pairs, "D", "remove", "i v a", "tabs", "s", "sort", "f", "state", "/", "filter", "w", "copy name")
	case m.inProjectPkg():
		pairs = append(pairs, "s", "sort", "f", "status", "/", "filter", "w", "home")
	case m.inProject():
		pairs = append(pairs, "s", "sort", "f", "status", "d", "deps", "p", "dev", "/", "filter", "w", "home")
	default:
		pairs = append(pairs, "D", "remove", "i v a", "tabs", "s", "sort", "f", "status", "/", "filter", "w", "home", "n", "new package")
	}
	switch m.activeTab() {
	case tabVersions:
		pairs = append(pairs, "y", "open page", "J K", "scroll changelog")
	case tabSecurity:
		if m.currentFix() != "" && m.sidePart == 0 {
			pairs = append(pairs, "c", "copy the fix")
		}
		pairs = append(pairs, "J K", "scroll detail")
	case tabLinks:
		if m.allAgents {
			pairs = append(pairs, "A", "installed only")
		} else {
			pairs = append(pairs, "A", "all agents")
		}
	}
	return append(pairs, "?", "help")
}

func (m model) enterLabel() string {
	p, _ := m.current()
	switch {
	case m.focus == focusTable:
		return "details"
	case m.inResults() && m.isCandidate(p) && p.Source == "skills" && m.focus == focusSide:
		return "install it"
	case m.activeTab() == tabVersions && !m.inProjectPkg():
		return "install it"
	case m.activeTab() == tabLinks:
		return "link or unlink"
	case m.depList() != nil:
		return "its advisories"
	}
	return "read"
}

// Always keeps the last pair, so the help key is there on a narrow screen.
func fitKeys(width int, pairs []string) string {
	if len(pairs) < 2 {
		return ""
	}
	sep := faint().Render("  ")
	last := keys(pairs[len(pairs)-2:]...)
	limit := width - lipgloss.Width(last) - lipgloss.Width(sep)
	out := ""
	for i := 0; i+3 < len(pairs); i += 2 {
		p := keys(pairs[i], pairs[i+1])
		cand := p
		if out != "" {
			cand = out + sep + p
		}
		if lipgloss.Width(cand) > limit {
			break
		}
		out = cand
	}
	if out == "" {
		return last
	}
	return out + sep + last
}

func (m model) footer() string {
	// A notice sits at the right of this line, so the keys have to leave it room.
	reserve := 0
	if m.notice != "" {
		reserve = lipgloss.Width(faint().Render(m.notice+" ")) + 1
	}
	var line string
	switch pop := m.popup(); {
	case pop == popHelp && m.helpHidden() > 0:
		line = keys("↑↓", "scroll", "?", "close", "esc", "close")
	case pop == popHelp:
		line = keys("?", "close", "esc", "close")
	case pop == popInstall && m.inst.phase() == instStopping:
		line = keys("ctrl+c", "kill it") + faint().Render("   stopping, the keys come back once it's done")
	case pop == popInstall && m.inst.phase() == instRunning:
		line = keys("ctrl+c", "stop it") + faint().Render("   the other keys come back once it's done")
	case pop == popInstall && m.inst.phase() == instFailed:
		line = keys("t", "run it in the terminal", "enter", "close")
	case pop == popInstall:
		line = keys("enter", "close")
	case pop == popDep:
		line = keys("↑↓", "scroll", "drag", "select and copy", "c", "copy all", "esc", "close")
	case pop == popConfirm && m.confirm.run != nil:
		line = keys("y", "yes", "n", "no")
	case pop == popConfirm:
		line = keys("esc", "close")
	case m.search != nil && m.search.mode == modePrompt:
		line = keys("type", "a name", "enter", "search", "esc", "cancel")
	case m.search != nil && m.search.editing:
		line = keys("type", "to search", "enter", "run", "esc", "cancel")
	case m.search != nil:
		switch m.focus {
		case focusSide:
			line = fitKeys(max(m.width-2-reserve, 24), []string{"↑↓", "select", "enter", m.enterLabel(),
				"i v a", "tabs", "J K", "scroll", "/", "edit", "esc", "back", "?", "help"})
		case focusRail:
			line = keys("↑↓", "source", "tab", "panel", "esc", "back", "?", "help")
		default:
			line = keys("/", "edit", "↑↓", "select", "enter", "details", "w", "home", "?", "help", "esc", "back")
		}
	case m.filtering:
		line = keys("type", "to filter", "enter", "keep", "esc", "clear")
	case m.showHistory:
		line = keys("↑↓", "move", "/", "filter", "f", "kind", "c", "copy command", "H esc", "back", "?", "help")
	case m.focus == focusRail && m.curRow().kind == rowProject && m.projOpen:
		line = keys("↑↓", "source", "enter", "close project", "p", "dev", "tab", "panel", "< >", "resize", "H", "history", "?", "help", "q", "quit")
	case m.focus == focusRail && m.curRow().kind == rowProject:
		line = keys("↑↓", "source", "enter", "open project", "p", "dev", "tab", "panel", "< >", "resize", "H", "history", "?", "help", "q", "quit")
	case m.focus == focusRail:
		line = keys("↑↓", "source", "enter", "packages", "tab", "panel", "< >", "resize", "H", "history", "?", "help", "q", "quit")
	default:
		line = fitKeys(max(m.width-2-reserve, 24), m.rowKeys())
		if m.inProjectPkg() && m.activeTab() == tabVersions {
			line += faint().Render("   kho doesn't change projects")
		}
	}
	line = " " + line
	if m.notice != "" {
		status := faint().Render(m.notice + " ")
		line += strings.Repeat(" ", max(m.width-lipgloss.Width(line)-lipgloss.Width(status), 1)) + status
	}
	return line
}

func (m model) tableTitle() string {
	if m.inResults() {
		return m.searchTitle()
	}
	r := m.curRow()
	if r.kind == rowImages || r.kind == rowMachineImages {
		return m.imageTitle()
	}
	title := icon(r.icon) + " " + r.name
	if r.kind == rowPart {
		title = icon("project") + " " + m.projName() + " · " + r.name
	}
	if m.inProject() && m.proj.Capped != "" {
		title += " · " + m.proj.Capped
	}
	if m.inProject() && len(m.proj.Shallow) > 0 {
		title += " · not below " + m.proj.Shallow[0]
	}
	if m.inProject() && m.prodOnly {
		title += " · dev hidden"
	}
	if m.status() != statusAll {
		title += " · " + statusNames[m.status()]
	}
	if !m.showDeps {
		title += " · deps hidden"
	}
	if m.filter() != "" {
		total := 0
		for _, p := range m.rowPkgs(r) {
			if !m.hidden(p) && m.matchStatus(p) {
				total++
			}
		}
		return fmt.Sprintf("%s · %d of %d", title, len(m.rows()), total)
	}
	return fmt.Sprintf("%s · %d", title, len(m.rows()))
}

type column struct {
	id, width int
}

func (m model) tableColumns() []column {
	inner := m.layout().tableW - 4
	cols := []column{{colName, 0}, {colSource, 8}, {colVersion, 13}, {colLatest, 13}, {colStatus, 11}}
	if m.skillScope() {
		// A skill's versions are short commit hashes, so the repo gets the
		// room the generic VERSION and LATEST columns do not need.
		fromW := min(max(inner-10-9-9-11-4, 12), 28)
		cols = []column{{colName, 0}, {colSource, fromW}, {colVersion, 9}, {colLatest, 9}, {colStatus, 11}}
	}
	if inner < 10+9+14+14+12 {
		cols = []column{{colName, 0}, {colVersion, 10}, {colLatest, 10}, {colStatus, 11}}
	}
	fixed := 0
	for _, c := range cols[1:] {
		fixed += c.width + 1
	}
	longest := 0
	for _, p := range m.rows() {
		longest = max(longest, lipgloss.Width(p.Name+nameTag(p)))
	}
	cols[0].width = max(min(longest+2, inner-fixed), 10)
	cols[len(cols)-1].width = max(inner-fixed+11-cols[0].width, 11)
	return cols
}

func (m model) tableLines() []string {
	if m.inResults() {
		return m.searchLines()
	}
	if k := m.curRow().kind; k == rowImages || k == rowMachineImages {
		return m.imageTableLines()
	}
	inner := m.layout().tableW - 2
	if r := m.curRow(); r.kind == rowPart && len(m.rowPkgs(r)) == 0 {
		lines := []string{""}
		for _, lf := range m.partLockfiles(r) {
			switch {
			case lf.Err != "":
				lines = append(lines, styled(red(), wrap(lf.Path+": "+lf.Err, m.layout().tableW-4))...)
			case lf.Missing != "":
				lines = append(lines, styled(yellow(), wrap("◌ "+lf.Path+": "+lf.Missing, m.layout().tableW-4))...)
			}
		}
		if len(lines) > 1 {
			return append(m.fitBody(lines), m.barRule(inner), m.filterBar())
		}
	}
	if r := m.curRow(); r.kind == rowProvider {
		name := r.name
		if err := m.errs[name]; err != nil && len(m.pkgs[name]) == 0 {
			return append(m.fitBody([]string{"", red().Render(" " + err.Error())}), m.barRule(inner), m.filterBar())
		}
		if m.busy[name] == "listing" {
			return append(m.fitBody([]string{"", " " + m.spin() + faint().Render(" scanning "+name+"…")}), m.barRule(inner), m.filterBar())
		}
	}
	cols := m.tableColumns()
	row := func(cells [5]string) string {
		var parts []string
		for _, c := range cols {
			parts = append(parts, pad(cells[c.id], c.width))
		}
		return strings.Join(parts, " ")
	}
	var head [5]string
	copy(head[:], columns)
	arrow := "▲"
	if m.sortDesc {
		arrow = "▼"
	}
	if m.skillScope() {
		head[colSource] = "FROM"
	}
	head[m.sortCol] += arrow
	lines := []string{"  " + faint().Bold(true).Render(row(head))}
	rows := m.rows()
	end := min(m.offset+m.layout().rows, len(rows))
	for i := m.offset; i < end; i++ {
		p := rows[i]
		ver := p.Version
		if len(p.Versions) > 1 {
			ver += fmt.Sprintf(" ×%d", len(p.Versions))
		}
		name := p.Name
		if p.Dependency {
			name = faint().Render(name)
		}
		if tag := nameTag(p); tag != "" {
			name += faint().Render(tag)
		}
		source := p.Source
		if m.skillScope() {
			source = skillFrom(p)
		}
		line := "  " + row([5]string{name, source, ver, p.Latest, m.statusCell(p)})
		if i == m.cursor {
			line = selected(line, inner, m.focus == focusTable)
		}
		lines = append(lines, line)
	}
	if len(rows) == 0 && !m.listing() {
		switch {
		case m.filter() != "" && (m.curRow().kind == rowAll || m.curRow().kind == rowProvider):
			lines = append(lines, m.searchBridge(inner)...)
		case m.status() != statusAll && m.filter() == "":
			lines = append(lines, "", faint().Render("  ✨ all clear here"))
		default:
			lines = append(lines, "", faint().Render("  nothing matches"))
		}
	}
	bar := m.filterBar()
	if m.inPrompt() {
		bar = m.searchBar()
	}
	return append(m.fitBody(lines), m.barRule(inner), bar)
}

// A security check running in the background changes no row, so it never hides an empty state.
func (m model) listing() bool {
	for _, state := range m.busy {
		if state == "listing" {
			return true
		}
	}
	return false
}

// A long empty state or a pile of error lines must never clip the input.
func (m model) fitBody(lines []string) []string {
	limit := m.layout().rows + 1
	if len(lines) > limit {
		lines = lines[:limit]
	}
	for len(lines) < limit {
		lines = append(lines, "")
	}
	return lines
}

func (m model) barRule(inner int) string {
	e := fg(th.subtle)
	if m.search != nil {
		e = searchTone()
	}
	return e.Render(strings.Repeat("─", inner))
}

func centered(text string, width int) string {
	return strings.Repeat(" ", max((width-lipgloss.Width(text))/2, 0)) + text
}

func (m model) searchBridge(inner int) []string {
	hint := []string{
		faint().Render(fmt.Sprintf("no installed match for %q", m.filter())),
		accent().Render("n") + faint().Render(" search for a new package"),
	}
	lines := make([]string, m.layout().rows)
	top := max((len(lines)-len(hint))/2, 0)
	for i, l := range hint {
		lines[top+i] = centered(l, inner)
	}
	return lines
}

func nameTag(p provider.Package) string {
	var tag string
	if p.Dev {
		tag += " dev"
	}
	if len(p.Via) > 0 {
		tag += " via " + p.Via[0]
	}
	return tag
}

func styled(style lipgloss.Style, lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = style.Render(" " + l)
	}
	return out
}

func (m model) statusCell(p provider.Package) string {
	switch n := len(m.vulns[pkgKey(p)]); {
	case n == 1:
		return red().Render("⚠ 1 vuln")
	case n > 1:
		return red().Render(fmt.Sprintf("⚠ %d vulns", n))
	case m.riskyAudit(p):
		return red().Render("⚠ audit")
	case p.Pinned && p.Outdated:
		return cyan().Render("⚑ newer")
	case p.Pinned:
		return cyan().Render("⚑ pinned")
	case p.Outdated:
		return yellow().Render("↑ outdated")
	case p.NoLock():
		return yellow().Render("◌ no lock")
	case p.Unmanaged():
		return faint().Render("◌ unmanaged")
	case p.LatestUnknown():
		return faint().Render("?")
	case p.Latest != "":
		return green().Render("✓")
	}
	return ""
}

func overlay(screen, boxed string, x, y, w int) string {
	lines := strings.Split(screen, "\n")
	for i, pl := range strings.Split(boxed, "\n") {
		if y+i < len(lines) {
			base := lines[y+i]
			// An edge through a wide character drops it on the left and keeps
			// it whole on the right; a space takes its place either way.
			left := ansi.Truncate(base, x, "")
			left += strings.Repeat(" ", x-ansi.StringWidth(left))
			right := ansi.TruncateLeft(base, x+w, "")
			if over := ansi.StringWidth(right) - (ansi.StringWidth(base) - x - w); over > 0 {
				right = strings.Repeat(" ", over) + ansi.TruncateLeft(base, x+w+over, "")
			}
			lines[y+i] = left + ansi.ResetStyle + pl + ansi.ResetStyle + right
		}
	}
	return strings.Join(lines, "\n")
}

func wrap(text string, w int) []string {
	text = expandTabs(strings.ReplaceAll(strings.TrimSpace(text), "\r\n", "\n"))
	return strings.Split(ansi.Wrap(text, max(w, 10), ""), "\n")
}

// Tab stops every 8 columns, as a terminal lines them up.
func expandTabs(s string) string {
	if !strings.Contains(s, "\t") {
		return s
	}
	var b strings.Builder
	col := 0
	for _, r := range s {
		switch r {
		case '\t':
			n := 8 - col%8
			b.WriteString(strings.Repeat(" ", n))
			col += n
		case '\n':
			b.WriteRune(r)
			col = 0
		default:
			b.WriteRune(r)
			col += ansi.StringWidth(string(r))
		}
	}
	return b.String()
}

func edge(focused bool) lipgloss.Style {
	if focused {
		return fg(th.accent)
	}
	return fg(th.subtle)
}

func boxTitle(title string, focused bool) string {
	if focused {
		return accent().Render(title)
	}
	return bold().Foreground(th.muted).Render(title)
}

// The top border, the title bar and the bottom border.
const popupFrame = 3

// Inside the one-column border, under the top border and the title bar.
func popupText(r rect) rect {
	return rect{r.x + 1, r.y + 2, r.w - 2, r.h - popupFrame}
}

// Wraps so a sentence is never cut by the border. r must already be tall
// enough for the wrapped lines.
func popupBox(title string, lines []string, r rect) string {
	return drawPopup(title, wrapPopup(lines, popupText(r).w), r)
}

// Pads and cuts rather than wrapping: the caller counts rows.
func popupRows(title string, lines []string, r rect) string {
	return drawPopup(title, lines, r)
}

func wrapPopup(lines []string, w int) []string {
	var out []string
	for _, l := range lines {
		out = append(out, wrapStyled(l, w)...)
	}
	return out
}

func drawPopup(title string, lines []string, r rect) string {
	e := fg(th.accent)
	t := popupText(r)
	bar := lipgloss.NewStyle().Background(th.accent).Foreground(th.pillFg).Bold(true).Render(pad(" "+title, t.w))
	out := []string{e.Render("┏" + strings.Repeat("━", t.w) + "┓"), e.Render("┃") + bar + e.Render("┃")}
	lines = slices.Clone(lines)
	for len(lines) < t.h {
		lines = append(lines, "")
	}
	for _, l := range lines[:max(t.h, 0)] {
		out = append(out, e.Render("┃")+pad(l, t.w)+e.Render("┃"))
	}
	out = append(out, e.Render("┗"+strings.Repeat("━", t.w)+"┛"))
	return strings.Join(out, "\n")
}

func box(title string, lines []string, w, h int, focused bool) string {
	e := edge(focused)
	inner := w - 2
	top := e.Render("╭─ ") + boxTitle(ansi.Truncate(title, inner-4, "…"), focused) + " "
	top += e.Render(strings.Repeat("─", max(w-1-lipgloss.Width(top), 0)) + "╮")
	out := []string{top}
	lines = slices.Clone(lines)
	for len(lines) < h-2 {
		lines = append(lines, "")
	}
	for _, l := range lines[:max(h-2, 0)] {
		out = append(out, e.Render("│")+pad(l, inner)+e.Render("│"))
	}
	out = append(out, e.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return strings.Join(out, "\n")
}

func pad(s string, w int) string {
	s = ansi.Truncate(s, w, "…")
	return s + strings.Repeat(" ", max(w-lipgloss.Width(s), 0))
}

func stripStyle(s string) string { return ansi.Strip(s) }
