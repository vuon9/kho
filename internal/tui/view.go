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
			box(icon("All")+" Sources", m.railLines(), l.railW, l.bodyH, m.focus == focusRail),
			box(m.tableTitle(), m.tableLines(), l.tableW, l.bodyH, m.focus == focusTable),
			m.sideBox(l.sideW, l.bodyH, m.focus == focusSide),
		)
	}
	screen := m.titleBar() + "\n" + body + "\n" + ansi.Truncate(m.statusBar(), m.width, "…") + "\n" + ansi.Truncate(m.footer(), m.width, "…")
	switch {
	case m.help:
		x, y, w, h := m.helpRect()
		screen = overlay(screen, box("⌨ Keys", helpLines(), w, h, true), x, y, w)
	case m.confirm != nil:
		x, y, w, h := m.confirmRect()
		var lines []string
		for _, l := range m.confirm.lines {
			lines = append(lines, " "+l)
		}
		screen = overlay(screen, box(m.confirm.title, lines, w, h, true), x, y, w)
	}
	v.SetContent(screen)
	return v
}

// actionable is a package an upgrade would move: outdated and not pinned.
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

// titleBar names the app and its version across the top.
func (m model) titleBar() string {
	left := " " + logo() + " " + pillOn(m.version, th.subtle, th.selFg) + faint().Render("  one place for every package manager")
	return ansi.Truncate(left, m.width, "…") + strings.Repeat(" ", max(m.width-lipgloss.Width(left), 0))
}

// statusBar sits under the panels: the tallies, and what kho is busy with.
func (m model) statusBar() string {
	t := m.count(m.allPkgs())
	parts := []string{" " + pillOn(fmt.Sprintf("%d packages", t.total), th.subtle, th.selFg)}
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

// activity says what kho is busy with, or when security data was last checked.
func (m model) activity() string {
	var busy []string
	for _, p := range m.providers {
		if m.busy[p.Name()] != "" {
			busy = append(busy, p.Name())
		}
	}
	if m.scanning > 0 {
		busy = append(busy, "security")
	}
	if len(busy) > 0 {
		return accent().Render(spinner[m.frame%len(spinner)]) + faint().Render(" checking "+strings.Join(busy, ", ")+" ")
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

func (m model) footer() string {
	var line string
	switch {
	case m.help:
		line = keys("?", "close", "esc", "close")
	case m.confirm != nil && m.confirm.run != nil:
		line = keys("y", "yes", "n", "no")
	case m.confirm != nil:
		line = keys("esc", "close")
	case m.filtering:
		line = keys("type", "to filter", "enter", "keep", "esc", "clear")
	case m.showHistory:
		line = keys("↑↓", "move", "/", "filter", "f", "kind", "c", "copy command", "H esc", "back", "?", "help")
	case m.focus == focusRail:
		line = keys("↑↓", "source", "enter", "packages", "tab", "panel", "< >", "resize", "H", "history", "?", "help", "q", "quit")
	case m.focus == focusTable:
		line = keys("↑↓", "move", "enter", "details", "s", "sort: "+strings.ToLower(columns[m.sortCol]), "f", "status", "/", "filter", "w", "home", "?", "help")
	case m.activeTab() == tabVersions:
		line = keys("↑↓", "version", "enter", "install it", "J K", "scroll changelog", "y", "open page", "[ ]", "tabs", "?", "help")
	case m.activeTab() == tabLinks:
		line = keys("↑↓", "agent", "enter", "link or unlink", "[ ]", "tabs", "?", "help")
	case m.sideListLen() >= 0 && m.sidePart == 0:
		line = keys("↑↓", "select", "enter", "read", "J K", "scroll detail", "[ ]", "tabs", "?", "help")
	default:
		line = keys("↑↓", "scroll", "J K", "scroll detail", "esc", "back", "[ ]", "tabs", "w", "home", "?", "help")
	}
	line = " " + line
	if m.notice != "" {
		status := faint().Render(m.notice + " ")
		line += strings.Repeat(" ", max(m.width-lipgloss.Width(line)-lipgloss.Width(status), 1)) + status
	}
	return line
}

func (m model) railLines() []string {
	inner := m.layout().railW - 2
	var lines []string
	for i := 0; i <= len(m.providers); i++ {
		name := "All"
		pkgs := m.allPkgs()
		var mark string
		if i > 0 {
			name = m.providers[i-1].Name()
			pkgs = m.pkgs[name]
			switch {
			case m.errs[name] != nil:
				mark = red().Render("!")
			case m.busy[name] != "":
				mark = accent().Render(spinner[m.frame%len(spinner)])
			}
		}
		t := m.count(pkgs)
		var badges []string
		if m.filters[i] != "" || m.statuses[i] != statusAll {
			badges = append(badges, accent().Render("⌕"))
		}
		if t.vulnerable > 0 {
			badges = append(badges, red().Render(fmt.Sprintf("⚠%d", t.vulnerable)))
		}
		if t.outdated > 0 {
			badges = append(badges, yellow().Render(fmt.Sprintf("↑%d", t.outdated)))
		}
		line := fmt.Sprintf("  %s %s%s %s %s", icon(name), pad(name, max(inner-17, 6)), fmt.Sprintf("%4d", t.total), strings.Join(badges, " "), mark)
		if i == m.rail {
			line = selected(line, inner, m.focus == focusRail)
		}
		lines = append(lines, line)
	}
	return lines
}

func (m model) tableTitle() string {
	title := icon("All") + " All"
	if m.rail > 0 {
		name := m.providers[m.rail-1].Name()
		title = icon(name) + " " + name
	}
	if m.status() != statusAll {
		title += " · " + statusNames[m.status()]
	}
	if !m.showDeps {
		title += " · deps hidden"
	}
	return fmt.Sprintf("%s · %d", title, len(m.rows()))
}

type column struct {
	id, width int
}

// tableColumns fits the columns to the table. A narrow table drops SOURCE
// and narrows the version columns before it squeezes names.
func (m model) tableColumns() []column {
	inner := m.layout().tableW - 4
	cols := []column{{colName, 0}, {colSource, 7}, {colVersion, 13}, {colLatest, 13}, {colStatus, 11}}
	if inner < 10+8+14+14+12 {
		cols = []column{{colName, 0}, {colVersion, 10}, {colLatest, 10}, {colStatus, 11}}
	}
	fixed := 0
	for _, c := range cols[1:] {
		fixed += c.width + 1
	}
	longest := 0
	for _, p := range m.rows() {
		longest = max(longest, len(p.Name))
	}
	cols[0].width = max(min(longest+2, inner-fixed), 10)
	cols[len(cols)-1].width = max(inner-fixed+11-cols[0].width, 11)
	return cols
}

func (m model) tableLines() []string {
	if m.rail > 0 {
		name := m.providers[m.rail-1].Name()
		if err := m.errs[name]; err != nil && len(m.pkgs[name]) == 0 {
			return []string{"", red().Render(" " + err.Error())}
		}
		if m.busy[name] == "listing" {
			return []string{"", faint().Render(" " + spinner[m.frame%len(spinner)] + " scanning " + name + "…")}
		}
	}
	cols := m.tableColumns()
	inner := m.layout().tableW - 2
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
		line := "  " + row([5]string{name, p.Source, ver, p.Latest, m.statusCell(p)})
		if i == m.cursor {
			line = selected(line, inner, m.focus == focusTable)
		}
		lines = append(lines, line)
	}
	if len(rows) == 0 && len(m.busy) == 0 {
		empty := "  nothing matches"
		if m.status() != statusAll && m.filter() == "" {
			empty = "  ✨ all clear here"
		}
		lines = append(lines, "", faint().Render(empty))
	}
	for len(lines) < m.layout().rows+1 {
		lines = append(lines, "")
	}
	return append(lines, fg(th.subtle).Render(strings.Repeat("─", inner)), m.filterBar())
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
	case strings.HasPrefix(p.Note, "no lock"):
		return yellow().Render("◌ no lock")
	case strings.HasPrefix(p.Note, "only in"):
		return faint().Render("◌ unmanaged")
	case strings.HasPrefix(p.Note, "latest unknown"):
		return faint().Render("?")
	case p.Latest != "":
		return green().Render("✓")
	}
	return ""
}

// overlay draws a box over the screen at x, y.
func overlay(screen, boxed string, x, y, w int) string {
	lines := strings.Split(screen, "\n")
	for i, pl := range strings.Split(boxed, "\n") {
		if y+i < len(lines) {
			base := lines[y+i]
			lines[y+i] = ansi.Truncate(base, x, "") + ansi.ResetStyle + pl + ansi.ResetStyle + ansi.TruncateLeft(base, x+w, "")
		}
	}
	return strings.Join(lines, "\n")
}

func wrap(text string, w int) []string {
	text = strings.NewReplacer("\r\n", "\n", "\t", "    ").Replace(strings.TrimSpace(text))
	return strings.Split(ansi.Wrap(text, max(w, 10), ""), "\n")
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

// box draws a rounded border with the title set into the top edge. A focused
// box gets an accent border.
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
