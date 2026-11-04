package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/vuon9/kho/internal/history"
)

const (
	kindAll = iota
	kindChanges
	kindFailed
)

var kindNames = []string{"All", "✎ Changes", "✗ Failed"}

func (m model) isKind(e history.Entry, k int) bool {
	switch k {
	case kindChanges:
		return e.Kind == history.Change
	case kindFailed:
		return e.Err != ""
	}
	return true
}

// historyEntries is the log newest first, after the kind and keyword filters.
func (m model) historyEntries() []history.Entry {
	var out []history.Entry
	for _, e := range m.log.Entries() {
		if m.isKind(e, m.hKind) && (m.hFilter == "" || strings.Contains(strings.ToLower(strings.Join(e.Command, " ")), strings.ToLower(m.hFilter))) {
			out = append(out, e)
		}
	}
	return out
}

// pressHistory handles keys on the history screen. It reports false only for
// the keys it leaves to the rest of kho, like ? and q; every other key would
// act on the panels hidden behind it, so it takes them and does nothing.
func (m *model) pressHistory(key string) (tea.Cmd, bool) {
	page := max(m.layout().rows-1, 1)
	switch key {
	case "H":
		m.showHistory = false
	case "esc":
		if m.hFilter != "" {
			m.hFilter = ""
		} else {
			m.showHistory = false
		}
	case "f":
		m.hKind = (m.hKind + 1) % len(kindNames)
		m.hCursor = 0
	case "F":
		m.hKind = (m.hKind + len(kindNames) - 1) % len(kindNames)
		m.hCursor = 0
	case "c":
		if e, ok := at(m.historyEntries(), m.hCursor); ok {
			return m.copy(strings.Join(e.Command, " ")), true
		}
	case "up", "k":
		m.hCursor--
	case "down", "j":
		m.hCursor++
	case "pgup":
		m.hCursor -= page
	case "pgdown", "space":
		m.hCursor += page
	case "home", "g":
		m.hCursor = 0
	case "end", "G":
		m.hCursor = len(m.historyEntries()) - 1
	case "q", "?", "/", "t", "T", "r", "R":
		return nil, false
	}
	return nil, true
}

func (m *model) clampHistory() {
	n := len(m.historyEntries())
	m.hCursor = max(min(m.hCursor, n-1), 0)
	m.hOffset = scroll(m.hOffset, m.hCursor, m.layout().rows)
}

func (m *model) clickHistory(x, r int) {
	l := m.layout()
	switch {
	case x >= l.sideX:
	case r == l.bodyH-3:
		if k := m.kindAt(x - 1); k >= 0 {
			m.hKind, m.hCursor = k, 0
		} else if k == -2 {
			m.filtering = true
		}
	case r > 0 && r <= l.rows:
		m.hCursor = m.hOffset + r - 1
	}
}

func (m model) historyBody() string {
	l := m.layout()
	return lipgloss.JoinHorizontal(lipgloss.Top,
		box(m.historyTitle(), m.historyLines(l.sideX-2), l.sideX, l.bodyH, true),
		box(m.historyDetailTitle(), m.historyDetail(l.sideW-2), l.sideW, l.bodyH, false),
	)
}

func (m model) historyTitle() string {
	title := fmt.Sprintf("🕘 History · %d", len(m.historyEntries()))
	if m.hKind != kindAll {
		title += " · " + kindNames[m.hKind]
	}
	return title
}

func (m model) historyLines(inner int) []string {
	es := m.historyEntries()
	cmdW := max(inner-2-12-2-2-7-4, 10)
	row := func(when, kind, result, took, command string) string {
		return "  " + pad(when, 12) + " " + pad(kind, 1) + " " + pad(result, 1) + " " + pad(took, 7) + " " + pad(command, cmdW)
	}
	lines := []string{"  " + faint().Bold(true).Render(pad("WHEN", 12)+"      "+pad("TOOK", 7)+" COMMAND")}
	end := min(m.hOffset+m.layout().rows, len(es))
	for i := m.hOffset; i < end; i++ {
		e := es[i]
		kind, result := faint().Render("⌁"), green().Render("✓")
		if e.Kind == history.Change {
			kind = accent().Render("✎")
		}
		if e.Err != "" {
			result = red().Render("✗")
		}
		line := row(when(e.At), kind, result, took(e.Took), strings.Join(e.Command, " "))
		if i == m.hCursor {
			line = selected(line, inner, true)
		}
		lines = append(lines, line)
	}
	if len(es) == 0 {
		lines = append(lines, "", faint().Render("  No commands yet. kho records every command it runs here."))
	}
	for len(lines) < m.layout().rows+1 {
		lines = append(lines, "")
	}
	return append(lines, fg(th.subtle).Render(strings.Repeat("─", inner)), m.kindBar())
}

func when(t time.Time) string {
	if y, mo, d := t.Date(); y == now().Year() && mo == now().Month() && d == now().Day() {
		return t.Format("15:04:05")
	}
	return t.Format("Jan 02 15:04")
}

func took(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func (m model) kindBar() string {
	query := faint().Render("/ to filter")
	switch {
	case m.filtering:
		query = m.hFilter + accent().Render("▏")
	case m.hFilter != "":
		query = m.hFilter
	}
	bar := " " + accent().Render("⌕ ") + pad(query, filterWidth) + " "
	for k := range kindNames {
		bar += m.kindChip(k) + " "
	}
	return bar
}

func (m model) kindChip(k int) string {
	n := 0
	for _, e := range m.log.Entries() {
		if m.isKind(e, k) {
			n++
		}
	}
	label := fmt.Sprintf("%s %d", kindNames[k], n)
	if k == m.hKind {
		return pillOn(label, th.accent, th.pillFg)
	}
	return lipgloss.NewStyle().Foreground(th.muted).Padding(0, 1).Render(label)
}

// kindAt maps an x offset within the history list to the chip under it, or
// -1, or -2 for the keyword box.
func (m model) kindAt(x int) int {
	edge := 1 + 2 + filterWidth + 1
	if x < edge {
		return -2
	}
	for k := range kindNames {
		edge += lipgloss.Width(m.kindChip(k)) + 1
		if x < edge {
			return k
		}
	}
	return -1
}

func (m model) historyDetailTitle() string {
	if e, ok := at(m.historyEntries(), m.hCursor); ok && len(e.Command) > 0 {
		return "⌨ " + e.Command[0]
	}
	return "⌨ Command"
}

func (m model) historyDetail(inner int) []string {
	e, ok := at(m.historyEntries(), m.hCursor)
	if !ok {
		return nil
	}
	result := green().Render("✓ succeeded")
	if e.Err != "" {
		result = red().Render("✗ " + e.Err)
	}
	kind := faint().Render("read: kho looked, nothing changed")
	if e.Kind == history.Change {
		kind = accent().Render("change: kho changed the machine")
	}
	lines := []line{
		field("when", e.At.Format("2006-01-02 15:04:05"), ""),
		field("kind", kind, ""),
		field("took", took(e.Took), ""),
		field("result", result, ""),
		{},
		field("command", strings.Join(e.Command, " "), ""),
	}
	if e.Output != "" {
		lines = append(lines, line{}, line{text: " " + accent().Render("output")})
		lines = append(lines, plain(wrap(e.Output, inner-1)...)...)
	}
	var out []string
	for _, l := range wrapLines(lines, inner) {
		out = append(out, l.text)
	}
	return out
}
