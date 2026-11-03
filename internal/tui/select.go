package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	areaTop = iota
	areaBottom
)

type point struct{ line, col int }

// textSel is a drag selection in one of the sidebar's reading areas. It
// never crosses into another panel or the other half.
type textSel struct {
	area     int
	a, b     point
	dragging bool
}

var copyText = tea.SetClipboard

// textAt finds the reading area under the mouse, and the line and column in
// it. List rows are not text to read, so a list half has no area.
func (m model) textAt(x, y int) (int, point, bool) {
	l := m.layout()
	col := x - l.sideX - 1
	if col < 0 || col >= l.sideW-2 || m.width == 0 {
		return 0, point{}, false
	}
	row := l.row(y)
	switch {
	case row >= 0 && row < l.topRows && m.sideListLen() < 0:
		return areaTop, point{m.sideOffset + row, col}, true
	case m.hasBottom() && row > l.topRows && row <= l.topRows+l.bottomRows:
		return areaBottom, point{m.bodyOffset + row - l.topRows - 1, col}, true
	}
	return 0, point{}, false
}

func (m model) areaLines(area int) []line {
	inner := m.layout().sideW - 2
	if area == areaTop {
		return m.topView(inner)
	}
	return m.bottomView(inner)
}

// span is the selection's columns on line i of area, if any.
func (s *textSel) span(area, i, width int) (int, int, bool) {
	if s == nil || s.area != area {
		return 0, 0, false
	}
	start, end := s.a, s.b
	if end.line < start.line || end.line == start.line && end.col < start.col {
		start, end = end, start
	}
	if i < start.line || i > end.line || start == end {
		return 0, 0, false
	}
	from, to := 0, width
	if i == start.line {
		from = start.col
	}
	if i == end.line {
		to = end.col + 1
	}
	return from, to, true
}

func highlight(text string, from, to int) string {
	return ansi.Cut(text, 0, from) + ansi.ResetStyle + lipgloss.NewStyle().Reverse(true).Render(ansi.Strip(ansi.Cut(text, from, to))) + ansi.Cut(text, to, lipgloss.Width(text))
}

func (m model) selectedText() string {
	width := m.layout().sideW - 2
	var out []string
	for i, l := range m.areaLines(m.sel.area) {
		if from, to, ok := m.sel.span(m.sel.area, i, width); ok {
			out = append(out, strings.TrimRight(ansi.Cut(ansi.Strip(l.text), from, to), " "))
		}
	}
	return strings.Join(out, "\n")
}

// copyArea copies the whole reading area: the detail below, or the sidebar
// when the tab has no bottom.
func (m *model) copyArea() tea.Cmd {
	area := areaTop
	if m.hasBottom() {
		area = areaBottom
	}
	var out []string
	for _, l := range m.areaLines(area) {
		out = append(out, strings.TrimRight(ansi.Strip(l.text), " "))
	}
	return m.copy(strings.TrimSpace(strings.Join(out, "\n")))
}

func (m *model) copy(text string) tea.Cmd {
	if text == "" {
		return nil
	}
	m.notice = fmt.Sprintf("copied %d lines to the clipboard", strings.Count(text, "\n")+1)
	return copyText(text)
}

func (m *model) startSelect(area int, p point) {
	m.sel = &textSel{area: area, a: p, b: p, dragging: true}
}

func (m *model) dragSelect(x, y int) {
	if m.sel == nil || !m.sel.dragging {
		return
	}
	if area, p, ok := m.textAt(x, y); ok && area == m.sel.area {
		m.sel.b = p
	}
}

// endSelect copies a drag. A press and release on the same cell is a click.
func (m *model) endSelect(x, y int) tea.Cmd {
	if m.sel == nil || !m.sel.dragging {
		return nil
	}
	m.sel.dragging = false
	if m.sel.a == m.sel.b {
		m.sel = nil
		focused := m.focus == focusSide
		l := m.layout()
		return m.clickSide(x-l.sideX-1, l.row(y), focused)
	}
	return m.copy(m.selectedText())
}
