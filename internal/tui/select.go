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
	areaPopup
)

type point struct{ line, col int }

// textSel is a drag selection in one of the sidebar's reading areas. It
// never crosses into another panel or the other half.
type textSel struct {
	area     int
	a, b     point
	dragging bool
	// focused is whether the sidebar had focus before the press, so a first
	// click into it only selects.
	focused bool
}

var copyText = tea.SetClipboard

// textAt finds the reading area under the mouse, and the line and column in
// it. List rows are not text to read, so a list half has no area.
func (m model) textAt(x, y int) (int, point, bool) {
	if m.depPop != nil {
		px, py, w, h := m.depRect()
		col, row := x-px-1, y-py-2
		if col < 0 || col >= w-2 || row < 0 || row >= h-3 {
			return 0, point{}, false
		}
		return areaPopup, point{m.depPop.top + row, col}, true
	}
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
	switch area {
	case areaPopup:
		return m.depPopView()
	case areaTop:
		return m.topView(inner)
	}
	return m.bottomView(inner)
}

func (m model) areaWidth(area int) int {
	if area == areaPopup {
		_, _, w, _ := m.depRect()
		return w - 2
	}
	return m.layout().sideW - 2
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
	width := m.areaWidth(m.sel.area)
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
	switch {
	case m.depPop != nil:
		area = areaPopup
	case m.hasBottom():
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
	if s := m.sel; s.a == s.b {
		m.sel = nil
		if s.area == areaPopup {
			if l, ok := at(m.depPopView(), s.a.line); ok && l.url != "" {
				return open(l.url)
			}
			return nil
		}
		l := m.layout()
		return m.clickSide(x-l.sideX-1, l.row(y), s.focused)
	}
	return m.copy(m.selectedText())
}
