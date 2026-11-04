package tui

import (
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	minWidth  = 100
	minHeight = 16
)

// layout is the screen geometry: the title line, the three panels, then the
// status bar and the key hints. The sidebar is one box whose halves meet at
// a divider.
type layout struct {
	top                  int
	railW, tableW, sideW int
	tableX, sideX        int
	bodyH                int
	rows                 int
	topRows, bottomRows  int
}

// The sizes a panel can be dragged or keyed to. The package panel takes what
// the other two leave.
const (
	minRail  = 16
	minSide  = 30
	minTable = 40
	// comfortTable fits every package column without squeezing names.
	comfortTable = 48
	minHalf      = 3
)

func (m model) layout() layout {
	var l layout
	// The sidebar is sized from the width alone, so the rail's room comes out
	// of the package list. By default the rail grows to 42 columns only while
	// the list keeps a comfortable width.
	l.sideW = max(38, (m.width-30)*2/5)
	l.railW = min(42, max(m.width-l.sideW-comfortTable, 24))
	if m.railW > 0 {
		l.railW = m.railW
	}
	l.railW = max(min(l.railW, m.width/3), minRail)
	if m.sideW > 0 {
		l.sideW = m.sideW
	}
	l.sideW = max(min(l.sideW, m.width-l.railW-minTable), minSide)
	l.tableW = max(m.width-l.railW-l.sideW, 0)
	l.tableX, l.sideX = l.railW, l.railW+l.tableW
	l.top = 1
	l.bodyH = max(m.height-4, 0)
	l.rows = max(l.bodyH-5, 0)
	l.topRows = max(l.bodyH-2, 0)
	if m.hasBottom() {
		l.topRows = max((l.bodyH-3)/2, 1)
		switch {
		case m.split > 0:
			l.topRows = m.split
		case m.activeTab() == tabSkill:
			// SKILL.md's front matter is short; give the body the room.
			l.topRows = max(min(len(m.topView(l.sideW-2)), l.topRows), 3)
		}
		l.topRows = max(min(l.topRows, l.bodyH-3-minHalf), minHalf)
		l.bottomRows = max(l.bodyH-3-l.topRows, 0)
	}
	return l
}

// row turns a screen row into a row inside the panels: 0 is the first line
// under their top border, which is row -1.
func (l layout) row(y int) int {
	return y - l.top - 1
}

func (m model) confirmRect() (x, y, w, h int) {
	w = 40
	for _, l := range m.confirm.lines {
		w = max(w, lipgloss.Width(l)+4)
	}
	w = min(w, m.width-8)
	h = len(m.confirm.lines) + 3
	return (m.width - w) / 2, (m.height - h) / 2, w, h
}

func (m model) helpRect() (x, y, w, h int) {
	w = min(m.width-8, 96)
	h = min(len(helpLines())+3, m.height-2)
	return (m.width - w) / 2, (m.height - h) / 2, w, h
}

// helpHidden is how many lines of help don't fit on the screen.
func (m model) helpHidden() int {
	_, _, _, h := m.helpRect()
	return len(helpLines()) - (h - 3)
}

func (m model) installRect() (x, y, w, h int) {
	w, h = min(m.width-8, 110), min(m.height-4, 24)
	return (m.width - w) / 2, (m.height - h) / 2, w, h
}

func (m model) depRect() (x, y, w, h int) {
	w, h = min(m.width-8, 100), min(m.height-4, 30)
	return (m.width - w) / 2, (m.height - h) / 2, w, h
}

func (m *model) click(x, y int) tea.Cmd {
	if m.help {
		m.help = false
		return nil
	}
	if m.inst != nil {
		if m.inst.done != nil {
			m.inst = nil
		}
		return nil
	}
	if m.depPop != nil {
		if area, p, ok := m.textAt(x, y); ok && area == areaPopup {
			m.startSelect(area, p)
			return nil
		}
		px, py, w, h := m.depRect()
		if x < px || x >= px+w || y < py || y >= py+h {
			m.depPop, m.sel = nil, nil
		}
		return nil
	}
	if m.confirm != nil {
		cx, cy, cw, ch := m.confirmRect()
		if x < cx || x >= cx+cw || y < cy || y >= cy+ch {
			m.confirm = nil
		}
		return nil
	}
	l := m.layout()
	r := l.row(y)
	if r < -1 || r > l.bodyH-2 {
		return nil
	}
	if m.showHistory {
		m.clickHistory(x, r)
		return nil
	}
	m.sel = nil
	// A border drag fixes every size first, so moving one border takes room
	// only from the panels on either side of it.
	switch {
	case x == l.tableX-1 || x == l.tableX:
		m.resizing, m.grab = resizeRail, l.railW-x
	case x == l.sideX-1 || x == l.sideX:
		m.resizing, m.grab = resizeSide, l.sideW-(m.width-x)
	case x > l.sideX && r == l.topRows && m.hasBottom():
		m.resizing, m.grab = resizeSplit, l.topRows-r
	}
	if m.resizing != resizeNone {
		m.railW, m.sideW = l.railW, l.sideW
		return nil
	}
	if area, p, ok := m.textAt(x, y); ok {
		focused := m.focus == focusSide
		m.focus = focusSide
		m.startSelect(area, p)
		m.sel.focused = focused
		return nil
	}
	switch {
	case x < l.tableX:
		m.focus = focusRail
		if r >= 0 {
			m.setRail(r)
		}
	case x < l.sideX:
		m.focus = focusTable
		switch {
		case r == 0:
			m.sortBy(m.columnAt(x - l.tableX - 3))
		case r == l.bodyH-3:
			switch c := m.chipAt(x - l.tableX - 1); {
			case c == -2:
				m.filtering = true
			case c >= 0:
				m.setStatus(c)
			}
		case r > 0 && r <= l.rows:
			if i := m.offset + r - 1; i < len(m.rows()) {
				m.cursor = i
			}
		}
	default:
		focused := m.focus == focusSide
		m.focus = focusSide
		return m.clickSide(x-l.sideX-1, r, focused)
	}
	return nil
}

// clickSide handles a click inside the sidebar at an x offset from its left
// edge and a row counted from its first content line: the tab bar, a link,
// a list row, or the bottom half.
func (m *model) clickSide(x, row int, focused bool) tea.Cmd {
	l := m.layout()
	switch {
	case row == -1:
		edge := 2
		for i, label := range m.tabLabels() {
			edge += lipgloss.Width(label) + 1
			if x < edge {
				m.setTab(m.tabs()[i])
				return nil
			}
		}
	case row < l.topRows:
		m.sidePart = 0
		lines := m.topView(l.sideW - 2)
		if i := m.sideOffset + row; m.sideListLen() < 0 && i < len(lines) && lines[i].url != "" {
			return open(lines[i].url)
		}
		if m.sideListLen() < 0 {
			return nil
		}
		i := m.sideOffset + row - 1
		if row < 1 || i >= m.sideListLen() {
			return nil
		}
		if i == m.sideCursor && focused {
			m.moveSide("enter", 0)
			return nil
		}
		m.sideCursor, m.bodyOffset = i, 0
	case row > l.topRows && m.hasBottom():
		m.sidePart = 1
		i := m.bodyOffset + row - l.topRows - 1
		if deps := m.depList(); i < len(deps) {
			if i == m.depCursor && focused {
				m.openDep(i)
			}
			m.depCursor = i
			return nil
		}
		lines := m.bottomView(l.sideW - 2)
		if i < len(lines) && lines[i].url != "" {
			return open(lines[i].url)
		}
	}
	return nil
}

func (m *model) sortBy(col int) {
	if col < 0 {
		return
	}
	if col == m.sortCol {
		m.sortDesc = !m.sortDesc
	} else {
		m.sortCol, m.sortDesc = col, false
	}
}

// columnAt maps an x offset within the table rows to the column under it.
func (m model) columnAt(x int) int {
	if x < 0 {
		return -1
	}
	edge := 0
	for _, c := range m.tableColumns() {
		edge += c.width + 1
		if x < edge {
			return c.id
		}
	}
	return -1
}

func (m *model) wheel(x, y, delta int) {
	if m.help {
		m.helpTop += delta
		return
	}
	if m.inst != nil {
		return
	}
	if m.depPop != nil {
		m.depPop.top += delta
		return
	}
	if m.showHistory {
		m.hCursor += delta
		return
	}
	l := m.layout()
	switch {
	case x < l.tableX:
		m.setRail(m.rail + delta)
	case x < l.sideX:
		m.cursor += delta
	case l.row(y) < l.topRows && m.sideListLen() >= 0:
		m.sideCursor += delta
		m.bodyOffset = 0
	case l.row(y) < l.topRows:
		m.sideOffset += delta
	case m.depList() != nil:
		m.depCursor += delta
	default:
		m.bodyOffset += delta
	}
}

const (
	resizeNone = iota
	resizeRail
	resizeSide
	resizeSplit
)

// resize follows a border being dragged to x, y.
func (m *model) resize(x, y int) {
	l := m.layout()
	switch m.resizing {
	case resizeRail:
		m.railW = max(x+m.grab, minRail)
	case resizeSide:
		m.sideW = max(m.width-x+m.grab, minSide)
	case resizeSplit:
		m.split = max(l.row(y)+m.grab, minHalf)
	}
	l = m.layout()
	m.railW, m.sideW = l.railW, l.sideW
}

// grow widens the focused panel by n columns, or narrows it when n is
// negative. The package panel grows by narrowing the sidebar.
func (m *model) grow(n int) {
	l := m.layout()
	switch m.focus {
	case focusRail:
		m.railW = l.railW + n
	case focusTable:
		m.sideW = l.sideW - n
	case focusSide:
		m.sideW = l.sideW + n
	}
	l = m.layout()
	m.railW, m.sideW = l.railW, l.sideW
}

func (m *model) moveSplit(n int) {
	l := m.layout()
	if l.bottomRows > 0 {
		m.split = l.topRows + n
		m.split = m.layout().topRows
	}
}
