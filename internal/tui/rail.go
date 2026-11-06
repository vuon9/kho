package tui

import (
	"fmt"
	"strings"

	"github.com/vuon9/kho/internal/provider"
)

const (
	rowAll = iota
	rowProvider
)

// railRow is one selectable line of the rail. key names it in filters and
// statuses, so each row keeps its own even when rows above it come and go.
type railRow struct {
	kind int
	name string
	key  string
}

func (m model) railRows() []railRow {
	rows := []railRow{{kind: rowAll, name: "All", key: "all"}}
	for _, p := range m.providers {
		rows = append(rows, railRow{kind: rowProvider, name: p.Name(), key: "machine:" + p.Name()})
	}
	return rows
}

func (m model) curRow() railRow {
	r, _ := at(m.railRows(), m.rail)
	return r
}

// rowPkgs is every package a rail row stands for, before any filter.
func (m model) rowPkgs(r railRow) []provider.Package {
	if r.kind == rowProvider {
		return m.pkgs[r.name]
	}
	return m.allPkgs()
}

func (m *model) setRail(i int) {
	i = max(min(i, len(m.railRows())-1), 0)
	if i != m.rail {
		m.rail, m.cursor, m.offset = i, 0, 0
	}
}

// railLines is what the rail panel shows, h lines tall, and which row each
// line selects (-1 for none). The rail scrolls to keep the selected row in
// view when it has more rows than lines.
func (m model) railLines(h int) (lines []string, rowOf []int) {
	inner := m.layout().railW - 2
	for i, r := range m.railRows() {
		lines = append(lines, m.railLine(r, i == m.rail, inner))
		rowOf = append(rowOf, i)
	}
	top := max(min(m.railTop, len(lines)-h), 0)
	end := min(top+max(h, 0), len(lines))
	return lines[top:end], rowOf[top:end]
}

func (m model) railLine(r railRow, selectedRow bool, inner int) string {
	var mark string
	if r.kind == rowProvider {
		switch {
		case m.errs[r.name] != nil:
			mark = red().Render("!")
		case m.busy[r.name] != "":
			mark = accent().Render(spinner[m.frame%len(spinner)])
		}
	}
	t := m.count(m.rowPkgs(r))
	var badges []string
	if m.filters[r.key] != "" || m.statuses[r.key] != statusAll {
		badges = append(badges, accent().Render("⌕"))
	}
	if t.vulnerable > 0 {
		badges = append(badges, red().Render(fmt.Sprintf("⚠%d", t.vulnerable)))
	}
	if t.outdated > 0 {
		badges = append(badges, yellow().Render(fmt.Sprintf("↑%d", t.outdated)))
	}
	line := fmt.Sprintf("  %s %s%s %s %s", icon(r.name), pad(r.name, max(inner-17, 6)), fmt.Sprintf("%4d", t.total), strings.Join(badges, " "), mark)
	if selectedRow {
		line = selected(line, inner, m.focus == focusRail)
	}
	return line
}

// railRowAt is the row a click on line y of the rail's body selects, or -1.
func (m model) railRowAt(y int) int {
	_, rowOf := m.railLines(m.layout().bodyH - 2)
	if r, ok := at(rowOf, y); ok {
		return r
	}
	return -1
}

// railBody is the rail panel's lines, h tall.
func (m model) railBody(h int) []string {
	lines, _ := m.railLines(h)
	return lines
}

// hiddenDep is a dependency row the d toggle hides. A vulnerable one always
// shows, so hiding dependencies never hides risk.
func (m model) hiddenDep(p provider.Package) bool {
	return p.Dependency && !m.showDeps && len(m.vulns[pkgKey(p)]) == 0
}
