package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/provider"
)

const (
	rowAll = iota
	rowProvider
	rowProject
	rowPart
)

// railRow is one selectable line of the rail. key names it in filters and
// statuses, so each row keeps its own even when rows above it come and go.
// A part of the project stands for one lockfile, or every lockfile in dir.
type railRow struct {
	kind     int
	name     string
	icon     string
	key      string
	lockfile string
	dir      string
	inDir    bool
}

func (m model) railRows() []railRow {
	rows := []railRow{{kind: rowAll, name: "All", icon: "All", key: "all"}}
	for _, p := range m.providers {
		rows = append(rows, railRow{kind: rowProvider, name: p.Name(), icon: p.Name(), key: "machine:" + p.Name()})
	}
	if m.projReady() {
		rows = append(rows, railRow{kind: rowProject, name: m.projName(), icon: "project", key: "project"})
		if m.projOpen {
			rows = append(rows, m.projParts()...)
		}
	}
	return rows
}

func (m model) curRow() railRow {
	r, _ := at(m.railRows(), m.rail)
	return r
}

// inProject says the selected rail row is the project or one of its parts.
func (m model) inProject() bool { return m.curRow().kind >= rowProject }

// rowPkgs is every package a rail row stands for, before any filter.
func (m model) rowPkgs(r railRow) []provider.Package {
	switch r.kind {
	case rowProvider:
		return m.pkgs[r.name]
	case rowProject:
		return m.projPkgs()
	case rowPart:
		return m.partPkgs(r)
	}
	return m.allPkgs()
}

func (m *model) setRail(i int) {
	rows := m.railRows()
	i = max(min(i, len(rows)-1), 0)
	if i != m.rail {
		m.rail, m.cursor, m.offset = i, 0, 0
	}
	m.railKey = rows[i].key
}

// keepRail puts the selection back on its row after rows came or went: a
// rescan, the project opening or closing, a provider appearing. A part of
// the project that went away falls back to the project's header.
func (m *model) keepRail() {
	rows := m.railRows()
	if r, ok := at(rows, m.rail); ok && r.key == m.railKey {
		return
	}
	for i, r := range rows {
		if r.key == m.railKey {
			m.rail = i
			return
		}
	}
	for i, r := range rows {
		if r.kind == rowProject && strings.HasPrefix(m.railKey, "project") {
			m.rail, m.cursor, m.offset = i, 0, 0
			m.railKey = r.key
			return
		}
	}
	if m.railKey != "" {
		m.cursor, m.offset = 0, 0
	}
	m.rail = max(min(m.rail, len(rows)-1), 0)
	m.railKey = rows[m.rail].key
}

// railAll is every line of the rail, which row each selects (-1 for none),
// and where the project block starts (-1 for none): a rule, then the
// project's header and parts. The header is only a row once the scan found
// something to select.
func (m model) railAll() (lines []string, rowOf []int, block int) {
	inner := m.layout().railW - 2
	rule := fg(th.subtle).Render(strings.Repeat("─", inner))
	block = -1
	for i, r := range m.railRows() {
		if r.kind == rowProject {
			block = len(lines)
			lines, rowOf = append(lines, rule), append(rowOf, -1)
		}
		lines, rowOf = append(lines, m.railLine(r, i == m.rail, inner)), append(rowOf, i)
	}
	if m.dir != "" && !m.projReady() {
		block = len(lines)
		lines, rowOf = append(lines, rule, m.projStatusLine()), append(rowOf, -1, -1)
	}
	return lines, rowOf, block
}

// pinned says the project block stays at the bottom while the Machine rows
// above it scroll, which it does when the rail overflows and the block
// leaves at least two lines for them.
func pinned(total, block, h int) bool {
	return block >= 0 && total > h && total-block <= h-2
}

// railTopFor is where the rail's scrolled part starts, h lines tall, so the
// selected row stays in view.
func (m model) railTopFor(h int) int {
	lines, _, block := m.railAll()
	sel := m.railLineOf(m.rail)
	switch {
	case len(lines) <= h:
		return 0
	case pinned(len(lines), block, h):
		window := h - (len(lines) - block)
		if sel >= block {
			return max(min(m.railTop, block-window), 0)
		}
		return max(min(scroll(m.railTop, sel, window), block-window), 0)
	}
	return max(min(scroll(m.railTop, sel, h), len(lines)-h), 0)
}

// railLines is what the rail panel shows, h lines tall. When it all fits,
// the project block sits at the bottom. When it doesn't, the Machine rows
// scroll above the block, or with a block too tall for that, everything
// scrolls, keeping the selected row in view.
func (m model) railLines(h int) (lines []string, rowOf []int) {
	lines, rowOf, block := m.railAll()
	if pinned(len(lines), block, h) {
		window := h - (len(lines) - block)
		top := max(min(m.railTop, block-window), 0)
		return append(slices.Clone(lines[top:top+window]), lines[block:]...), append(slices.Clone(rowOf[top:top+window]), rowOf[block:]...)
	}
	if len(lines) <= h {
		if block >= 0 {
			gap := h - len(lines)
			padOf := make([]int, gap)
			for i := range padOf {
				padOf[i] = -1
			}
			lines = append(append(append([]string{}, lines[:block]...), make([]string, gap)...), lines[block:]...)
			rowOf = append(append(append([]int{}, rowOf[:block]...), padOf...), rowOf[block:]...)
		}
		return lines, rowOf
	}
	top := max(min(m.railTop, len(lines)-h), 0)
	end := min(top+max(h, 0), len(lines))
	return lines[top:end], rowOf[top:end]
}

// railLineOf is the line of the undocked rail that holds row i.
func (m model) railLineOf(i int) int {
	_, rowOf, _ := m.railAll()
	for n, r := range rowOf {
		if r == i {
			return n
		}
	}
	return 0
}

func (m model) railLine(r railRow, selectedRow bool, inner int) string {
	if r.kind == rowProject {
		return m.projHeader(selectedRow, inner)
	}
	var mark string
	switch r.kind {
	case rowProvider:
		switch {
		case m.errs[r.name] != nil:
			mark = red().Render("!")
		case m.busy[r.name] != "":
			mark = accent().Render(spinner[m.frame%len(spinner)])
		}
	case rowPart:
		for _, lf := range m.partLockfiles(r) {
			switch {
			case lf.Err != "":
				mark = red().Render("!")
			case lf.Missing != "" && mark == "":
				mark = yellow().Render("◌")
			}
		}
	}
	indent := "  "
	if r.kind == rowPart {
		indent = "    "
	}
	line := indent + icon(r.icon) + " " + pad(r.name, max(inner-15-len(indent), 3)) + m.badges(r) + " " + mark
	if selectedRow {
		line = selected(line, inner, m.focus == focusRail)
	}
	return line
}

// badges is a row's count, then its filter mark, vulnerable and outdated.
func (m model) badges(r railRow) string {
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
	return fmt.Sprintf("%4d", t.total) + " " + strings.Join(badges, " ")
}

// projHeader is the project section's selectable header, ▸ closed or ▾ open.
func (m model) projHeader(selectedRow bool, inner int) string {
	arrow := "▸"
	if m.projOpen {
		arrow = "▾"
	}
	nameW := max(inner-17, 6)
	name := m.projName()
	if n := len(m.proj.Projects); n > 1 {
		count := fmt.Sprintf(" · %d projects", n)
		name = ansi.Truncate(name, max(nameW-len(count), 1), "…") + count
	}
	var mark string
	if m.projBusy != "" {
		mark = accent().Render(spinner[m.frame%len(spinner)])
	}
	line := arrow + " " + icon("project") + " " + pad(name, nameW) + m.badges(railRow{kind: rowProject, key: "project"}) + " " + mark
	if selectedRow {
		line = selected(line, inner, m.focus == focusRail)
	}
	return line
}

// projStatusLine stands in for the header while there is nothing to select:
// the scan is running, it failed, or the folder has no lockfiles.
func (m model) projStatusLine() string {
	name := icon("project") + " " + m.projName()
	switch {
	case m.projBusy == projReading:
		return "▸ " + name + "  " + accent().Render(spinner[m.frame%len(spinner)]) + faint().Render(" reading lockfiles")
	case m.projErr != nil:
		return "  " + name + red().Render(" · "+m.projErr.Error())
	}
	return faint().Render("  " + name + " · no lockfiles")
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

// hidden is a row the d or p toggle leaves out. A vulnerable dependency
// always shows, so hiding dependencies never hides risk. Hiding dev packages
// is asking to leave their risk out, so it does.
func (m model) hidden(p provider.Package) bool {
	switch {
	case p.Dev && m.prodOnly:
		return true
	case p.Dependency && !m.showDeps:
		return len(m.vulns[pkgKey(p)]) == 0
	}
	return false
}
