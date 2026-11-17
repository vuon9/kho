package tui

import (
	"fmt"
	"slices"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/provider"
)

const (
	rowAll = iota
	rowProvider
	rowProject
	rowPart
	rowImages
	rowMachineImages
)

// key names it in filters and statuses, so each row keeps its own even when
// rows above it come and go. A part of the project stands for one lockfile, or
// every lockfile in dir.
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
	if len(m.machineImgs) > 0 || m.imgBusy {
		rows = append(rows, railRow{kind: rowMachineImages, name: "docker", icon: "docker", key: "machine:docker"})
	}
	if m.projReady() {
		rows = append(rows, railRow{kind: rowProject, name: m.projName(), icon: "project", key: "project"})
		if m.projOpen {
			rows = append(rows, m.projParts()...)
		}
		if len(m.images) > 0 || m.imgBusy {
			rows = append(rows, railRow{kind: rowImages, name: "docker", icon: "docker", key: "project:images"})
		}
	}
	return rows
}

func (m model) curRow() railRow {
	r, _ := at(m.railRows(), m.rail)
	return r
}

func (m model) inProject() bool { return m.curRow().kind >= rowProject }

func (m model) rowPkgs(r railRow) []provider.Package {
	switch r.kind {
	case rowProvider:
		return m.pkgs[r.name]
	case rowProject:
		return m.projPkgs()
	case rowPart:
		return m.partPkgs(r)
	case rowImages, rowMachineImages:
		return nil
	}
	return m.allPkgs()
}

func (m *model) setRail(i int) {
	rows := m.railRows()
	i = max(min(i, len(rows)-1), 0)
	if i != m.rail {
		m.rail, m.cursor, m.offset = i, 0, 0
		// Search is transient and never carries a query into a panel the
		// person did not ask about.
		m.search = nil
	}
	m.railKey = rows[i].key
}

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

// rowOf and block are -1 for none. The header is only a row once the scan
// found something to select.
func (m model) railAll() (lines []string, rowOf []int, block int) {
	inner := m.layout().railW - 2
	rule := projRule(inner)
	block = -1
	rows := m.railRows()
	signsOnly := false
	for _, r := range rows {
		// A folder name can be any length, so the project row is cut instead.
		if r.kind != rowProject {
			signsOnly = signsOnly || lipgloss.Width(r.name) > inner-15-railIndent(r)
		}
	}
	for i, r := range rows {
		if r.kind == rowProject {
			block = len(lines)
			lines, rowOf = append(lines, rule), append(rowOf, -1)
		}
		lines, rowOf = append(lines, m.railLine(r, i == m.rail, inner, signsOnly)), append(rowOf, i)
	}
	if m.dir != "" && !m.projReady() {
		block = len(lines)
		lines, rowOf = append(lines, rule, m.projStatusLine()), append(rowOf, -1, -1)
	}
	return lines, rowOf, block
}

// The block is pinned only when the rail overflows and it leaves the Machine
// rows at least two lines.
func pinned(total, block, h int) bool {
	return block >= 0 && total > h && total-block <= h-2
}

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

func projRule(inner int) string {
	label := "── Project "
	return fg(th.subtle).Render("── ") + faint().Bold(true).Render("Project") + " " + fg(th.subtle).Render(strings.Repeat("─", max(inner-len([]rune(label)), 0)))
}

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

func (m model) railLineOf(i int) int {
	_, rowOf, _ := m.railAll()
	for n, r := range rowOf {
		if r == i {
			return n
		}
	}
	return 0
}

func railIndent(r railRow) int {
	if r.kind == rowPart {
		return 4
	}
	return 2
}

func (m model) railLine(r railRow, selectedRow bool, inner int, signsOnly bool) string {
	if r.kind == rowProject {
		return m.projHeader(selectedRow, inner, signsOnly)
	}
	var mark string
	switch r.kind {
	case rowProvider:
		switch {
		case m.errs[r.name] != nil:
			mark = red().Render("!")
		case m.busy[r.name] != "":
			mark = m.spin()
		}
	case rowImages, rowMachineImages:
		if m.imgBusy {
			mark = m.spin()
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
	indent := strings.Repeat(" ", railIndent(r))
	nameW, badges := m.railFit(r, inner-15-len(indent), inner-len(indent)-3, signsOnly)
	line := indent + icon(r.icon) + " " + pad(r.name, nameW) + badges + " " + mark
	if selectedRow {
		line = selected(line, inner, m.focus == focusRail)
	}
	return line
}

// A narrow rail keeps every row's whole name and its signs, and drops the
// counts, since a cut name can't be read and the table shows the counts.
func (m model) railFit(r railRow, nameW, room int, signsOnly bool) (int, string) {
	if !signsOnly {
		return nameW, m.badges(r, false)
	}
	signs := pad(m.badges(r, true), 3)
	return max(room-lipgloss.Width(signs)-2, 3), signs
}

func (m model) badges(r railRow, signsOnly bool) string {
	if r.kind == rowImages || r.kind == rowMachineImages {
		list := m.images
		if r.kind == rowMachineImages {
			list = m.machineImgs
		}
		var eol, gone, stale int
		for _, img := range list {
			switch img.State {
			case image.EOL:
				eol++
			case image.Gone:
				gone++
			case image.Stale:
				stale++
			}
		}
		b := railBadges{signsOnly: signsOnly}
		b.add(red(), image.EOL.Mark(), eol)
		b.add(red(), image.Gone.Mark(), gone)
		b.add(yellow(), image.Stale.Mark(), stale)
		return b.render(len(list))
	}
	t := m.count(m.rowPkgs(r))
	b := railBadges{signsOnly: signsOnly}
	if m.filters[r.key] != "" || m.statuses[r.key] != statusAll {
		b.parts = append(b.parts, accent().Render("⌕"))
	}
	b.add(red(), "⚠", t.vulnerable)
	b.add(yellow(), "↑", t.outdated)
	return b.render(t.total)
}

type railBadges struct {
	signsOnly bool
	parts     []string
}

func (b *railBadges) add(style lipgloss.Style, mark string, n int) {
	switch {
	case n == 0:
	case b.signsOnly:
		b.parts = append(b.parts, style.Render(mark))
	default:
		b.parts = append(b.parts, style.Render(fmt.Sprintf("%s%d", mark, n)))
	}
}

func (b railBadges) render(total int) string {
	if b.signsOnly {
		return strings.Join(b.parts, "")
	}
	return fmt.Sprintf("%4d", total) + " " + strings.Join(b.parts, " ")
}

func (m model) projHeader(selectedRow bool, inner int, signsOnly bool) string {
	arrow := "▸"
	if m.projOpen {
		arrow = "▾"
	}
	nameW := max(inner-17, 6)
	name := m.projName()
	if count := fmt.Sprintf(" · %d projects", len(m.proj.Projects)); len(m.proj.Projects) > 1 && nameW-len(count) >= 4 {
		name = ansi.Truncate(name, nameW-len(count), "…") + count
	}
	var mark string
	if m.projBusy != "" {
		mark = m.spin()
	}
	nameW, badges := m.railFit(railRow{kind: rowProject, key: "project"}, nameW, inner-5, signsOnly)
	line := arrow + " " + icon("project") + " " + pad(name, nameW) + badges + " " + mark
	if selectedRow {
		line = selected(line, inner, m.focus == focusRail)
	}
	return line
}

func (m model) projStatusLine() string {
	name := icon("project") + " " + m.projName()
	switch {
	case m.projBusy == projReading:
		return "▸ " + name + "  " + m.spin() + faint().Render(" reading lockfiles")
	case m.projErr != nil:
		return "  " + name + red().Render(" · "+m.projErr.Error())
	}
	return faint().Render("  " + name + " · no lockfiles")
}

func (m model) railRowAt(y int) int {
	_, rowOf := m.railLines(m.layout().bodyH - 2)
	if r, ok := at(rowOf, y); ok {
		return r
	}
	return -1
}

func (m model) railBody(h int) []string {
	lines, _ := m.railLines(h)
	return lines
}

// A vulnerable dependency always shows, so hiding dependencies never hides
// risk. Hiding dev packages is asking to leave their risk out, so it does.
func (m model) hidden(p provider.Package) bool {
	switch {
	case p.Dev && m.prodOnly:
		return true
	case p.Dependency && !m.showDeps:
		return len(m.vulns[pkgKey(p)]) == 0
	}
	return false
}
