package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/vuon9/kho/internal/provider"
)

const (
	statusAll = iota
	statusVulnerable
	statusOutdated
	statusPinned
	statusUntracked
	statusOK
)

var (
	statusNames = []string{"All", "⚠ Vulnerable", "↑ Outdated", "⚑ Pinned", "◌ Untracked", "✓ Up to date"}
	statusIcons = []string{"All", "⚠", "↑", "⚑", "◌", "✓"}
)

// filter and status are what the current screen shows. Each source keeps its
// own, so filtering one never hides packages on another.
func (m model) filter() string {
	if m.showHistory {
		return m.hFilter
	}
	return m.filters[m.rail]
}

func (m *model) setFilter(f string) {
	if m.showHistory {
		m.hFilter, m.hCursor = f, 0
		return
	}
	m.filters[m.rail] = f
}

func (m model) status() int { return m.statuses[m.rail] }

func (m *model) setStatus(s int) {
	m.statuses[m.rail] = (s + len(statusNames)) % len(statusNames)
	m.cursor, m.offset = 0, 0
}

// toggleStatus shows only s, or everything again when s is already shown.
func (m *model) toggleStatus(s int) {
	if m.status() == s {
		s = statusAll
	}
	m.setStatus(s)
}

func (m model) matchStatus(p provider.Package) bool {
	return m.isStatus(p, m.status())
}

func (m model) isStatus(p provider.Package, s int) bool {
	switch s {
	case statusVulnerable:
		return len(m.vulns[pkgKey(p)]) > 0 || m.riskyAudit(p)
	case statusOutdated:
		return p.Outdated
	case statusPinned:
		return p.Pinned
	case statusUntracked:
		return strings.HasPrefix(p.Note, "no lock") || strings.HasPrefix(p.Note, "only in")
	case statusOK:
		return m.statusRank(p) == rankOK
	}
	return true
}

// counts tallies the current screen by status, after the keyword filter, so
// each chip says how many packages it would show.
func (m model) counts() []int {
	n := make([]int, len(statusNames))
	for i, p := range m.providers {
		if m.rail != 0 && m.rail != i+1 {
			continue
		}
		for _, pkg := range m.pkgs[p.Name()] {
			if pkg.Dependency && !m.showDeps || m.filter() != "" && !strings.Contains(strings.ToLower(pkg.Name), strings.ToLower(m.filter())) {
				continue
			}
			for s := range statusNames {
				if m.isStatus(pkg, s) {
					n[s]++
				}
			}
		}
	}
	return n
}

// filterBar is the last line of the package panel: the keyword, then a chip
// for each status with its count, the active one lit and named in full.
func (m model) filterBar() string {
	query := faint().Render("/ to filter")
	switch {
	case m.filtering:
		query = m.filter() + accent().Render("▏")
	case m.filter() != "":
		query = m.filter()
	}
	bar := " " + accent().Render("⌕ ") + pad(query, filterWidth) + " "
	counts := m.counts()
	for i := range statusNames {
		bar += m.chip(i, counts[i]) + " "
	}
	return bar
}

const filterWidth = 14

func (m model) chip(i, count int) string {
	if i == m.status() {
		return pillOn(fmt.Sprintf("%s %d", statusNames[i], count), th.accent, th.pillFg)
	}
	return lipgloss.NewStyle().Foreground(th.muted).Padding(0, 1).Render(fmt.Sprintf("%s %d", statusIcons[i], count))
}

// chipAt maps an x offset within the package panel to the status chip under
// it, or -1, or -2 for the keyword box.
func (m model) chipAt(x int) int {
	edge := 1 + 2 + filterWidth + 1
	if x < edge {
		return -2
	}
	counts := m.counts()
	for i := range statusNames {
		edge += lipgloss.Width(m.chip(i, counts[i])) + 1
		if x < edge {
			return i
		}
	}
	return -1
}
