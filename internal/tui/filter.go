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

// Each source keeps its own filter, so filtering one never hides packages on
// another.
func (m model) filter() string {
	if m.showHistory {
		return m.hFilter
	}
	return m.filters[m.curRow().key]
}

func (m *model) setFilter(f string) {
	if m.showHistory {
		m.hFilter, m.hCursor = f, 0
		return
	}
	m.filters[m.curRow().key] = f
}

func (m model) status() int { return m.statuses[m.curRow().key] }

func (m *model) setStatus(s int) {
	m.statuses[m.curRow().key] = (s + len(statusNames)) % len(statusNames)
	m.cursor, m.offset = 0, 0
}

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
		return p.NoLock() || p.Unmanaged()
	case statusOK:
		return m.statusRank(p) == rankOK
	}
	return true
}

func (m model) counts() []int {
	n := make([]int, len(statusNames))
	for _, pkg := range m.rowPkgs(m.curRow()) {
		if m.hidden(pkg) || m.filter() != "" && !strings.Contains(strings.ToLower(pkg.Name), strings.ToLower(m.filter())) {
			continue
		}
		for s := range statusNames {
			if m.isStatus(pkg, s) {
				n[s]++
			}
		}
	}
	return n
}

func (m model) statusChips() (names, icons []string, counts []int, active int) {
	if isImageRow(m.curRow().kind) {
		return imageStatusNames, imageStatusIcons, m.imgCounts(), m.imgStatus()
	}
	return statusNames, statusIcons, m.counts(), m.status()
}

type chipEntry struct {
	status int
	text   string
}

// A narrow table drops the tail rather than cutting a chip in half, and never
// drops the one that is on.
func (m model) filterBarChips() (string, []chipEntry) {
	names, icons, counts, active := m.statusChips()
	head := m.filterBox()
	var chips []chipEntry
	for i := range names {
		chips = append(chips, chipEntry{status: i, text: m.chip(names, icons, i, active, counts[i])})
	}
	width := func(list []chipEntry) int {
		var texts []string
		for _, c := range list {
			texts = append(texts, c.text)
		}
		return lipgloss.Width(head + strings.Join(texts, " "))
	}
	limit := m.layout().tableW - 4
	for len(chips) > 1 && width(chips) > limit {
		drop := len(chips) - 1
		if chips[drop].status == active {
			drop--
		}
		if drop < 0 {
			break
		}
		chips = append(chips[:drop], chips[drop+1:]...)
	}
	return head, chips
}

func (m model) filterBar() string {
	head, chips := m.filterBarChips()
	var texts []string
	for _, c := range chips {
		texts = append(texts, c.text)
	}
	return head + strings.Join(texts, " ")
}

// The filter box keeps one width while typing, so the label stays and the
// chips never move. It grows with the table but stays narrow enough to leave
// the active chip beside it on the smallest terminal kho draws.
const (
	filterBoxMin = 20
	filterBoxMax = 30
)

func (m model) filterBoxWidth() int {
	return min(filterBoxMax, max(filterBoxMin, m.layout().tableW-12))
}

func (m model) filterBox() string {
	prefix := " " + accent().Render("⌕ filter ")
	w := m.filterBoxWidth()
	cursor, hint := "", ""
	switch {
	case m.filtering && m.filter() == "":
		cursor, hint = accent().Render("▏"), faint().Render("part of a name")
	case m.filtering:
		cursor = accent().Render("▏")
	case m.filter() != "":
		if clear := faint().Render("  esc clears"); lipgloss.Width(prefix+m.filter()+clear) <= w {
			hint = clear
		}
	}
	return pad(fitBar(prefix, m.filter(), cursor, hint, w), w)
}

const filterWidth = 14

func (m model) chip(names, icons []string, i, active, count int) string {
	if i == active {
		return pillOn(fmt.Sprintf("%s %d", names[i], count), th.accent, th.pillFg)
	}
	return lipgloss.NewStyle().Foreground(th.muted).Padding(0, 1).Render(fmt.Sprintf("%s %d", icons[i], count))
}

// Returns -1 for no chip, -2 for the keyword box.
func (m model) chipAt(x int) int {
	head, chips := m.filterBarChips()
	edge := lipgloss.Width(head)
	if x < edge {
		return -2
	}
	for _, c := range chips {
		edge += lipgloss.Width(c.text) + 1
		if x < edge {
			return c.status
		}
	}
	return -1
}
