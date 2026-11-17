package tui

import (
	"cmp"
	"slices"
	"strings"

	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

var columns = []string{"NAME", "SOURCE", "VERSION", "LATEST", "STATUS"}

func (m model) sort(rows []provider.Package) {
	order := map[string]int{}
	for i, p := range m.providers {
		order[p.Name()] = i
	}
	slices.SortStableFunc(rows, func(a, b provider.Package) int {
		var c int
		switch m.sortCol {
		case colName:
			c = strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		case colSource:
			if m.skillScope() {
				c = strings.Compare(strings.ToLower(skillFrom(a)), strings.ToLower(skillFrom(b)))
			} else {
				c = cmp.Or(order[provider.ProviderOf(a)]-order[provider.ProviderOf(b)], strings.Compare(a.Source, b.Source))
			}
		case colVersion:
			c = vuln.Compare(a.Version, b.Version)
		case colLatest:
			c = vuln.Compare(a.Latest, b.Latest)
		case colStatus:
			c = m.statusRank(a) - m.statusRank(b)
		}
		if m.sortDesc {
			c = -c
		}
		return cmp.Or(c, strings.Compare(a.Name, b.Name))
	})
}

func (m model) statusRank(p provider.Package) int {
	switch {
	case len(m.vulns[pkgKey(p)]) > 0:
		return 0
	case m.riskyAudit(p):
		return 1
	case actionable(p):
		return 2
	case p.Pinned && p.Outdated:
		return 3
	case p.Pinned:
		return 4
	case p.NoLock():
		return 5
	case p.Unmanaged():
		return 6
	case p.Latest == "" || p.LatestUnknown():
		return 7
	}
	return rankOK
}

const rankOK = 8

func (m model) riskyAudit(p provider.Package) bool {
	a, ok := m.audit(p)
	return ok && vuln.Verdict(a.Worst()) == vuln.Fail
}
