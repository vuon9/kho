package tui

import (
	"cmp"
	"fmt"
	"regexp"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

// line is one row of sidebar text. A row with a url opens it when clicked.
// A labeled row wraps its value under the value, not under the label, and a
// list row is never wrapped so each entry stays one row.
type line struct {
	text   string
	url    string
	label  string
	nowrap bool
}

func field(label, value, url string) line {
	return line{label: label, text: value, url: url}
}

func row(text string) line {
	return line{text: text, nowrap: true}
}

// wrapLines folds every line to width, so nothing in the sidebar is cut off.
func wrapLines(lines []line, width int) []line {
	var out []line
	for _, l := range lines {
		if l.label != "" {
			labelW := max(10, len(l.label)+1)
			for i, v := range wrapStyled(l.text, max(width-1-labelW, 8)) {
				head := strings.Repeat(" ", labelW)
				if i == 0 {
					head = faint().Render(pad(l.label, labelW))
				}
				out = append(out, line{text: " " + head + v, url: l.url, nowrap: true})
			}
			continue
		}
		if l.nowrap || lipgloss.Width(l.text) <= width {
			out = append(out, l)
			continue
		}
		for i, v := range wrapStyled(l.text, width-1) {
			if i > 0 {
				v = " " + v
			}
			out = append(out, line{text: v, url: l.url, nowrap: true})
		}
	}
	return out
}

var escapes = regexp.MustCompile("\x1b\\]8;[^;\x07\x1b]*;([^\x07\x1b]*)(?:\x07|\x1b\\\\)|\x1b\\[([0-9;:]*)m")

// wrapStyled wraps styled text and makes each line stand alone. A link or
// style still open where a line breaks is closed there and opened again on
// the next line; left open, it runs on into the panels beside the sidebar,
// which terminals draw as a dotted line across the screen.
func wrapStyled(text string, width int) []string {
	lines := strings.Split(ansi.Wrap(text, width, ""), "\n")
	link, style := "", ""
	for i, l := range lines {
		l = link + style + l
		for _, m := range escapes.FindAllStringSubmatch(l, -1) {
			switch {
			case strings.HasPrefix(m[0], "\x1b]8;"):
				link = m[0]
				if m[1] == "" {
					link = ""
				}
			case m[2] == "" || m[2] == "0":
				style = ""
			default:
				style += m[0]
			}
		}
		if link != "" {
			l += ansi.ResetHyperlink()
		}
		if style != "" {
			l += ansi.ResetStyle
		}
		lines[i] = l
	}
	return lines
}

func plain(texts ...string) []line {
	var out []line
	for _, t := range texts {
		out = append(out, line{text: t})
	}
	return out
}

var shortTabNames = map[int]string{tabInfo: "Info", tabVersions: "Ver", tabSecurity: "Sec", tabSkill: "Skill", tabReadme: "Read", tabLinks: "Links"}

func tabLabel(name string, active bool) string {
	if active {
		return pillOn(name, th.accent, th.pillFg)
	}
	return lipgloss.NewStyle().Foreground(th.muted).Padding(0, 1).Render(name)
}

// tabLabels names the tabs in full, or shortened when the full names don't
// fit across the sidebar.
func (m model) tabLabels() []string {
	build := func(names map[int]string) []string {
		var labels []string
		for _, t := range m.tabs() {
			labels = append(labels, tabLabel(names[t], t == m.activeTab()))
		}
		return labels
	}
	labels := build(tabNames)
	if lipgloss.Width(strings.Join(labels, " ")) > m.layout().sideW-6 {
		labels = build(shortTabNames)
	}
	return labels
}

func (m model) tabBar() string {
	return strings.Join(m.tabLabels(), " ")
}

// hasBottom says whether the active tab splits the sidebar. Long reads, like
// a README, use the whole height instead.
func (m model) hasBottom() bool {
	p, ok := m.current()
	if !ok {
		return false
	}
	switch m.activeTab() {
	case tabReadme:
		return false
	case tabSecurity:
		return p.Source != "skills"
	}
	return true
}

// sideListLen is the length of the active tab's list, or -1 for tabs that
// show text rather than a list.
func (m model) sideListLen() int {
	p, ok := m.current()
	if !ok {
		return -1
	}
	switch m.activeTab() {
	case tabVersions:
		return len(m.currentVersions())
	case tabSecurity:
		if p.Source == "skills" {
			return -1
		}
		return len(m.securityEntries())
	case tabLinks:
		return len(m.links)
	}
	return -1
}

// topView and bottomView are the sidebar halves as drawn: wrapped to width,
// except list rows.
func (m model) topView(inner int) []line {
	return wrapLines(m.topLines(inner), inner)
}

func (m model) bottomView(inner int) []line {
	return wrapLines(m.bottomLines(inner), inner)
}

func (m model) sideBox(w, h int, focused bool) string {
	l := m.layout()
	inner := w - 2
	e := edge(focused)
	top := e.Render("╭─") + " " + m.tabBar() + " "
	top += e.Render(strings.Repeat("─", max(w-1-lipgloss.Width(top), 0)) + "╮")
	out := []string{top}
	row := func(s string) string { return e.Render("│") + pad(s, inner) + e.Render("│") }

	tops := m.topView(inner)
	list := m.sideListLen() >= 0
	for i := range l.topRows {
		idx := m.sideOffset + i
		switch {
		case list && i == 0 && len(tops) > 0:
			idx = 0
		case list:
			idx = m.sideOffset + i
		}
		text := ""
		if idx < len(tops) {
			text = tops[idx].text
		}
		if from, to, ok := m.sel.span(areaTop, idx, inner); ok && !list {
			text = highlight(text, from, to)
		}
		if list && i > 0 && idx-1 == m.sideCursor && idx < len(tops) {
			text = selected(text, inner, focused && m.sidePart == 0)
		}
		out = append(out, row(text))
	}
	if m.hasBottom() {
		title := m.bottomTitle()
		active := focused && m.sidePart == 1
		div := e.Render("├─ ") + boxTitle(title, active) + " "
		out = append(out, div+e.Render(strings.Repeat("─", max(w-1-lipgloss.Width(div), 0))+"┤"))
		bottoms, deps := m.bottomView(inner), m.depList()
		for i := range l.bottomRows {
			text := ""
			j := m.bodyOffset + i
			if j < len(bottoms) {
				text = bottoms[j].text
			}
			if from, to, ok := m.sel.span(areaBottom, j, inner); ok {
				text = highlight(text, from, to)
			}
			if j == m.depCursor && j < len(deps) {
				text = selected(text, inner, focused)
			}
			out = append(out, row(text))
		}
	}
	out = append(out, e.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return strings.Join(out, "\n")
}

func (m model) topLines(inner int) []line {
	p, ok := m.current()
	if !ok {
		return plain("", faint().Render(" pick a package to see it here"))
	}
	switch m.activeTab() {
	case tabVersions:
		return m.versionLines(p, inner)
	case tabSecurity:
		if p.Source == "skills" {
			return m.auditLines(p)
		}
		return m.securityLines(p, inner)
	case tabSkill:
		return m.skillMetaLines(p)
	case tabReadme:
		return m.readmeLines(p, inner)
	case tabLinks:
		return linkLines(m.links)
	}
	return m.infoLines(p)
}

func (m model) bottomTitle() string {
	p, _ := m.current()
	switch m.activeTab() {
	case tabVersions:
		if r, ok := at(m.currentVersions(), m.sideCursor); ok {
			return "📜 Changelog · " + r.Version
		}
		return "📜 Changelog"
	case tabSecurity:
		if e, ok := at(m.securityEntries(), m.sideCursor); ok {
			return "🛡 " + e.adv.ID
		}
		return "🛡 Advisory"
	case tabSkill:
		return "📄 SKILL.md"
	case tabLinks:
		if l, ok := at(m.links, m.sideCursor); ok {
			return "🔗 " + agentName(l)
		}
		return "🔗 Link"
	}
	if p.Source == "skills" {
		linked := 0
		for _, l := range installed(m.links) {
			if l.Sees() {
				linked++
			}
		}
		return fmt.Sprintf("🔗 Seen by %d agents", linked)
	}
	if d := m.deps[pkgKey(p)]; d != nil && d.done && d.err == nil {
		return fmt.Sprintf("🔗 Dependencies · %d", len(d.val))
	}
	return "🔗 Dependencies"
}

func (m model) bottomLines(inner int) []line {
	p, _ := m.current()
	switch m.activeTab() {
	case tabVersions:
		return m.changelogLines(p, inner)
	case tabSecurity:
		return m.advisoryLines(p, inner)
	case tabSkill:
		d := m.docs[pkgKey(p)]
		switch {
		case d == nil || !d.done:
			return plain(faint().Render(" loading…"))
		case d.err != nil:
			return plain(red().Render(" " + d.err.Error()))
		}
		return plain(m.md.render(d.val.Body, inner)...)
	case tabLinks:
		return m.linkDetail(p)
	}
	if p.Source == "skills" {
		return linkLines(installed(m.links))
	}
	return m.depLines(p, inner)
}

func (m model) infoLines(p provider.Package) []line {
	lines := plain(" "+icon(provider.ProviderOf(p))+" "+accent().Render(p.Name)+faint().Render(" · "+p.Source), "")
	add := func(label, value, url string) {
		if value == "" {
			return
		}
		if url != "" {
			value = link(url).Render(value)
		}
		lines = append(lines, field(label, value, url))
	}
	add("about", p.Desc, "")
	version := p.Version
	if p.Latest != "" && p.Latest != p.Version {
		version += " → " + green().Render(p.Latest)
	}
	add("version", version, "")
	if len(p.Versions) > 1 {
		add("installed", strings.Join(p.Versions, ", "), "")
	}
	add("security", m.securitySummary(p), "")
	add("from", p.Origin, "")
	if home := homeURL(p); home != "" {
		add("home", home, home)
	}
	if p.Repo != "" && "https://github.com/"+p.Repo != homeURL(p) {
		add("repo", "github.com/"+p.Repo, "https://github.com/"+p.Repo)
	}
	if p.Source == "skills" {
		add("path", tilde(provider.RealPath(p)), "")
	} else {
		add("path", p.Path, "")
	}
	if p.Source == "skills" {
		add("agents", strings.Join(p.Agents, ", "), "")
	}
	add("note", p.Note, "")
	if p.Dependency {
		add("note", "installed as a dependency", "")
	}
	if err := m.errs[provider.ProviderOf(p)]; err != nil {
		add("error", red().Render(err.Error()), "")
	}
	return lines
}

func (m model) securitySummary(p provider.Package) string {
	if p.Source == "skills" {
		a, ok := m.audit(p)
		if !ok {
			return faint().Render("no skills.sh audit")
		}
		return verdictPill(vuln.Verdict(a.Worst())) + faint().Render(" worst of 3 audits on skills.sh")
	}
	q, ok := provider.Query(p)
	if !ok {
		return faint().Render("not covered: OSV has no data for " + p.Source)
	}
	if _, checked := m.db.Checked[q.Key()]; !checked {
		return faint().Render("not checked yet")
	}
	advs := m.vulns[pkgKey(p)]
	deps := len(m.depVulns[pkgKey(p)])
	var parts []string
	switch {
	case len(advs) > 0:
		parts = append(parts, red().Render(fmt.Sprintf("⚠ %d known in %s", len(advs), p.Version)))
		if fix := fixFor(advs, p.Version); fix != "" {
			parts = append(parts, green().Render("fixed in "+fix))
		}
	default:
		parts = append(parts, green().Render("✓ no known advisories"))
	}
	if deps > 0 {
		parts = append(parts, orange().Render(fmt.Sprintf("◆ %d in deps", deps)))
	}
	return strings.Join(parts, faint().Render(" · "))
}

// fixFor is the lowest version that fixes every advisory, or "" when one of
// them has no fix yet.
func fixFor(advs []vuln.Advisory, version string) string {
	best := ""
	for _, a := range advs {
		f := a.FixedAfter(version)
		if f == "" {
			return ""
		}
		if vuln.Compare(f, best) > 0 {
			best = f
		}
	}
	return best
}

// depList is the dependencies the Info tab lists for ↑↓ to pick from.
func (m model) depList() []provider.Dep {
	p, ok := m.current()
	if !ok || p.Source == "skills" || m.activeTab() != tabInfo {
		return nil
	}
	if d := m.deps[pkgKey(p)]; d != nil && d.done && d.err == nil {
		return d.val
	}
	return nil
}

// depPopup shows one of a package's dependencies and its advisories over the
// screen.
type depPopup struct {
	pkg provider.Package
	dep provider.Dep
	top int
}

func (m *model) openDep(i int) {
	p, _ := m.current()
	if d, ok := at(m.depList(), i); ok {
		m.depPop, m.sel = &depPopup{pkg: p, dep: d}, nil
	}
}

// depAdvisories is what the security cache holds for one of p's
// dependencies: its advisories, and whether osv.dev was asked about it.
func (m model) depAdvisories(p provider.Package, d provider.Dep) ([]vuln.Advisory, bool) {
	q, ok := provider.DepQuery(p, d)
	if !ok {
		return nil, false
	}
	_, checked := m.db.Checked[q.Key()]
	return m.db.For(q), checked
}

func (m model) depPopTitle() string {
	p, d := m.depPop.pkg, m.depPop.dep
	advs, _ := m.depAdvisories(p, d)
	title := "◆ " + d.Name + " " + d.Version
	switch n := len(advs); {
	case n == 1:
		title += " · 1 advisory"
	case n > 1:
		title += fmt.Sprintf(" · %d advisories", n)
	}
	return title
}

// depPopView is the dependency popup's text, wrapped to fit it. It calls a
// dependency clean only once osv.dev has answered for that very version.
func (m model) depPopView() []line {
	_, _, w, _ := m.depRect()
	inner := w - 2
	p, d := m.depPop.pkg, m.depPop.dep
	advs, checked := m.depAdvisories(p, d)
	_, asked := provider.DepQuery(p, d)
	var lines []line
	for _, a := range advs {
		if len(lines) > 0 {
			lines = append(lines, line{}, row(faint().Render(" "+strings.Repeat("─", max(inner-2, 0)))), line{})
		}
		lines = append(lines, row(" "+accent().Render(a.ID)))
		lines = append(lines, m.advisoryDetail(a, "", d.Version, "", inner)...)
	}
	again := faint().Render(" R checks again.")
	switch {
	case len(lines) > 0:
	case provider.Ecosystem(p) == "":
		lines = plain("", faint().Render(" OSV has no data for "+p.Source+", so kho can't check "+d.Name+"."))
	case checked:
		lines = plain("", green().Render(" ✓ No known advisories for "+d.Name+" "+d.Version))
	case !provider.Released(d.Version):
		lines = plain("", faint().Render(" "+d.Name+" has no release version to check on osv.dev."))
	case !asked:
		lines = plain("", faint().Render(" kho doesn't check "+p.Source+" dependencies on osv.dev, so "+d.Name+" isn't checked."))
	case m.scanning > 0:
		lines = plain("", faint().Render(" "+spinner[m.frame%len(spinner)]+" checking osv.dev…"))
	case m.secErr != nil:
		lines = plain("", red().Render(" security check failed: "+m.secErr.Error()), again)
	default:
		lines = plain("", faint().Render(" "+d.Name+" isn't checked yet."), again)
	}
	return wrapLines(lines, inner)
}

func (m model) depLines(p provider.Package, inner int) []line {
	d := m.deps[pkgKey(p)]
	switch {
	case d == nil || !d.done:
		return plain(faint().Render(" loading…"))
	case d.err != nil:
		return plain(red().Render(" " + d.err.Error()))
	case len(d.val) == 0:
		return plain(faint().Render(" no dependencies"))
	}
	nameW := max(inner-24, 12)
	var lines []line
	for _, dep := range d.val {
		mark := faint().Render("·")
		if dep.Direct {
			mark = accent().Render("•")
		}
		text := fmt.Sprintf(" %s %s %s", mark, pad(dep.Name, nameW), faint().Render(dep.Version))
		if advs, _ := m.depAdvisories(p, dep); len(advs) > 0 {
			text = fmt.Sprintf(" %s %s %s %s", red().Render("⚠"), pad(dep.Name, nameW), dep.Version, red().Render(fmt.Sprintf("%d vuln", len(advs))))
		}
		lines = append(lines, row(text))
	}
	return lines
}

func (m model) versionLines(p provider.Package, inner int) []line {
	v := m.versions[pkgKey(p)]
	switch {
	case v == nil || !v.done:
		return plain(faint().Render(" " + spinner[m.frame%len(spinner)] + " loading versions…"))
	case v.err != nil:
		return plain(red().Render(" " + v.err.Error()))
	case len(v.val) == 0:
		return plain(faint().Render(" no versions published"))
	}
	eco, name := provider.Ecosystem(p), provider.OSVName(p)
	known := m.db.Known(eco, name)
	history := eco != "" && m.db.HistoryFresh(eco, name, now())
	verW := max(min(inner-36, 22), 10)
	lines := plain("  " + faint().Bold(true).Render(pad("VERSION", verW)+" "+pad("DATE", 10)+" NOTES  SECURITY"))
	for _, r := range v.val {
		date := ""
		if !r.Date.IsZero() {
			date = r.Date.Format("2006-01-02")
		}
		notes := "      "
		if strings.TrimSpace(r.Notes) != "" {
			notes = cyan().Render("≡ yes ")
		}
		var tags []string
		affected := 0
		for _, a := range known {
			if a.Affects(r.Version) {
				affected++
			}
		}
		switch {
		case affected > 0:
			tags = append(tags, red().Render(fmt.Sprintf("⚠ %d", affected)))
		case history && vuln.Compare(r.Version, p.Version) > 0:
			tags = append(tags, green().Render("✓ safe"))
		}
		if provider.TagVersion(r.Version) == provider.TagVersion(p.Version) {
			tags = append(tags, pill("installed", th.green))
		}
		lines = append(lines, row("  "+pad(r.Version, verW)+" "+pad(faint().Render(date), 10)+" "+notes+" "+strings.Join(tags, " ")))
	}
	return lines
}

func (m model) changelogLines(p provider.Package, inner int) []line {
	r, ok := at(m.currentVersions(), m.sideCursor)
	if !ok {
		return nil
	}
	var lines []line
	eco, name := provider.Ecosystem(p), provider.OSVName(p)
	for _, a := range m.db.Known(eco, name) {
		if a.Affects(r.Version) {
			lines = append(lines, line{text: " " + severityPill(a.Severity) + " " + red().Render(a.ID) + " " + faint().Render(a.Summary), url: a.URL()})
		}
	}
	if len(lines) > 0 {
		lines = append(lines, line{})
	}
	switch {
	case strings.TrimSpace(r.Notes) != "":
		lines = append(lines, plain(m.md.render(r.Notes, inner)...)...)
	case r.URL != "":
		lines = append(lines,
			line{text: " " + yellow().Render("No changelog found for "+r.Version+".")},
			line{},
			line{text: " Open the release page in your browser?"},
			line{text: " " + link(r.URL).Render(r.URL), url: r.URL},
			line{text: " " + accent().Render("y") + faint().Render(" open the page  ") + accent().Render("↑↓") + faint().Render(" another version")},
		)
	default:
		lines = append(lines, line{text: faint().Render(" No changelog or release page found for " + r.Version + ".")})
	}
	return lines
}

type securityEntry struct {
	adv vuln.Advisory
	dep string
}

func (m model) securityEntries() []securityEntry {
	p, ok := m.current()
	if !ok {
		return nil
	}
	var es []securityEntry
	for _, a := range m.vulns[pkgKey(p)] {
		es = append(es, securityEntry{adv: a})
	}
	for _, da := range m.depVulns[pkgKey(p)] {
		es = append(es, securityEntry{adv: da.adv, dep: da.dep.Name + "@" + da.dep.Version})
	}
	return es
}

func (m model) securityLines(p provider.Package, inner int) []line {
	q, ok := provider.Query(p)
	if !ok {
		return plain("", faint().Render(" 🛡  OSV has no data for "+p.Source+","), faint().Render("    so kho can't check this one yet."))
	}
	es := m.securityEntries()
	if len(es) == 0 {
		if _, checked := m.db.Checked[q.Key()]; !checked {
			return plain("", faint().Render(" "+spinner[m.frame%len(spinner)]+" checking osv.dev…"))
		}
		return plain("", green().Render(" ✓ No known advisories for "+p.Version), faint().Render(" checked "+ago(m.db.Checked[q.Key()])+" on osv.dev"))
	}
	lines := plain("  " + faint().Bold(true).Render(pad("SEV", 6)+" "+pad("ID", 20)+" FIX"))
	for _, e := range es {
		fix := red().Render("no fix yet")
		version := p.Version
		if e.dep != "" {
			_, version, _ = strings.Cut(e.dep, "@")
		}
		if f := e.adv.FixedAfter(version); f != "" {
			fix = green().Render("≥ " + f)
		}
		text := "  " + severityPill(e.adv.Severity) + " " + pad(e.adv.ID, 20) + " " + fix
		if e.dep != "" {
			text += faint().Render(" via " + e.dep)
		}
		lines = append(lines, row(text))
	}
	return lines
}

func (m model) advisoryLines(p provider.Package, inner int) []line {
	e, ok := at(m.securityEntries(), m.sideCursor)
	if !ok {
		return nil
	}
	version, latest := p.Version, p.Latest
	if e.dep != "" {
		_, version, _ = strings.Cut(e.dep, "@")
		latest = ""
	}
	return m.advisoryDetail(e.adv, e.dep, version, latest, inner)
}

// advisoryDetail is one advisory as it affects version, reached through a
// dependency when through is set. A latest version gets a word on whether
// upgrading to it clears the advisory.
func (m model) advisoryDetail(a vuln.Advisory, through, version, latest string, inner int) []line {
	lines := plain(" " + severityPill(a.Severity) + " " + bold().Render(ansi.Truncate(a.Summary, inner-10, "…")))
	lines = append(lines, line{})
	if through != "" {
		lines = append(lines, field("through", through, ""))
	}
	fix := red().Render("no fix published yet")
	if f := a.FixedAfter(version); f != "" {
		fix = green().Render(f)
		if latest != "" {
			if a.Affects(latest) {
				fix += red().Render(" · latest " + latest + " is still affected")
			} else {
				fix += faint().Render(" · latest " + latest + " is clear")
			}
		}
	}
	lines = append(lines, field("affects", version, ""), field("fixed in", fix, ""))
	if !a.Published.IsZero() {
		lines = append(lines, field("published", a.Published.Format("2006-01-02"), ""))
	}
	if len(a.Aliases) > 0 {
		lines = append(lines, field("aliases", strings.Join(a.Aliases, ", "), ""))
	}
	lines = append(lines, field("details", link(a.URL()).Render(a.URL()), a.URL()), line{})
	return append(lines, plain(m.md.render(a.Details, inner)...)...)
}

func (m model) auditLines(p provider.Package) []line {
	if p.Repo == "" {
		return plain("", faint().Render(" 🛡  skills.sh audits only cover skills"), faint().Render("    installed from GitHub."))
	}
	page := vuln.SkillPage(p.Repo, p.Name)
	a, ok := m.audit(p)
	if !ok {
		return []line{{}, {text: faint().Render(" No audit found on skills.sh yet.")}, {text: " " + link(page).Render(page), url: page}}
	}
	alerts := fmt.Sprintf("%d alerts", a.SocketAlerts)
	if a.SocketAlerts == 1 {
		alerts = "1 alert"
	}
	lines := []line{
		{text: " " + accent().Render("🛡 Security audits") + faint().Render(" from skills.sh")},
		{},
		{text: " " + pad("Gen Agent Trust Hub", 22) + verdictPill(vuln.Verdict(a.Gen)) + faint().Render(" "+a.Gen)},
		{text: " " + pad("Socket", 22) + verdictPill(vuln.Verdict(a.Socket)) + faint().Render(" "+alerts)},
		{text: " " + pad("Snyk", 22) + verdictPill(vuln.Verdict(a.Snyk)) + faint().Render(" "+a.Snyk)},
		{},
	}
	if !a.Analyzed.IsZero() {
		lines = append(lines, field("analyzed", a.Analyzed.Format("2006-01-02"), ""))
	}
	return append(lines, field("report", link(page).Render(page), page))
}

func (m model) skillMetaLines(p provider.Package) []line {
	d := m.docs[pkgKey(p)]
	switch {
	case d == nil || !d.done:
		return plain(faint().Render(" loading…"))
	case d.err != nil:
		return plain(red().Render(" " + d.err.Error()))
	}
	lines := plain(" " + icon("skills") + " " + accent().Render(p.Name))
	lines = append(lines, line{})
	for _, kv := range d.val.Meta {
		if kv[1] != "" {
			lines = append(lines, field(kv[0], kv[1], ""))
		}
	}
	return append(lines, field("files", strings.Join(d.val.Files, "  "), ""))
}

func (m model) readmeLines(p provider.Package, inner int) []line {
	d := m.docs[pkgKey(p)]
	switch {
	case d == nil || !d.done:
		return plain(faint().Render(" loading…"))
	case d.err != nil:
		return plain(red().Render(" " + d.err.Error()))
	case d.val.Readme == "":
		lines := plain("", faint().Render(" 📭 This skill has no README.md."))
		if p.Repo != "" {
			u := "https://github.com/" + p.Repo
			lines = append(lines, line{text: faint().Render(" The repo may have one: ") + link(u).Render(u), url: u})
		}
		return lines
	}
	return plain(m.md.render(d.val.Readme, inner)...)
}

func linkState(l provider.SkillLink) string {
	switch {
	case l.Kind == provider.LinkSymlink && l.Own:
		return green().Render("🔗 linked")
	case l.Kind == provider.LinkSymlink:
		return yellow().Render("⚠ broken")
	case l.Kind == provider.LinkCopy && l.Own:
		return cyan().Render("📁 copy")
	case l.Kind == provider.LinkCopy:
		return yellow().Render("⚠ no SKILL.md")
	case l.Shared:
		return faint().Render("≈ shared")
	}
	return faint().Render("· none")
}

// readLinks reads the selected skill's agents into the model: the installed
// ones, or with A every agent the skills CLI supports. The Links tab draws
// and acts on these rows, so enter always works on the row on screen.
func (m *model) readLinks() {
	p, _ := m.current()
	if pkgKey(p) == m.linksOf {
		return
	}
	m.links, m.linksOf = nil, pkgKey(p)
	if p.Source == "skills" {
		m.links = skillLinks(p, m.allAgents)
	}
}

// installed keeps the agents that are installed. The Info tab lists only
// those, whatever A shows on the Links tab.
func installed(links []provider.SkillLink) []provider.SkillLink {
	var out []provider.SkillLink
	for _, l := range links {
		if l.Installed {
			out = append(out, l)
		}
	}
	return out
}

func agentName(l provider.SkillLink) string { return cmp.Or(l.Display, l.Agent) }

func linkLines(links []provider.SkillLink) []line {
	lines := []line{row("  " + faint().Bold(true).Render(pad("AGENT", 16)+" "+pad("STATE", 15)+" PATH"))}
	for _, l := range links {
		state := linkState(l)
		if !l.Installed && l.Kind == provider.LinkMissing {
			state = faint().Render("· not installed")
		}
		lines = append(lines, row("  "+pad(agentName(l), 16)+" "+pad(state, 15)+" "+faint().Render(tilde(l.Path))))
	}
	return lines
}

func (m model) linkDetail(p provider.Package) []line {
	l, ok := at(m.links, m.sideCursor)
	if !ok {
		return nil
	}
	name := agentName(l)
	lines := []line{field("path", tilde(l.Path), ""), field("skill", tilde(provider.RealPath(p)), ""), {}}
	say := func(s string) { lines = append(lines, line{text: faint().Render(" " + s)}) }
	switch {
	case l.CanLink():
		if !l.Installed {
			say(name + " isn't installed yet; the link waits for it.")
		}
		lines = append(lines, line{text: " " + accent().Render("enter") + faint().Render(" links it into "+name+"'s own folder.")})
	case l.Kind == provider.LinkSymlink:
		if l.Target != "" {
			lines = append(lines, field("points to", tilde(l.Target), ""), line{})
		}
		switch {
		case !l.Own:
			say("This link leads to no SKILL.md, so " + name + " doesn't load the skill from it.")
			if l.Shared {
				say(name + " still sees the skill through ~/.agents/skills.")
			}
		case l.Shared:
			say(name + " also reads ~/.agents/skills, so it loads this skill twice.")
		}
		lines = append(lines, line{text: " " + accent().Render("enter") + faint().Render(" removes this link. The skill's files stay where they are.")})
	case l.Kind == provider.LinkCopy && l.Own:
		say("A copied folder, not a link. kho won't delete it.")
	case l.Kind == provider.LinkCopy:
		say("A folder with no SKILL.md, so " + name + " doesn't load the skill from it. kho won't delete it.")
	case l.Kind == provider.LinkNoFolder && l.Shared:
		say(name + " reads ~/.agents/skills directly, so it always sees this skill.")
	case l.Kind == provider.LinkNoFolder:
		say(name + " reads only ~/.agents/skills, and this skill isn't there.")
	default:
		say(name + " already sees it through ~/.agents/skills, so there is nothing to link.")
	}
	return lines
}
