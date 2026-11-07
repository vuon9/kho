package tui

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/trivy"
	"github.com/vuon9/kho/internal/vuln"
)

// scanImage runs the scanner over one image. Tests swap it.
var scanImage = trivy.Scan

// trivyAvailable says whether a scan can run at all.
var trivyAvailable = trivy.Available

type imageScanMsg struct {
	key   string
	vulns []trivy.Vuln
	err   error
}

// isImageRow says the selected rail row is one of the image lists.
func isImageRow(kind int) bool { return kind == rowImages || kind == rowMachineImages }

// Anything that reaches the network or the machine goes through a package
// variable, so tests can swap it.
var (
	findImages    = func(ctx context.Context, dir string) (image.Scan, error) { return image.Find(ctx, dir) }
	listImages    = image.ListLocal
	inspectImages = func(ctx context.Context, refs []image.Ref, local []image.LocalImage, asked bool, ask image.Asker) []image.Ref {
		return image.Inspect(ctx, refs, local, asked, ask, now())
	}
	machineImages = func(ctx context.Context, local []image.LocalImage, ask image.Asker) []image.Ref {
		return image.Machine(ctx, local, ask, now())
	}
	tagsFor = func(ctx context.Context, r image.Ref, ask image.Asker) []image.Tag {
		t, ok := ask.(interface {
			Tags(context.Context, image.Ref) ([]image.Tag, error)
		})
		if !ok {
			return nil
		}
		tags, err := t.Tags(ctx, r)
		if err != nil {
			return nil
		}
		return tags
	}
)

type imagesMsg struct {
	gen     int
	refs    []image.Ref
	machine []image.Ref
	tags    map[string][]image.Tag
	err     error
}

// imagesCmd reads the project's images and asks about each one, off the UI
// goroutine. It never pulls, builds or runs anything.
func (m model) imagesCmd() tea.Cmd {
	gen, dir, ask := m.imgGen, m.dir, m.imgAsk
	return func() tea.Msg {
		ctx := context.Background()
		local, lerr := listImages(ctx)
		asked := lerr == nil
		msg := imagesMsg{gen: gen}
		if asked {
			msg.machine = machineImages(ctx, local, ask)
		}
		if dir == "" {
			return msg
		}
		scan, err := findImages(ctx, dir)
		if err != nil {
			msg.err = err
			return msg
		}
		msg.refs = inspectImages(ctx, scan.Refs, local, asked, ask)
		msg.tags = map[string][]image.Tag{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, r := range msg.refs {
			if r.Unresolved || r.Registry == "" || r.Repo == "scratch" {
				continue
			}
			wg.Go(func() {
				tags := tagsFor(ctx, r, ask)
				mu.Lock()
				msg.tags[r.Canonical()] = tags
				mu.Unlock()
			})
		}
		wg.Wait()
		return msg
	}
}

func (m *model) gotImages(msg imagesMsg) {
	if msg.gen != m.imgGen {
		return
	}
	m.images, m.machineImgs, m.imgErr, m.imgBusy = msg.refs, msg.machine, msg.err, false
	if msg.tags != nil {
		m.imgTags = msg.tags
	}
	m.reindex()
}

// imageStatusNames are the filters the images table steps through with f.
var imageStatusNames = []string{"All", "⚠ past line", "⟳ stale", "◎ tracked", "◌ untracked", "● on disk", "○ not pulled"}

func (m model) imgStatus() int { return m.imgStatuses[m.curRow().key] }

func (m *model) cycleImgStatus() {
	key := m.curRow().key
	m.imgStatuses[key] = (m.imgStatuses[key] + 1) % len(imageStatusNames)
	m.cursor, m.offset = 0, 0
}

// hasUpstream says kho could identify what an image is built from: a
// registry answered for it, so its tag, its upstream version and its release
// line can be followed.
func hasUpstream(r image.Ref) bool {
	if r.Unresolved {
		return false
	}
	switch r.State {
	case image.Fresh, image.Stale, image.EOL, image.Gone, image.Pinned:
		return true
	}
	return false
}

// imgList is the images the selected row stands for: the machine's own, or
// the ones the project names.
func (m model) imgList() []image.Ref {
	if m.curRow().kind == rowMachineImages {
		return m.machineImgs
	}
	return m.images
}

// imgRows is the images table after the keyword and status filters.
func (m model) imgRows() []image.Ref {
	var out []image.Ref
	for _, r := range m.imgList() {
		if f := m.filter(); f != "" && !strings.Contains(strings.ToLower(r.Image), strings.ToLower(f)) {
			continue
		}
		if !m.matchImgStatus(r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (m model) matchImgStatus(r image.Ref) bool {
	switch m.imgStatus() {
	case 1:
		return r.State == image.EOL || r.State == image.Gone
	case 2:
		return r.State == image.Stale
	case 3:
		return hasUpstream(r)
	case 4:
		return !hasUpstream(r)
	case 5:
		return r.Presence == image.OnDisk
	case 6:
		return r.Presence == image.NotPulled
	}
	return true
}

// rowLen is how many rows the table holds: images on the images row,
// packages everywhere else.
func (m model) rowLen() int {
	if isImageRow(m.curRow().kind) {
		return len(m.imgRows())
	}
	return len(m.rows())
}

func (m model) currentImg() (image.Ref, bool) {
	return at(m.imgRows(), m.cursor)
}

// imageTitle is the table's header: the project, the filter, and the count.
func (m model) imageTitle() string {
	title := icon("project") + " " + m.projName() + " · images"
	if m.curRow().kind == rowMachineImages {
		title = icon("docker") + " docker"
	}
	if s := m.imgStatus(); s > 0 {
		title += " · " + imageStatusNames[s]
	}
	if m.imgBusy {
		title += " · reading"
	}
	return fmt.Sprintf("%s · %d", title, len(m.imgRows()))
}

// presenceMark says whether docker holds the image, in one character.
func presenceMark(r image.Ref) string {
	switch r.Presence {
	case image.OnDisk:
		return cyan().Render("●")
	case image.NotPulled:
		return faint().Render("○")
	}
	return faint().Render("?")
}

// imageState paints the state the way the package table paints a status. The
// table gets a short word; the sidebar spells it out.
func imageState(r image.Ref) string {
	switch r.State {
	case image.EOL, image.Gone:
		return red().Render(shortState(r))
	case image.Stale:
		return yellow().Render(shortState(r))
	case image.Fresh:
		return green().Render(shortState(r))
	}
	return faint().Render(shortState(r))
}

func shortState(r image.Ref) string {
	switch r.State {
	case image.Fresh:
		return "✓ fresh"
	case image.Stale:
		return "⟳ stale"
	case image.EOL:
		return "⚠ EOL"
	case image.Gone:
		return "⚠ gone"
	case image.Pinned:
		return "· pinned"
	case image.Local:
		return "· local"
	case image.None:
		return "· n/a"
	case image.Unknown:
		return "· unverified"
	}
	return "· build"
}

func stateWord(r image.Ref) string {
	switch r.State {
	case image.Fresh:
		return "✓ fresh"
	case image.Stale:
		return "⟳ stale"
	case image.EOL:
		return "⚠ past line"
	case image.Gone:
		return "⚠ tag gone"
	case image.Pinned:
		return "· pinned"
	case image.Local:
		return "· local"
	case image.None:
		return "· nothing to ask"
	case image.Unknown:
		return "· unverified"
	}
	return "· build time"
}

// imageWhere names the line the reference was read from.
func imageWhere(r image.Ref) string {
	if r.File == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", r.File, r.Line)
}

func (m model) imageTableLines() []string {
	inner := m.layout().tableW - 4
	rows := m.imgRows()
	// Columns drop as the table narrows: the state always stays, then the
	// upstream version, then where the reference was read.
	stateW, upstreamW, whereW := 10, 10, 18
	if inner < 62 {
		whereW = 0
	}
	if inner < 46 {
		upstreamW = 0
	}
	nameW := max(inner-(stateW+upstreamW+whereW+4), 10)
	head := pad("IMAGE", nameW)
	if whereW > 0 {
		head += " " + pad("FROM", whereW)
	}
	if upstreamW > 0 {
		head += " " + pad("UPSTREAM", upstreamW)
	}
	head += " " + pad("STATE", stateW)
	lines := []string{faint().Render(ansi.Truncate(head, inner, "…"))}
	if m.imgErr != nil {
		lines = append(lines, styled(red(), wrap(m.imgErr.Error(), inner))...)
		return lines
	}
	if len(rows) == 0 {
		why := "no images in this project"
		if m.imgBusy {
			why = "reading Dockerfiles and compose files"
		}
		lines = append(lines, faint().Render(" "+why))
		return lines
	}
	for i, r := range rows {
		line := presenceMark(r) + " " + pad(ansi.Truncate(r.Image, nameW, "…"), nameW)
		if whereW > 0 {
			line += " " + faint().Render(pad(ansi.Truncate(imageWhere(r), whereW, "…"), whereW))
		}
		if upstreamW > 0 {
			line += " " + pad(ansi.Truncate(r.Upstream, upstreamW, "…"), upstreamW)
		}
		line += " " + imageState(r)
		if i == m.cursor {
			line = selected(line, inner, m.focus == focusTable)
		}
		lines = append(lines, line)
	}
	return lines
}

// sideBoxFor picks the sidebar the selected row needs: images have their own.
func (m model) sideBoxFor(w, h int, focused bool) string {
	if isImageRow(m.curRow().kind) {
		return m.imageSideBox(w, h, focused)
	}
	return m.sideBox(w, h, focused)
}

// imageStatusBar counts the project's images by what matters: past the line,
// stale, and held on the machine.
func (m model) imageStatusBar() string {
	var past, stale, disk int
	list := m.imgList()
	for _, r := range list {
		switch r.State {
		case image.EOL, image.Gone:
			past++
		case image.Stale:
			stale++
		}
		if r.Presence == image.OnDisk {
			disk++
		}
	}
	parts := []string{" " + pillOn(fmt.Sprintf("%d images", len(list)), th.subtle, th.selFg)}
	if past > 0 {
		parts = append(parts, pillOn(fmt.Sprintf("⚠ %d past their line", past), th.red, th.selFg))
	}
	if stale > 0 {
		parts = append(parts, pill(fmt.Sprintf("⟳ %d stale", stale), th.yellow))
	}
	parts = append(parts, pill(fmt.Sprintf("● %d on disk", disk), th.cyan), pill(fmt.Sprintf("○ %d not pulled", len(list)-disk), th.muted))
	left := strings.Join(parts, " ")
	right := m.activity() + faint().Render("🎨 "+th.name+" ")
	return left + strings.Repeat(" ", max(m.width-ansi.StringWidth(left)-ansi.StringWidth(right), 1)) + right
}

// imageSideBox is the sidebar for an image: the same tabs as a package, with
// the fields, the tags the repository publishes, and what a scan found. The
// Security tab splits like a package's, list above and the finding below.
func (m model) imageSideBox(w, h int, focused bool) string {
	inner := w - 2
	e := edge(focused)
	top := e.Render("╭─") + " " + m.imageTabs() + " "
	top += e.Render(strings.Repeat("─", max(w-1-ansi.StringWidth(top), 0)) + "╮")
	out := []string{top}
	row := func(s string) string { return e.Render("│") + pad(s, inner) + e.Render("│") }
	body := wrapLines(m.imageTabLines(inner), inner)
	list := m.imageListLen() >= 0
	for i := 0; i < m.layout().topRows; i++ {
		idx := m.sideOffset + i
		text := ""
		if idx < len(body) {
			text = body[idx].text
		}
		if list && idx == m.sideCursor && idx < len(body) {
			text = selected(text, inner, focused)
		}
		out = append(out, row(text))
	}
	if m.imageHasBottom() {
		div := e.Render("├─ ") + boxTitle(m.imageBottomTitle(), focused) + " "
		out = append(out, div+e.Render(strings.Repeat("─", max(w-1-ansi.StringWidth(div), 0))+"┤"))
		bottom := wrapLines(m.imageBottomLines(inner), inner)
		for i := 0; i < m.layout().bottomRows; i++ {
			idx := m.bodyOffset + i
			text := ""
			if idx < len(bottom) {
				text = bottom[idx].text
			}
			out = append(out, row(text))
		}
	}
	out = append(out, e.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return strings.Join(out, "\n")
}

// imageHasBottom says the image sidebar splits: only a scan result has a
// detail worth reading under the list.
func (m model) imageHasBottom() bool {
	r, ok := m.currentImg()
	return ok && m.imageTab() == tabSecurity && len(m.imgVulns[r.Canonical()]) > 0
}

func (m model) imageBottomTitle() string {
	r, ok := m.currentImg()
	if !ok {
		return "🛡 Finding"
	}
	if v, ok := at(m.imgVulns[r.Canonical()], m.sideCursor); ok {
		return "🛡 " + v.ID
	}
	return "🛡 Finding"
}

func (m model) imageBottomLines(inner int) []line {
	r, ok := m.currentImg()
	if !ok {
		return nil
	}
	v, ok := at(m.imgVulns[r.Canonical()], m.sideCursor)
	if !ok {
		return plain("", faint().Render(" pick a finding to read it here"))
	}
	lines := plain("", severityPill(v.Severity)+" "+bold().Render(v.ID))
	add := func(label, value, url string) {
		if value != "" {
			lines = append(lines, field(label, value, url))
		}
	}
	add("package", v.Package, "")
	add("installed", v.Installed, "")
	fixed := v.Fixed
	if fixed == "" {
		fixed = "no fix published"
	}
	add("fixed in", fixed, "")
	add("about", v.Title, "")
	add("report", v.URL, v.URL)
	lines = append(lines, plain("", faint().Render(" from trivy, which read the image's packages"))...)
	lines = append(lines, plain("", faint().Render(" the fix is a newer base image, then a rebuild"))...)
	return lines
}

// imageTab is the tab the image sidebar shows; the tabs an image has no use
// for fall back to Info.
func (m model) imageTab() int {
	switch m.activeTab() {
	case tabVersions, tabSecurity:
		return m.activeTab()
	}
	return tabInfo
}

func (m model) imageTabs() string {
	names := []struct {
		id   int
		name string
	}{{tabInfo, "Info"}, {tabVersions, "Versions"}, {tabSecurity, "Security"}}
	labels := func(long bool) []string {
		var out []string
		for _, t := range names {
			name := t.name
			if !long {
				name = t.name[:3]
			}
			out = append(out, tabLabel(name, t.id == m.imageTab()))
		}
		return out
	}
	wide := labels(true)
	if lipgloss.Width(strings.Join(wide, " ")) > m.layout().sideW-6 {
		wide = labels(false)
	}
	return strings.Join(wide, " ")
}

// moveImageSide scrolls the image sidebar. The tabs that list things move
// through them; there is nothing to install or open, so enter only moves
// focus back to the list.
func (m *model) moveImageSide(key string, step int) {
	n := m.imageListLen()
	switch {
	case key == "home" || key == "g":
		m.sideCursor, m.sideOffset = 0, 0
	case n > 0 && (key == "up" || key == "k" || key == "down" || key == "j" || key == "pgup" || key == "pgdown"):
		m.sideCursor = max(min(m.sideCursor+step, n-1), 0)
		m.sideOffset = scroll(m.sideOffset, m.sideCursor, max(m.layout().topRows+m.layout().bottomRows, 1))
	}
}

// imageListLen is the length of the tab's list, or -1 for the tabs that show
// fields.
func (m model) imageListLen() int {
	r, ok := m.currentImg()
	if !ok {
		return -1
	}
	switch m.imageTab() {
	case tabVersions:
		return len(m.imgTags[r.Canonical()])
	case tabSecurity:
		return len(m.imgVulns[r.Canonical()])
	}
	return -1
}

func (m model) imageTabLines(inner int) []line {
	r, ok := m.currentImg()
	if !ok {
		return plain("", faint().Render(" pick an image to see it here"))
	}
	switch m.imageTab() {
	case tabVersions:
		return m.imageVersionLines(r)
	case tabSecurity:
		return m.imageSecurityLines(r, inner)
	}
	return m.imageLines(r)
}

func (m model) imageLines(r image.Ref) []line {
	lines := plain(" "+icon("docker")+" "+accent().Render(r.Image), "")
	add := func(label, value, url string) {
		if value != "" {
			lines = append(lines, field(label, value, url))
		}
	}
	add("where", imageWhere(r), "")
	add("presence", presenceWord(r), "")
	add("upstream", r.Upstream, "")
	add("base", r.Base, "")
	if p := r.Product(); p != "" {
		add("line", p+" "+r.Cycle(), "https://endoflife.date/"+p)
	}
	if r.Registry == "docker.io" {
		add("registry", "hub.docker.com/r/"+r.RemoteRepo(), "https://hub.docker.com/r/"+r.RemoteRepo())
	} else if r.Registry != "" && r.Repo != "" {
		add("registry", r.Registry+"/"+r.Repo, "")
	}
	if !r.Built.IsZero() {
		add("on disk", r.Built.Format("2006-01-02"), "")
	}
	if !r.RemotePushed.IsZero() {
		add("remote", r.RemotePushed.Format("2006-01-02")+" · "+shortDigest(r.RemoteDigest), "")
	}
	if !r.EOL.IsZero() {
		add("support", "ended "+r.EOL.Format("2006-01-02"), "")
	}
	add("state", stateWord(r), "")
	if r.Note != "" {
		add("note", r.Note, "")
	}
	if r.Via != "" {
		add("chosen by", r.Via+" at build time, so kho cannot say which image this is", "")
	}
	lines = append(lines, plain("", faint().Render(" kho reads references and registry metadata, never what is inside an image."))...)
	return lines
}

// imageVersionLines lists the tags the repository publishes, newest first,
// with the one in use marked.
func (m model) imageVersionLines(r image.Ref) []line {
	tags := slices.Clone(m.imgTags[r.Canonical()])
	if len(tags) == 0 {
		if r.Registry == "" || r.Repo == "scratch" || r.Unresolved {
			return plain("", faint().Render(" this image has no repository to ask"))
		}
		return plain("", faint().Render(" the repository did not list its tags"))
	}
	// Newest line first, and the tag in use always shows, even when the
	// repository lists more than kho asked for.
	// Numbered tags first, newest line at the top, then the named variants.
	numbered := func(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }
	sort.SliceStable(tags, func(i, j int) bool {
		if numbered(tags[i].Name) != numbered(tags[j].Name) {
			return numbered(tags[i].Name)
		}
		return vuln.Compare(tags[i].Name, tags[j].Name) > 0
	})
	if r.Tag != "" && !slices.ContainsFunc(tags, func(t image.Tag) bool { return t.Name == r.Tag }) {
		tags = append([]image.Tag{{Name: r.Tag}}, tags...)
	}
	lines := plain("", faint().Render(" tags published by "+r.Registry))
	for _, t := range tags {
		mark := "  "
		if t.Name == r.Tag {
			mark = accent().Render("→ ")
		}
		when := ""
		if !t.Pushed.IsZero() {
			when = "  " + faint().Render(t.Pushed.Format("2006-01-02"))
		}
		text := " " + mark + pad(ansi.Truncate(t.Name, 22, "…"), 22) + when
		lines = append(lines, row(text))
	}
	return lines
}

// imageSecurityLines says what is known about an image's security. kho does
// not read inside an image, so a package level CVE list needs a scanner: the
// scan key runs trivy when it is installed.
func (m model) imageSecurityLines(r image.Ref, inner int) []line {
	key := r.Canonical()
	if m.imgScanning[key] {
		return plain("", faint().Render(" scanning with trivy, this takes a moment"))
	}
	if err := m.imgScanErr[key]; err != "" {
		return append(plain("", red().Render(" "+err)), plain("", faint().Render(" the rest of kho still works without a scan"))...)
	}
	vulns := m.imgVulns[key]
	if len(vulns) == 0 {
		lines := plain("", faint().Render(" kho does not read inside an image, so it cannot"))
		lines = append(lines, plain("", faint().Render(" list the packages a CVE would be filed against."))...)
		lines = append(lines, plain("", "")...)
		if trivyAvailable() {
			lines = append(lines, plain("", accent().Render(" x  scan this image with trivy"))...)
		} else {
			lines = append(lines, plain("", faint().Render(" install trivy and press x to scan it"))...)
		}
		if !r.EOL.IsZero() {
			lines = append(lines, plain("", "")...)
			lines = append(lines, plain("", faint().Render(" the line itself ended "+r.EOL.Format("2006-01-02"))+", which a rebuild cannot fix")...)
		}
		return lines
	}
	lines := plain("", faint().Render(fmt.Sprintf(" %d findings from trivy", len(vulns))))
	for _, v := range vulns {
		text := " " + severityPill(v.Severity) + " " + pad(ansi.Truncate(v.ID, 18, "…"), 18) + " " + ansi.Truncate(v.Package, 16, "…")
		lines = append(lines, row(text))
	}
	return lines
}

func presenceWord(r image.Ref) string {
	switch r.Presence {
	case image.OnDisk:
		return "on disk"
	case image.NotPulled:
		return "not pulled"
	}
	return "docker was not asked"
}

// shortDigest trims a digest to what a person reads.
func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

func lipglossWidth(s string) int { return ansi.StringWidth(s) }
