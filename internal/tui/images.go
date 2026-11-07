package tui

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/trivy"
	"github.com/vuon9/kho/internal/vuln"
)

// scanImage runs the scanner over one image. Tests swap it.
var scanImage = trivy.Scan

// trivyAvailable says whether a scan can run at all.
var trivyAvailable = trivy.Available

type imageTagsMsg struct {
	key  string
	tags []image.Tag
}

// tagsCmd asks a repository what it publishes, when a person opens Versions
// on an image kho has not asked about yet.
func (m model) tagsCmd() tea.Cmd {
	r, ok := m.currentImg()
	if !ok {
		return nil
	}
	key, ask := r.Canonical(), m.imgAsk
	m.imgTagBusy[key] = true
	return func() tea.Msg {
		return imageTagsMsg{key: key, tags: tagsFor(context.Background(), r, ask)}
	}
}

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
	local   []image.LocalImage
	err     error
}

// imageFactsMsg is what the registries said, arriving after the table is
// already on screen: the rows say asking until it lands.
type imageFactsMsg struct {
	gen     int
	refs    []image.Ref
	machine []image.Ref
}

// imagesCmd reads the project's images and asks about each one, off the UI
// goroutine. It never pulls, builds or runs anything.
func (m model) imagesCmd() tea.Cmd {
	gen, dir := m.imgGen, m.dir
	return func() tea.Msg {
		ctx := context.Background()
		msg := imagesMsg{gen: gen}
		local, err := listImages(ctx)
		asked := err == nil
		msg.local = local
		if asked {
			// The machine's own images without the registries, so the table
			// has something to show before anything is asked about them.
			msg.machine = machineImages(ctx, local, nil)
		}
		if dir != "" {
			scan, ferr := findImages(ctx, dir)
			if ferr != nil {
				msg.err = ferr
			} else {
				msg.refs = inspectImages(ctx, scan.Refs, local, asked, nil)
			}
		}
		return msg
	}
}

// factsCmd asks the registries what the rows are, once they are on screen.
// Tags are not fetched here: they belong to the Versions tab, which asks for
// them when it is opened.
func (m model) factsCmd() tea.Cmd {
	gen, ask, refs, local := m.imgGen, m.imgAsk, m.images, m.localImgs
	return func() tea.Msg {
		ctx := context.Background()
		msg := imageFactsMsg{gen: gen}
		asked := local != nil
		if asked {
			msg.machine = machineImages(ctx, local, ask)
		}
		if len(refs) > 0 {
			msg.refs = inspectImages(ctx, refs, local, asked, ask)
		}
		return msg
	}
}

func (m *model) gotImages(msg imagesMsg) {
	if msg.gen != m.imgGen {
		return
	}
	m.images, m.machineImgs, m.imgErr, m.imgBusy = msg.refs, msg.machine, msg.err, false
	if msg.local != nil {
		m.localImgs, m.imgBusy = msg.local, true
	}
	if msg.tags != nil {
		m.imgTags = msg.tags
	}
	m.reindex()
}

// gotFacts replaces the rows with what the registries answered.
func (m *model) gotFacts(msg imageFactsMsg) {
	if msg.gen != m.imgGen {
		return
	}
	if len(msg.refs) > 0 {
		m.images = msg.refs
	}
	if len(msg.machine) > 0 {
		m.machineImgs = msg.machine
	}
	m.imgBusy = false
	m.reindex()
}

// imageStatusNames are the filters the images table steps through with f.
// untracked is the only one that shows what kho could not identify.
const (
	imgStatusAll = iota
	imgStatusPast
	imgStatusStale
	imgStatusTracked
	imgStatusUntracked
	imgStatusOnDisk
	imgStatusNotPulled
)

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

// unverified says kho could not identify what an image is built from: it was
// chosen at build time, or no registry answers for the name. They are kept
// out of the table unless the untracked filter asks for them, and counted
// under it so the list never looks like everything there is.
func unverified(r image.Ref) bool {
	return r.Unresolved || r.State == image.Unknown
}

// hiddenUnverified is how many the table is leaving out.
func (m model) hiddenUnverified() int {
	if m.imgBusy {
		return 0
	}
	n := 0
	for _, r := range m.imgList() {
		if unverified(r) {
			n++
		}
	}
	return n
}

// imgRows is the images table after the keyword and status filters.
func (m model) imgRows() []image.Ref {
	var out []image.Ref
	only := m.imgStatus() == imgStatusUntracked
	for _, r := range m.imgList() {
		if unverified(r) && !only && !m.imgBusy {
			continue
		}
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
	case imgStatusPast:
		return r.State == image.EOL || r.State == image.Gone
	case imgStatusStale:
		return r.State == image.Stale
	case imgStatusTracked:
		return hasUpstream(r)
	case imgStatusUntracked:
		return unverified(r)
	case imgStatusOnDisk:
		return r.Presence == image.OnDisk
	case imgStatusNotPulled:
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
	title = fmt.Sprintf("%s · %d", title, len(m.imgRows()))
	if n := m.hiddenUnverified(); n > 0 && m.imgStatus() != imgStatusUntracked {
		title += fmt.Sprintf(" · %d unverified hidden", n)
	}
	return title
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
// asking is the state of a row whose registry has not answered yet: it is not
// unverified, it is unanswered.
func (m model) asking(r image.Ref) bool { return m.imgBusy && r.State == image.Unknown }

// table gets a short word; the sidebar spells it out.
func (m model) imageState(r image.Ref) string {
	if m.asking(r) {
		return faint().Render("· asking")
	}
	return imageState(r)
}

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

func (m model) stateWord(r image.Ref) string {
	if m.asking(r) {
		return "· asking"
	}
	return stateWord(r)
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
	// The name never takes more than it needs: a long reference would push
	// the state off the table, and the sidebar spells the whole name anyway.
	const nameMax = 26
	stateW, upstreamW, whereW := 10, 10, 16
	if inner < 58 {
		upstreamW = 0
	}
	if inner < 40 {
		whereW = 0
	}
	nameW := min(max(inner-(stateW+upstreamW+whereW+4), 10), nameMax)
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
		switch {
		case m.imgBusy:
			why = "reading Dockerfiles and compose files"
		case m.hiddenUnverified() > 0:
			// Every row kho could not identify is hidden, and saying the
			// project has none would be a lie.
			why = fmt.Sprintf("%d images kho could not identify; f shows them", m.hiddenUnverified())
		}
		lines = append(lines, faint().Render(" "+why))
		return lines
	}
	for i, r := range rows {
		name := pad(ansi.Truncate(r.Image, nameW, "…"), nameW)
		if r.State == image.Unknown || r.Unresolved {
			name = faint().Render(name)
		}
		line := presenceMark(r) + " " + name
		if whereW > 0 {
			line += " " + faint().Render(pad(ansi.Truncate(imageWhere(r), whereW, "…"), whereW))
		}
		if upstreamW > 0 {
			line += " " + pad(ansi.Truncate(r.Upstream, upstreamW, "…"), upstreamW)
		}
		line += " " + m.imageState(r)
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
	body := wrapLines(m.imageTabLines(inner), inner)
	list := m.imageListLen() >= 0
	var rows []string
	for i := 0; i < m.layout().topRows; i++ {
		idx := m.sideOffset + i
		text := ""
		if idx < len(body) {
			text = body[idx].text
		}
		if list && idx == m.sideCursor && idx < len(body) {
			text = selected(text, inner, focused)
		}
		rows = append(rows, text)
	}
	if m.imageHasBottom() {
		div := e.Render("├─ ") + boxTitle(m.imageBottomTitle(), focused) + " "
		rows = append(rows, div+e.Render(strings.Repeat("─", max(w-1-ansi.StringWidth(div), 0))+"┤"))
		bottom := wrapLines(m.imageBottomLines(inner), inner)
		for i := 0; i < m.layout().bottomRows; i++ {
			idx := m.bodyOffset + i
			text := ""
			if idx < len(bottom) {
				text = bottom[idx].text
			}
			rows = append(rows, text)
		}
	}
	if status := m.imageTabStatus(); status != "" && len(rows) > 0 {
		rule := "── " + status + " "
		rows[len(rows)-1] = faint().Render(rule + strings.Repeat("─", max(inner-ansi.StringWidth(rule), 0)))
	}
	out := []string{top}
	for _, r := range rows {
		out = append(out, e.Render("│")+pad(r, inner)+e.Render("│"))
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
		return plain(faint().Render(" pick a finding to read it here"))
	}
	lines := plain(severityPill(v.Severity) + " " + bold().Render(v.ID))
	add := func(label, value, url string) {
		if value == "" {
			return
		}
		if url != "" {
			value = link(url).Render(value)
		}
		lines = append(lines, field(label, value, url))
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

func (m model) imageTabs() string { return m.tabBar() }

// autoScan starts the scan the first time an image's Security tab opens, so
// the tab answers by itself instead of asking for a key press. A failed or
// finished scan is not repeated; x runs it again.
func (m *model) autoScan() tea.Cmd {
	r, ok := m.currentImg()
	if !ok || m.imageTab() != tabSecurity {
		return nil
	}
	key := r.Canonical()
	if m.imgScanning[key] || m.imgVulns[key] != nil || m.imgScanErr[key] != "" || !trivyAvailable() {
		return nil
	}
	m.imgScanning[key] = true
	ref := r.Image
	return func() tea.Msg {
		vulns, err := scanImage(context.Background(), ref)
		return imageScanMsg{key: key, vulns: vulns, err: err}
	}
}

// pullCmd is the command that fetches one tag. Tests swap it.
var pullCmd = func(ref string) *exec.Cmd { return exec.Command("docker", "pull", ref) }

// askPull is enter on a version: the confirmation a package install gets,
// for the one change kho makes to an image, which is fetching it.
func (m *model) askPull() {
	r, ok := m.currentImg()
	if !ok || m.imageTab() != tabVersions {
		return
	}
	t, ok := at(m.sortedTags(r), m.sideCursor)
	if !ok {
		return
	}
	target := r.CanonicalRepo() + ":" + t.Name
	title := "⬇ Pull " + r.Name() + " as " + t.Name
	lines := []string{
		bold().Render(r.Image) + faint().Render(" → ") + green().Render(t.Name),
		"",
		faint().Render("runs  ") + "docker pull " + target,
		"",
		faint().Render("the image on disk stays until you remove it"),
		"",
		accent().Render("y") + faint().Render(" run it   ") + accent().Render("n") + faint().Render(" cancel"),
	}
	m.confirm = &confirm{title: title + "?", lines: lines,
		run: startInstall(title, pullCmd(target), m.log, installedMsg{provider: "docker", name: r.Image, version: t.Name})}
}

// sortedTags is the tags of an image in the order the panel shows them, with
// the tag in use kept in front when the repository did not list it.
func (m model) sortedTags(r image.Ref) []image.Tag {
	tags := slices.Clone(m.imgTags[r.Canonical()])
	if r.Tag != "" && !slices.ContainsFunc(tags, func(t image.Tag) bool { return t.Name == r.Tag }) {
		// The tag in use always shows, in its own place in the order, even
		// when the repository lists more than kho asked for.
		tags = append(tags, image.Tag{Name: r.Tag})
	}
	tagOrder(tags)
	return tags
}

// tagURL is where a person reads one tag, for the registries that publish a
// page for it.
func tagURL(r image.Ref, tag string) string {
	if r.Registry == "docker.io" {
		return "https://hub.docker.com/r/" + r.RemoteRepo() + "/tags?name=" + url.QueryEscape(tag)
	}
	return ""
}

// moveImageSide scrolls the image sidebar. The tabs that list things move
// through them; there is nothing to install or open, so enter only moves
// focus back to the list.
func (m *model) moveImageSide(key string, step int) {
	n := m.imageListLen()
	switch {
	case key == "enter" && m.imageTab() == tabVersions && n > 0:
		m.askPull()
	case key == "home" || key == "g":
		m.sideCursor, m.sideOffset = 0, 0
	case n > 0 && (key == "up" || key == "k" || key == "down" || key == "j" || key == "pgup" || key == "pgdown"):
		m.sideCursor = max(min(m.sideCursor+step, n-1), 0)
		m.sideOffset = scroll(m.sideOffset, m.sideCursor, max(m.layout().topRows+m.layout().bottomRows, 1))
	}
}

// imageTabStatus is the fixed line at the foot of the panel, which says what
// the tab is looking at without taking a row from the list.
func (m model) imageTabStatus() string {
	r, ok := m.currentImg()
	if !ok {
		return ""
	}
	switch m.imageTab() {
	case tabVersions:
		if r.Registry == "" || r.Repo == "scratch" || r.Unresolved {
			return "no repository to ask"
		}
		if m.imgTagBusy[r.Canonical()] {
			return "asking " + r.Registry + " for its tags"
		}
		return "tags · " + r.Registry
	case tabSecurity:
		if n := len(m.imgVulns[r.Canonical()]); n > 0 {
			return fmt.Sprintf("%d findings · trivy", n)
		}
		if m.imgScanning[r.Canonical()] {
			return "scanning · trivy"
		}
		return "no scan yet · trivy"
	}
	return ""
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
		return plain(faint().Render(" pick an image to see it here"))
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
		if value == "" {
			return
		}
		if url != "" {
			value = link(url).Render(value)
		}
		lines = append(lines, field(label, value, url))
	}
	add("where", imageWhere(r), "")
	add("presence", presenceWord(r), "")
	add("upstream", r.Upstream, "")
	add("base", r.Base, "")
	if p := r.Product(); p != "" {
		text := "endoflife.date/" + p
		if c := r.Cycle(); c != "" {
			text += " · " + c
		}
		add("line", text, "https://endoflife.date/"+p)
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
		if now().After(r.EOL) {
			add("support", "ended "+r.EOL.Format("2006-01-02"), "")
		} else {
			add("support", "supported until "+r.EOL.Format("2006-01-02"), "")
		}
	}
	add("state", m.stateWord(r), "")
	if r.Note != "" {
		add("note", r.Note, "")
	}
	if r.Via != "" {
		if r.Unresolved {
			add("chosen by", r.Via+" at build time, so kho cannot say which image this is", "")
		} else {
			add("from", "ARG "+r.Via, "")
		}
	}
	lines = append(lines, plain("", faint().Render(" kho reads references and registry metadata, never what is inside an image."))...)
	return lines
}

// tagOrder sorts tags the way a person reads them: the highest version first,
// then the most recently published within one version, then by name. Tags
// with no version, like latest or trixie, come after the numbered ones.
func tagOrder(tags []image.Tag) {
	sort.SliceStable(tags, func(i, j int) bool {
		vi, vj := versionOf(tags[i].Name), versionOf(tags[j].Name)
		if (vi == "") != (vj == "") {
			return vi != ""
		}
		if vi != vj {
			if c := vuln.Compare(vi, vj); c != 0 {
				return c > 0
			}
		}
		if !tags[i].Pushed.Equal(tags[j].Pushed) {
			return tags[i].Pushed.After(tags[j].Pushed)
		}
		return tags[i].Name < tags[j].Name
	})
}

var versionPrefix = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

// versionOf is the numbers a tag starts with, as in 3.12.16 from
// 3.12.16-alpine, or "" when the tag is a word.
func versionOf(name string) string {
	if m := versionPrefix.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}

// imageVersionLines lists the tags the repository publishes, newest first,
// with the one in use marked.
func (m model) imageVersionLines(r image.Ref) []line {
	tags := m.sortedTags(r)
	if len(tags) == 0 {
		if r.Registry == "" || r.Repo == "scratch" || r.Unresolved {
			return plain(faint().Render(" this image has no repository to ask"))
		}
		if m.imgTagBusy[r.Canonical()] {
			return plain(faint().Render(" asking " + r.Registry + " for its tags"))
		}
		return plain(faint().Render(" press v again to ask " + r.Registry))
	}
	var lines []line
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
		return plain(faint().Render(" scanning with trivy, this takes a moment"))
	}
	if err := m.imgScanErr[key]; err != "" {
		return append(plain(red().Render(" "+err)), plain(faint().Render(" the rest of kho still works without a scan"))...)
	}
	vulns := m.imgVulns[key]
	if len(vulns) == 0 {
		lines := plain(faint().Render(" kho does not read inside an image, so it cannot"),
			faint().Render(" list the packages a CVE would be filed against."), "")
		if trivyAvailable() {
			lines = append(lines, plain(accent().Render(" x  scan this image with trivy"), "")...)
		} else {
			lines = append(lines, plain(faint().Render(" install trivy and press x to scan it"), "")...)
		}
		if !r.EOL.IsZero() {
			lines = append(lines, plain(faint().Render(" the line itself ended "+r.EOL.Format("2006-01-02"))+", which a rebuild cannot fix")...)
		}
		return lines
	}
	var lines []line
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
