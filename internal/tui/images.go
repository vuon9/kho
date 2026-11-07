package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/image"
)

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
)

type imagesMsg struct {
	gen     int
	refs    []image.Ref
	machine []image.Ref
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
		return msg
	}
}

func (m *model) gotImages(msg imagesMsg) {
	if msg.gen != m.imgGen {
		return
	}
	m.images, m.machineImgs, m.imgErr, m.imgBusy = msg.refs, msg.machine, msg.err, false
	m.reindex()
}

// imageStatusNames are the filters the images table steps through with f.
var imageStatusNames = []string{"All", "⚠ past line", "⟳ stale", "● on disk", "○ not pulled"}

func (m model) imgStatus() int { return m.imgStatuses[m.curRow().key] }

func (m *model) cycleImgStatus() {
	key := m.curRow().key
	m.imgStatuses[key] = (m.imgStatuses[key] + 1) % len(imageStatusNames)
	m.cursor, m.offset = 0, 0
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
		return r.Presence == image.OnDisk
	case 4:
		return r.Presence == image.NotPulled
	}
	return true
}

// rowLen is how many rows the table holds: images on the images row,
// packages everywhere else.
func (m model) rowLen() int {
	if k := m.curRow().kind; k == rowImages || k == rowMachineImages {
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
	if k := m.curRow().kind; k == rowImages || k == rowMachineImages {
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

// imageSideBox is the sidebar for an image. There are no tabs to step
// through: everything kho knows about one image fits in one panel.
func (m model) imageSideBox(w, h int, focused bool) string {
	inner := w - 2
	e := edge(focused)
	top := e.Render("╭─") + " " + faint().Bold(true).Render("Image") + " "
	top += e.Render(strings.Repeat("─", max(w-1-lipglossWidth(top), 0)) + "╮")
	out := []string{top}
	body := wrapLines(m.imageLines(inner), inner)
	lines := m.layout().topRows + m.layout().bottomRows
	for i := 0; i < lines; i++ {
		text := ""
		if i < len(body) {
			text = body[i].text
		}
		out = append(out, e.Render("│")+pad(text, inner)+e.Render("│"))
	}
	out = append(out, e.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return strings.Join(out, "\n")
}

func (m model) imageLines(inner int) []line {
	r, ok := m.currentImg()
	if !ok {
		return plain("", faint().Render(" pick an image to see it here"))
	}
	lines := plain(" "+icon("docker")+" "+accent().Render(r.Image), "")
	add := func(label, value string) {
		if value != "" {
			lines = append(lines, field(label, value, ""))
		}
	}
	add("where", imageWhere(r))
	add("presence", presenceWord(r))
	add("upstream", r.Upstream)
	add("base", r.Base)
	if !r.Built.IsZero() {
		add("on disk", r.Built.Format("2006-01-02"))
	}
	if !r.RemotePushed.IsZero() {
		add("remote", r.RemotePushed.Format("2006-01-02")+" · "+shortDigest(r.RemoteDigest))
	}
	if !r.EOL.IsZero() {
		add("support", "ended "+r.EOL.Format("2006-01-02"))
	}
	add("state", stateWord(r))
	if r.Note != "" {
		add("note", r.Note)
	}
	if r.Via != "" {
		add("chosen by", r.Via+" at build time, so kho cannot say which image this is")
	}
	lines = append(lines, plain("", faint().Render(" kho reads references and registry metadata, never what is inside an image."))...)
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
