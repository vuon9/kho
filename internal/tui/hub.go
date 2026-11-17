package tui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/registry"
)

// The source a machine image search asks, as the status bar and errors name it.
const hubName = "Docker Hub"

var searchHub = func(ctx context.Context, ask image.Asker, q string, limit int) ([]registry.HubRepo, error) {
	h, ok := ask.(interface {
		SearchHub(context.Context, string, int) ([]registry.HubRepo, error)
	})
	if !ok {
		return nil, errors.New("no Docker Hub client")
	}
	return h.SearchHub(ctx, q, limit)
}

func (m model) hubScope() bool   { return m.search != nil && m.curRow().kind == rowMachineImages }
func (m model) hubResults() bool { return m.inResults() && m.hubScope() }

func (m model) hubCmd(gen int, q string) tea.Cmd {
	ask := m.imgAsk
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
		defer cancel()
		repos, err := searchHub(ctx, ask, q, searchLimit)
		return searchMsg{gen: gen, manager: hubName, repos: repos, err: err}
	}
}

// A candidate's tag stays latest whatever tag is suggested, so its tags are
// asked for once, under one key.
func (m model) hubRefs() []image.Ref {
	out := make([]image.Ref, 0, len(m.search.hub))
	for _, h := range m.search.hub {
		r := h.Ref("latest")
		r.Presence = image.NotPulled
		if len(m.hubOnDisk(r)) > 0 {
			r.Presence = image.OnDisk
		}
		out = append(out, r)
	}
	return out
}

func (m model) hubOnDisk(r image.Ref) []string {
	var tags []string
	for _, l := range m.machineImgs {
		if l.CanonicalRepo() == r.CanonicalRepo() && l.Tag != "" {
			tags = append(tags, l.Tag)
		}
	}
	return tags
}

func (m model) hubCandidate(r image.Ref) (registry.HubRepo, bool) {
	if !m.hubResults() {
		return registry.HubRepo{}, false
	}
	for _, h := range m.search.hub {
		if h.Ref("latest").CanonicalRepo() == r.CanonicalRepo() {
			return h, true
		}
	}
	return registry.HubRepo{}, false
}

func (m model) hubSuggested(r image.Ref) (image.Tag, bool) {
	tags := m.imgTags[r.Canonical()]
	name := registry.SuggestTag(tags)
	i := slices.IndexFunc(tags, func(t image.Tag) bool { return t.Name == name })
	if i < 0 {
		return image.Tag{}, false
	}
	return tags[i], true
}

func (m model) hubLines() []string {
	st := m.search
	inner := m.layout().tableW - 2
	room := inner - 2
	// A narrow table keeps whole names: stars go, and the status keeps its sign.
	pullsW, starsW, statusW := 7, 7, 13
	nameW := room - pullsW - starsW - statusW - 3
	narrow := nameW < 24
	if narrow {
		starsW, statusW = 0, 1
		nameW = max(room-pullsW-statusW-2, 10)
	}
	head := pad("NAME", nameW) + " " + padLeft("PULLS", pullsW)
	if !narrow {
		head += " " + padLeft("STARS", starsW) + " STATUS"
	}
	lines := []string{"  " + faint().Bold(true).Render(head)}
	refs := m.hubRefs()
	end := min(m.offset+m.layout().rows, len(refs))
	for i := m.offset; i < end; i++ {
		h, r := st.hub[i], refs[i]
		name := printable(h.Name)
		if h.Official {
			name += faint().Render(" official")
		}
		status := faint().Render(image.NotPulled.Mark() + " not pulled")
		if r.Presence == image.OnDisk {
			status = cyan().Render(image.OnDisk.Mark() + " on disk")
		}
		line := "  " + pad(name, nameW) + " " + padLeft(registry.Count(h.Pulls), pullsW)
		if !narrow {
			line += " " + padLeft(registry.Count(int64(h.Stars)), starsW)
		}
		line += " " + ansi.Truncate(status, statusW, "")
		if i == m.cursor {
			line = selected(line, inner, m.focus == focusTable)
		}
		lines = append(lines, line)
	}
	if len(refs) == 0 {
		lines = append(lines, m.hubHints()...)
	}
	return append(m.fitBody(lines), m.barRule(inner), m.searchBar())
}

func (m model) hubHints() []string {
	st := m.search
	out := []string{""}
	switch {
	case st.busy:
		return append(out, " "+m.spin()+faint().Render(" searching "+hubName+"…"))
	case st.errs[hubName] != "":
		return append(out, " "+red().Render("could not search "+hubName),
			red().Render(" "+shortReason(st.errs[hubName])))
	}
	return append(out, faint().Render(" no images match \""+printable(st.query)+"\" on "+hubName),
		faint().Render(" searched "+hubName+" in "+tookText(st.took)))
}

func padLeft(s string, w int) string {
	s = ansi.Truncate(s, w, "…")
	return strings.Repeat(" ", max(w-ansi.StringWidth(s), 0)) + s
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d MB", n>>20)
	case n > 0:
		return fmt.Sprintf("%d kB", max(n>>10, 1))
	}
	return ""
}

func (m model) hubInfoLines(h registry.HubRepo, r image.Ref) []line {
	title := " " + icon("docker") + " " + accent().Render(printable(h.Name))
	if h.Official {
		title += faint().Render(" · official image")
	}
	lines := plain(title, "")
	add := func(label, value, url string) {
		if value == "" {
			return
		}
		if url != "" {
			value = link(url).Render(value)
		}
		lines = append(lines, field(label, value, url))
	}
	add("about", printable(h.Description), "")
	add("pulls", registry.Count(h.Pulls), "")
	add("stars", registry.Count(int64(h.Stars)), "")
	add("page", strings.TrimPrefix(h.URL(), "https://"), h.URL())
	if !h.Updated.IsZero() {
		add("updated", h.Updated.Format("2006-01-02"), "")
	}
	if on := m.hubOnDisk(r); len(on) > 0 {
		add("on disk", strings.Join(on, ", "), "")
	}
	lines = append(lines, line{})
	t, ok := m.hubSuggested(r)
	switch {
	case ok:
		add("tag", printable(t.Name)+faint().Render(" suggested"), "")
		add("size", byteSize(t.Size), "")
		add("platforms", platformsText(t.Platforms), "")
		if cmd, ok := h.PullRef(t.Name); ok {
			add("runs", "docker pull "+cmd, "")
		}
		lines = append(lines, plain("", faint().Render(" enter pulls this tag after asking · v picks another"))...)
	case m.imgTagBusy[r.Canonical()]:
		lines = append(lines, plain(" "+m.spin()+faint().Render(" asking "+hubName+" for its tags"))...)
	case m.imgTagErr[r.Canonical()] != "":
		lines = append(lines, plain(faint().Render(" no tags: "+shortReason(m.imgTagErr[r.Canonical()])))...)
	default:
		lines = append(lines, plain(faint().Render(" open it to see its tags"))...)
	}
	return append(lines, plain("", faint().Render(" kho reads "+hubName+"'s metadata, never what is inside an image."))...)
}

func (m model) hubSecurityLines() []line {
	return plain(
		faint().Render(" nothing is scanned before a pull."),
		faint().Render(" once the image is on disk, its Security tab runs trivy."),
	)
}

func (m *model) pointAtSuggested() {
	r, ok := m.currentImg()
	if !ok || !m.hubResults() || m.imageTab() != tabVersions {
		return
	}
	if t, ok := m.hubSuggested(r); ok {
		m.sideCursor = max(slices.IndexFunc(m.sortedTags(r), func(s image.Tag) bool { return s.Name == t.Name }), 0)
		m.sideOffset = scroll(0, m.sideCursor, max(m.layout().topRows, 1))
	}
}

// Three platforms say what a tag runs on; the rest are counted.
func platformsText(ps []string) string {
	if len(ps) <= 3 {
		return strings.Join(ps, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(ps[:2], ", "), len(ps)-2)
}

// The command shown is the one that runs: the name Docker Hub gave, and the
// tag picked, each checked so neither can read as a flag.
func (m *model) askHubPull(r image.Ref, t image.Tag) {
	h, ok := m.hubCandidate(r)
	if !ok {
		return
	}
	target, ok := h.PullRef(t.Name)
	if !ok {
		m.notice = "kho won't pull " + printable(h.Name) + ":" + printable(t.Name) + ", its name is not a plain image name"
		return
	}
	lines := []string{bold().Render(target), ""}
	if s := byteSize(t.Size); s != "" {
		lines = append(lines, faint().Render("size       ")+s)
	}
	if len(t.Platforms) > 0 {
		lines = append(lines, faint().Render("platforms  ")+platformsText(t.Platforms))
		lines = append(lines, faint().Render("           docker picks the one this machine runs"))
	}
	lines = append(lines, faint().Render("runs       ")+"docker pull "+target, "")
	if slices.Contains(m.hubOnDisk(r), t.Name) {
		lines = append(lines, yellow().Render("⚠ the machine has "+target+" already."),
			faint().Render("pulling fetches what the tag points to now and moves the tag to it."), "")
	}
	lines = append(lines, accent().Render("y")+faint().Render(" pull it   ")+accent().Render("n")+faint().Render(" cancel"))
	title := "⬇ Pull " + target
	m.confirm = &confirm{title: title + "?", lines: lines,
		run: startInstall(title, pullCmd(target), m.log, installedMsg{provider: "docker", name: target, version: t.Name, pulled: true})}
}

// The pulled image is selected once the relisted machine images show it.
func (m *model) selectPulled() {
	if m.pulledImg == "" || m.curRow().kind != rowMachineImages {
		return
	}
	for i, r := range m.imgRows() {
		if r.Canonical() == m.pulledImg {
			m.cursor, m.pulledImg = i, ""
			m.offset = scroll(m.offset, m.cursor, m.layout().rows)
			return
		}
	}
}
