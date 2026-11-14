package tui

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/project"
	"github.com/vuon9/kho/internal/trivy"
)

// withImages loads a project and the images its files name, with the states
// the registries would have given them.
func withImages(t *testing.T, refs ...image.Ref) model {
	t.Helper()
	// A test must never reach the real scanner or the network.
	scanImage = func(context.Context, string) ([]trivy.Vuln, error) { return nil, nil }
	trivyAvailable = func() bool { return true }
	scan := project.Scan{Root: "/work/app", Projects: []project.Project{{Lockfiles: []project.Lockfile{
		{Path: "Dockerfile", Manager: "docker"},
	}}}}
	m := withProject(t, scan, false)
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: refs})
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	return m
}

// asker is a registry that answers nothing; the tests that care swap the
// lookups around it.
type asker struct{}

func (asker) Remote(context.Context, image.Ref) (image.Remote, error) { return image.Remote{}, nil }
func (asker) Life(context.Context, image.Ref) (image.Life, error)     { return image.Life{}, nil }

// A row is listed only once kho knows what it is, and the rows arrive one at a
// time instead of all at the end: the table fills in as the registries answer.
func TestImagesArriveOneAtATime(t *testing.T) {
	mk := func(name string) image.Ref {
		return image.Ref{Image: name, Registry: "docker.io", Repo: "library/" + name, Tag: "1", File: "compose.yaml", Line: 1, State: image.Unknown}
	}
	m := withProject(t, project.Scan{Root: "/work/app"}, false)
	m.dir, m.imgAsk = "/work/app", asker{}
	machineImages = func(context.Context, []image.LocalImage, image.Asker) []image.Ref { return nil }
	slow := make(chan struct{})
	inspectImages = func(_ context.Context, refs []image.Ref, _ []image.LocalImage, _ bool, ask image.Asker) []image.Ref {
		if refs[0].Image == "slow:1" {
			<-slow // the first answer is held back until the second has landed
		}
		refs[0].State = image.Fresh
		return refs
	}

	m.gotImages(imagesMsg{gen: m.imgGen, refs: []image.Ref{mk("slow"), mk("quick")}, local: []image.LocalImage{}})
	if got := len(m.imgRows()); got != 0 {
		t.Fatalf("%d rows before any answer, want none", got)
	}
	cmd := m.factsCmd()
	// One answer lands while the other registry is still thinking.
	first := cmd()
	fact, ok := first.(imageFactMsg)
	if !ok {
		t.Fatalf("first message is %T, want an answer", first)
	}
	m.applyFact(fact)
	if got := len(m.imgRows()); got != 1 {
		t.Errorf("%d rows after one answer, want the one that landed", got)
	}
	close(slow)
	for {
		msg := readFact(m.factCh, m.imgGen)()
		if done, ok := msg.(imageFactsDoneMsg); ok {
			m.imgBusy = false
			_ = done
			break
		}
		m.applyFact(msg.(imageFactMsg))
	}
	if got := len(m.imgRows()); got != 2 {
		t.Errorf("%d rows after every answer, want both", got)
	}
}

// A row in the images table answers a click the way a package row does.
func TestImageRowsAreClickable(t *testing.T) {
	m := onImages(t, withImages(t,
		image.Ref{Image: "node:22-alpine", File: "Dockerfile", Line: 1},
		image.Ref{Image: "postgres:16-alpine", File: "compose.yaml", Line: 7},
		image.Ref{Image: "redis:7.4-alpine", File: "compose.yaml", Line: 11},
	))
	l := m.layout()
	at := func(row int) int { return l.top + 1 + row }
	for _, want := range []struct{ panelRow, cursor int }{{2, 1}, {3, 2}, {1, 0}} {
		m2 := m
		m2.click(l.tableX+6, at(want.panelRow))
		if m2.focus != focusTable || m2.cursor != want.cursor {
			t.Errorf("clicking panel row %d gave focus %d and cursor %d, want %d and %d",
				want.panelRow, m2.focus, m2.cursor, focusTable, want.cursor)
		}
	}
}

// onImages moves the rail to the images row.
func onImages(t *testing.T, m model) model {
	t.Helper()
	for i, r := range m.railRows() {
		if r.kind == rowImages {
			m.setRail(i)
			m.curRow()
			return m
		}
	}
	t.Fatal("no images row in the rail")
	return m
}

func sampleImages() []image.Ref {
	return []image.Ref{
		{Image: "python:3.9-slim", Registry: "docker.io", Repo: "python", Tag: "3.9-slim",
			File: "Dockerfile", Line: 3, Source: "dockerfile", Stage: "build",
			Presence: image.NotPulled, Upstream: "3.9.25", Base: "debian",
			EOL: time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC), State: image.EOL},
		{Image: "postgres:13", Registry: "docker.io", Repo: "postgres", Tag: "13",
			File: "compose.yaml", Line: 3, Source: "compose", Service: "db",
			Presence: image.OnDisk, Built: time.Date(2025, 11, 14, 0, 0, 0, 0, time.UTC),
			Upstream: "13.23-1", State: image.EOL},
		{Image: "node:22-alpine", Registry: "docker.io", Repo: "node", Tag: "22-alpine",
			File: "Dockerfile", Line: 9, Source: "dockerfile", Presence: image.OnDisk,
			Upstream: "22.23.4", Base: "alpine", State: image.Stale},
		{Image: "${BASE_IMAGE}", Raw: "${BASE_IMAGE}", Via: "BASE_IMAGE",
			File: "Dockerfile", Line: 12, Source: "dockerfile", Unresolved: true},
	}
}

func TestImagesRailRow(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	line := ""
	for _, l := range strings.Split(screen(m), "\n") {
		if strings.Contains(l, "🐳 docker") {
			line = l
		}
	}
	if !strings.Contains(line, "4") || !strings.Contains(line, "⚠2") || !strings.Contains(line, "↑1") {
		t.Errorf("rail line %q should count 4 images, 2 EOL and 1 stale", line)
	}
}

func TestImagesTable(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	got := screen(m)
	for _, want := range []string{"· docker · 3", "1 unverified hidden", "python:3.9-slim", "postgres:13",
		"node:22-alpine", "Dockerfile:3", "compose.yaml:3", "22.23.4", "EOL", "stale"} {
		if !strings.Contains(got, want) {
			t.Errorf("screen does not show %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "●") || !strings.Contains(got, "○") {
		t.Errorf("screen should mark what is on disk and what is not:\n%s", got)
	}
}

func TestImagesFilter(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = press(t, m, "f")
	got := screen(m)
	if strings.Contains(got, "node:22-alpine") || !strings.Contains(got, "python:3.9-slim") {
		t.Errorf("the past line filter should show only the closed lines:\n%s", got)
	}
	if !strings.Contains(got, "⚠ EOL") {
		t.Errorf("the title should name the filter:\n%s", got)
	}
	// EOL, gone, stale, tracked, untracked, on disk, not pulled.
	m = press(t, m, "f", "f", "f", "f")
	if got := screen(m); !strings.Contains(got, "◌ untracked") || !strings.Contains(got, "${BASE_IMAGE}") || strings.Contains(got, "python:3.9-slim") {
		t.Errorf("the untracked filter should show only what kho cannot follow:\n%s", got)
	}
	m = press(t, m, "f", "f")
	if got := screen(m); !strings.Contains(got, "○ not pulled") || !strings.Contains(got, "python:3.9-slim") || strings.Contains(got, "node:22-alpine") {
		t.Errorf("the not pulled filter should show only what docker does not hold:\n%s", got)
	}
}

func TestImagesKeywordFilter(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = press(t, m, "/", "p", "o", "s", "enter")
	got := screen(m)
	if !strings.Contains(got, "postgres:13") || strings.Contains(got, "python:3.9-slim") {
		t.Errorf("filtering for pos should leave postgres alone:\n%s", got)
	}
}

func TestImagesSidebar(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	got := screen(m)
	for _, want := range []string{"Info", "Versions", "Security", "upstream", "3.9.25", "not pulled", "ended 2025-10-31", "never what is inside"} {
		if !strings.Contains(got, want) {
			t.Errorf("sidebar does not show %q:\n%s", want, got)
		}
	}
}

func TestImagesUnresolvedIsHonest(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	// Unverified images are out of the way unless the untracked filter asks.
	m = press(t, m, "f", "f", "f", "f", "f")
	for i, r := range m.imgRows() {
		if r.Unresolved {
			m.cursor = i
		}
	}
	got := screen(m)
	if !strings.Contains(got, "chosen by") || !strings.Contains(got, "BASE_IMAGE") {
		t.Errorf("an unresolved image should say what chose it:\n%s", got)
	}
	if strings.Contains(got, "✓ fresh") && strings.Contains(got, "BASE_IMAGE") {
		t.Errorf("an unresolved image must never look fresh:\n%s", got)
	}
}

func TestImagesNoProject(t *testing.T) {
	m := loaded(t)
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	for _, r := range m.railRows() {
		if r.kind == rowImages {
			t.Fatal("a machine with no project should have no images row")
		}
	}
}

// A narrow terminal drops columns rather than cutting the state off.
func TestImagesNarrow(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 110, Height: 40})
	got := screen(m)
	if !strings.Contains(got, "⚠ EOL") || !strings.Contains(got, "↑ stale") {
		t.Errorf("the state must survive a narrow table:\n%s", got)
	}
	if strings.Contains(got, "…") && strings.Contains(got, "STATE …") {
		t.Errorf("the header should not be cut off:\n%s", got)
	}
}

// The machine's own images get their own row, and the two lists stay apart.
func TestMachineImagesRow(t *testing.T) {
	m := withImages(t, sampleImages()...)
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: m.images, machine: []image.Ref{
		{Image: "nginx:alpine", Registry: "docker.io", Repo: "nginx", Tag: "alpine",
			Presence: image.OnDisk, State: image.Fresh, Upstream: "1.29.3"},
		{Image: "hermes-agent:latest", Registry: "docker.io", Repo: "hermes-agent", Tag: "latest",
			Presence: image.OnDisk, State: image.Local},
	}})
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	for i, r := range m.railRows() {
		if r.kind == rowMachineImages {
			m.setRail(i)
		}
	}
	if m.curRow().kind != rowMachineImages {
		t.Fatalf("the docker row should be selectable, selected %+v", m.curRow())
	}
	got := screen(m)
	for _, want := range []string{"🐳 docker", "nginx:alpine", "hermes-agent:latest", "· local"} {
		if !strings.Contains(got, want) {
			t.Errorf("machine images should show %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "python:3.9-slim") {
		t.Errorf("the project's images must not appear in the machine list:\n%s", got)
	}
}

// The Versions tab lists what the repository publishes, with the tag in use
// marked.
func TestImageVersionsTab(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: m.images, tags: map[string][]image.Tag{
		"docker.io/library/python:3.9-slim": {
			{Name: "3.13-slim", Pushed: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)},
			{Name: "3.9-slim", Pushed: time.Date(2025, 10, 20, 0, 0, 0, 0, time.UTC)},
		},
	}})
	m = press(t, m, "v")
	got := screen(m)
	for _, want := range []string{"tags · docker.io", "3.13-slim", "3.9-slim", "2026-11-05"} {
		if !strings.Contains(got, want) {
			t.Errorf("versions tab should show %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "→ 3.9-slim") {
		t.Errorf("the tag in use should be marked:\n%s", got)
	}
}

// The Security tab says what kho cannot know, and lists what a scan found.
func TestImageSecurityTab(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = press(t, m, "a")
	got := screen(m)
	for _, want := range []string{"trivy found no known vulnerabilities"} {
		if !strings.Contains(got, want) {
			t.Errorf("the security tab should say %q:\n%s", want, got)
		}
	}
	key := m.imgRows()[0].Canonical()
	m = update(t, m, imageScanMsg{key: key, vulns: []trivy.Vuln{
		{ID: "CVE-2025-1234", Severity: "CRITICAL", Package: "openssl", Installed: "3.0.1", Fixed: "3.0.2"},
		{ID: "CVE-2025-9999", Severity: "LOW", Package: "zlib", Installed: "1.2.11"},
	}})
	got = screen(m)
	for _, want := range []string{"2 findings · trivy", "CVE-2025-1234", "openssl", "CVE-2025-9999"} {
		if !strings.Contains(got, want) {
			t.Errorf("a scan result should show %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "CVE-2025-1234") > strings.Index(got, "CVE-2025-9999") {
		t.Errorf("critical should sort above low:\n%s", got)
	}
}

// A scan result splits the sidebar like a package's: the list above, the
// finding below.
func TestImageSecuritySplit(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	key := m.imgRows()[0].Canonical()
	m = update(t, m, imageScanMsg{key: key, vulns: []trivy.Vuln{
		{ID: "CVE-2025-1234", Severity: "CRITICAL", Package: "openssl", Installed: "3.0.1",
			Fixed: "3.0.2", Title: "openssl: a bug", URL: "https://example.test/CVE-2025-1234"},
	}})
	m = press(t, m, "a")
	got := screen(m)
	for _, want := range []string{"🛡 CVE-2025-1234", "openssl", "3.0.2", "openssl: a bug", "from trivy"} {
		if !strings.Contains(got, want) {
			t.Errorf("the split sidebar should show %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "├─") {
		t.Errorf("the finding should sit under a divider:\n%s", got)
	}
}

// The upstream line in the Info tab is a link: clicking it opens the
// lifecycle page, the way a package's homepage opens.
func TestImageUpstreamLinkIsClickable(t *testing.T) {
	opened = nil
	defer func() { openURL = func(string) error { return nil } }()
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	for row := 0; row < m.layout().topRows; row++ {
		if cmd := m.clickSide(4, row, true); cmd != nil {
			cmd()
		}
		if len(opened) > 0 {
			break
		}
	}
	if len(opened) != 1 || opened[0] != "https://endoflife.date/python" {
		t.Errorf("clicking the upstream line should open its page, opened %v", opened)
	}
}

// The fixed line at the foot of the panel names what the tab is looking at.
func TestImageTabStatus(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: m.images, tags: map[string][]image.Tag{
		"docker.io/library/python:3.9-slim": {{Name: "3.9-slim"}},
	}})
	m = press(t, m, "v")
	box := strings.Split(ansi.Strip(m.imageSideBox(46, 20, false)), "\n")
	last := box[len(box)-2]
	if !strings.Contains(last, "── tags · docker.io") {
		t.Errorf("the versions tab should name the registry on its last row, got %q\n%s", last, strings.Join(box, "\n"))
	}
	if !strings.Contains(strings.Join(box, "\n"), "→ 3.9-slim") {
		t.Errorf("the tag in use should still be listed:\n%s", strings.Join(box, "\n"))
	}
	if n := strings.Count(strings.Join(box, "\n"), "tags · "); n != 1 {
		t.Errorf("the registry should be named once, at the foot, found %d:\n%s", n, strings.Join(box, "\n"))
	}
}

// Opening Security scans without being asked.
func TestImageAutoScan(t *testing.T) {
	scans := 0
	m := onImages(t, withImages(t, sampleImages()...))
	scanImage = func(context.Context, string) ([]trivy.Vuln, error) {
		scans++
		return []trivy.Vuln{{ID: "CVE-2025-1", Severity: "HIGH", Package: "musl"}}, nil
	}
	m = press(t, m, "a")
	if scans != 1 {
		t.Fatalf("opening Security should scan once, scanned %d", scans)
	}
	if got := screen(m); !strings.Contains(got, "CVE-2025-1") {
		t.Errorf("the scan result should show without pressing anything else:\n%s", got)
	}
}

// The scan is lazy: opening Security runs it, and nothing else does. A clean
// result is kept, and a failed one is asked again only when the tab opens
// again, never on every redraw.
func TestImageScanIsLazy(t *testing.T) {
	tests := []struct {
		id    string
		err   error
		keys  []string
		scans int
	}{
		{"a clean image is scanned once", nil, []string{"a", "J", "K", "J"}, 1},
		{"a failed scan waits on screen", errors.New("trivy failed"), []string{"a", "J", "K", "J"}, 1},
		{"a failed scan runs again when the tab reopens", errors.New("trivy failed"), []string{"a", "i", "a"}, 2},
		{"another tab never scans", nil, []string{"i", "J"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := onImages(t, withImages(t, sampleImages()...))
			scans := 0
			scanImage = func(context.Context, string) ([]trivy.Vuln, error) {
				scans++
				return nil, tt.err
			}
			for _, k := range tt.keys {
				m = press(t, m, k)
			}
			if scans != tt.scans {
				t.Errorf("scanned %d times, want %d", scans, tt.scans)
			}
		})
	}
}

// Enter on a version asks before pulling it, the way a package install does.
func TestImageVersionPull(t *testing.T) {
	var asked string
	pullCmd = func(ref string) *exec.Cmd { asked = ref; return exec.Command("true") }
	defer func() { pullCmd = func(ref string) *exec.Cmd { return exec.Command("docker", "pull", ref) } }()
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: m.images, tags: map[string][]image.Tag{
		"docker.io/library/python:3.9-slim": {{Name: "3.13-slim"}},
	}})
	m = press(t, m, "v")
	m.focus = focusSide
	m = press(t, m, "enter")
	if m.confirm == nil {
		t.Fatal("enter on a version should ask first")
	}
	if asked != "docker.io/library/python:3.13-slim" {
		t.Errorf("pulled %q, want docker.io/library/python:3.13-slim", asked)
	}
	dialog := strings.Join(m.confirm.lines, "\n")
	if !strings.Contains(dialog, "docker pull docker.io/library/python:3.13-slim") {
		t.Errorf("the dialog should name the command:\n%s", dialog)
	}
}

// y opens the page for the selected tag.
func TestImageVersionOpensOnTheWeb(t *testing.T) {
	opened = nil
	defer func() { openURL = func(string) error { return nil } }()
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: m.images, tags: map[string][]image.Tag{
		"docker.io/library/python:3.9-slim": {{Name: "3.13-slim"}},
	}})
	m = press(t, m, "v")
	m = press(t, m, "y")
	if len(opened) != 1 || !strings.Contains(opened[0], "hub.docker.com/r/library/python/tags?name=3.13-slim") {
		t.Errorf("y should open the tag page, opened %v", opened)
	}
}

func TestTagOrder(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	tags := []image.Tag{
		{Name: "3.12.16-alpine", Pushed: day(1)},
		{Name: "3.13.2", Pushed: day(1)},
		{Name: "latest", Pushed: day(5)},
		{Name: "3.12.16-bookworm", Pushed: day(9)},
		{Name: "3.13.2-alpine", Pushed: day(3)},
	}
	tagOrder(tags)
	want := []string{"3.13.2-alpine", "3.13.2", "3.12.16-bookworm", "3.12.16-alpine", "latest"}
	for i, w := range want {
		if tags[i].Name != w {
			t.Fatalf("order %v, want %v", tags, want)
		}
	}
}

// Unverified images stay out of the list, but never disappear silently.
func TestImagesHideUnverified(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	got := screen(m)
	if strings.Contains(got, "BASE_IMAGE") {
		t.Errorf("an unresolved image should be out of the way:\n%s", got)
	}
	if !strings.Contains(got, "1 unverified hidden") {
		t.Errorf("the title should say one is hidden:\n%s", got)
	}
	m = press(t, m, "f", "f", "f", "f", "f")
	if !strings.Contains(screen(m), "BASE_IMAGE") {
		t.Errorf("the untracked filter should show it again:\n%s", screen(m))
	}
}

// Opening Versions asks the repository, whether it was opened with v, with a
// numbered tab, or with a click on the tab bar.
func TestVersionsTabAsksHoweverItOpens(t *testing.T) {
	asked := 0
	tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) {
		asked++
		return []image.Tag{{Name: "22.23.4"}}, nil
	}
	t.Cleanup(func() {
		tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) { return nil, nil }
	})

	for _, open := range []struct {
		id string
		do func(model) model
	}{
		{id: "the v key", do: func(m model) model { return update(t, m, tea.KeyPressMsg{Code: 'v', Text: "v"}) }},
		{id: "the numbered tab", do: func(m model) model { return update(t, m, tea.KeyPressMsg{Code: '2', Text: "2"}) }},
		{id: "a click on the tab bar", do: func(m model) model {
			l := m.layout()
			tabX := l.sideX + 3 + lipgloss.Width(m.tabLabels()[0]) + 2
			return update(t, m, tea.MouseClickMsg{X: tabX, Y: l.top, Button: tea.MouseLeft})
		}},
	} {
		asked = 0
		m := onImages(t, withImages(t, sampleImages()...))
		m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
		m = open.do(m)
		if asked != 1 {
			t.Errorf("%s: asked %d times, want once", open.id, asked)
			continue
		}
		r, _ := m.currentImg()
		if got := m.imgTags[r.Canonical()]; len(got) != 1 {
			t.Errorf("%s: tags %v, want the repository's answer", open.id, got)
		}
	}
}

// An empty answer reads as empty and says why, instead of looking like a
// repository that publishes one version.
func TestVersionsSaysWhyItIsEmpty(t *testing.T) {
	tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) {
		return nil, errors.New("docker hub answered 429 for library/python")
	}
	t.Cleanup(func() {
		tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) { return nil, nil }
	})

	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = update(t, m, tea.KeyPressMsg{Code: 'v', Text: "v"})

	r, _ := m.currentImg()
	var text []string
	for _, l := range m.imageVersionLines(r) {
		text = append(text, l.text)
	}
	joined := ansi.Strip(strings.Join(text, "\n"))
	if !strings.Contains(joined, "429") {
		t.Errorf("panel %q, want the reason it is empty", joined)
	}
	if strings.Contains(joined, "→") {
		t.Errorf("panel %q, want no version row when the registry said nothing", joined)
	}
}

// A failed ask heals itself once, without waiting for someone to press v.
func TestVersionsRetriesOnceByItself(t *testing.T) {
	asked := 0
	tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) {
		asked++
		if asked == 1 {
			return nil, errors.New("docker hub answered 429")
		}
		return []image.Tag{{Name: "22.23.4"}}, nil
	}
	t.Cleanup(func() {
		tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) { return nil, nil }
	})

	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = update(t, m, tea.KeyPressMsg{Code: 'v', Text: "v"})
	r, _ := m.currentImg()
	if asked != 1 || m.imgTags[r.Canonical()] != nil {
		t.Fatalf("first ask: asked %d, tags %v, want one failed ask", asked, m.imgTags[r.Canonical()])
	}
	m = update(t, m, imageTagsRetryMsg{key: r.Canonical()})
	if asked != 2 {
		t.Fatalf("asked %d times, want the retry", asked)
	}
	if got := m.imgTags[r.Canonical()]; len(got) != 1 {
		t.Errorf("tags %v after the retry, want the answer", got)
	}
}

// Moving to another image while Versions is open asks about that image too,
// instead of leaving the panel on "press v again".
func TestVersionsAsksWhenTheRowMoves(t *testing.T) {
	asked := map[string]int{}
	tagsFor = func(_ context.Context, r image.Ref, _ image.Asker) ([]image.Tag, error) {
		asked[r.Canonical()]++
		return []image.Tag{{Name: "1.0"}}, nil
	}
	t.Cleanup(func() {
		tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) { return nil, nil }
	})

	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = update(t, m, tea.KeyPressMsg{Code: 'v', Text: "v"})

	first, _ := m.currentImg()
	m = update(t, m, tea.KeyPressMsg{Code: 'j', Text: "j"})
	second, _ := m.currentImg()
	if first.Canonical() == second.Canonical() {
		t.Fatal("the cursor did not move to another image")
	}
	if asked[second.Canonical()] != 1 {
		t.Errorf("asked %v, want the image the cursor moved to", asked)
	}
	if got := m.imgTags[second.Canonical()]; len(got) != 1 {
		t.Errorf("tags %v for the second image, want its answer", got)
	}
}

// The image table carries the same bar as a package table: the keyword box,
// then a chip per state with how many it holds.
func TestImagesHaveTheSameFilterBar(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})

	bar := ansi.Strip(m.filterBar())
	for _, want := range []string{"⌕", "All ", "⚠", "↑", "◎", "●"} {
		if !strings.Contains(bar, want) {
			t.Errorf("bar %q, want %q in it", bar, want)
		}
	}
	if counts := m.imgCounts(); counts[imgStatusEOL] != 2 {
		t.Errorf("counts %v, want two images past their line", counts)
	}

	// and a click on the second chip selects that state, like a package table
	m = update(t, m, tea.KeyPressMsg{Code: 'f', Text: "f"})
	if bar := ansi.Strip(m.filterBar()); !strings.Contains(bar, "⚠ EOL") {
		t.Errorf("bar %q, want the active chip named in full", bar)
	}
	head, chips := m.filterBarChips()
	x := lipgloss.Width(head) + 1
	if got := m.chipAt(x); got != chips[0].status {
		t.Errorf("clicking the first chip gave %d, want %d", got, chips[0].status)
	}
	if m.imgStatus() != imgStatusEOL {
		t.Errorf("f left the images on state %d, want EOL", m.imgStatus())
	}
}

// s sorts the image table by its own columns, and F steps the state back.
func TestImagesSortAndReverse(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	first := m.imgRows()[0].Image

	m = update(t, m, key("s"))
	if m.imgSort != imgColName {
		t.Fatalf("s left the sort on %d, want the name column", m.imgSort)
	}
	sorted := m.imgRows()[0].Image
	if sorted == first {
		t.Errorf("sorting by name left %q first", sorted)
	}
	if !strings.Contains(ansi.Strip(strings.Join(m.imageTableLines(), "\n")), "IMAGE▲") {
		t.Error("the header does not mark the sorted column")
	}
	m = update(t, m, key("S"))
	if got := m.imgRows()[0].Image; got == sorted {
		t.Errorf("reversing left %q first", got)
	}

	m = update(t, m, key("f"))
	m = update(t, m, key("F"))
	if m.imgStatus() != imgStatusAll {
		t.Errorf("F left the state on %d, want All", m.imgStatus())
	}
}

// The keys that only mean something for a package do nothing on an image row.
func TestPackageStatusKeysIgnoreImageRows(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})

	for _, k := range []string{"o", "!"} {
		before := m.statuses[m.curRow().key]
		m = update(t, m, key(k))
		if m.statuses[m.curRow().key] != before {
			t.Errorf("%s changed the package status under an image row", k)
		}
		if m.confirm != nil {
			t.Errorf("%s opened a dialog on an image row", k)
		}
	}
}

// A filter that hides every image says so, the way a package table does,
// instead of claiming the project names no images.
func TestImagesSayNothingMatches(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m.setFilter("no-such-image")
	if len(m.imgRows()) != 0 {
		t.Fatalf("rows %d, want the filter to hide them", len(m.imgRows()))
	}
	screen := ansi.Strip(strings.Join(m.imageTableLines(), "\n"))
	if !strings.Contains(screen, "nothing matches") {
		t.Errorf("screen %q, want it to say nothing matches", screen)
	}
}

// D on an image asks first, and says which containers still use it.
func TestImageRemoveAsksWithItsContainers(t *testing.T) {
	imageUsers = func(context.Context, image.Ref) ([]image.Container, error) {
		return []image.Container{
			{Name: "shop-api", Image: "python:3.9-slim", State: "running"},
			{Name: "shop-db", Image: "python:3.9-slim", State: "exited"},
		}, nil
	}
	t.Cleanup(func() { imageUsers = image.Users })

	refs := sampleImages()
	refs[0].Presence = image.OnDisk
	m := onImages(t, withImages(t, refs...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = update(t, m, key("D"))

	if m.confirm == nil {
		t.Fatal("D did not ask")
	}
	screen := ansi.Strip(m.confirm.title + "\n" + strings.Join(m.confirm.lines, "\n"))
	for _, want := range []string{"python:3.9-slim", "shop-api", "shop-db", "2 containers still use it", "docker refuses"} {
		if !strings.Contains(screen, want) {
			t.Errorf("dialog %q, want %q in it", screen, want)
		}
	}
	if m.confirm.run == nil {
		t.Error("the dialog has nothing to run when the person says yes")
	}
}

// An image that is not on disk has nothing to remove, and kho says so instead
// of opening a dialog that would fail.
func TestImageRemoveNeedsItOnDisk(t *testing.T) {
	refs := sampleImages()
	refs[0].Presence = image.NotPulled
	m := onImages(t, withImages(t, refs...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = update(t, m, key("D"))

	if m.confirm != nil {
		t.Error("D asked to remove an image that is not on disk")
	}
	if !strings.Contains(m.notice, "not on disk") {
		t.Errorf("notice %q, want it to say why nothing happened", m.notice)
	}
}

// Every line that says work is in progress starts with the same spinner, and
// the ticker runs while it does, so the frame moves.
func TestImageProgressSpins(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m.frame = 3
	m.images, m.imgBusy = nil, true
	if !m.working() {
		t.Error("the ticker must run while kho reads a project's images")
	}
	screen := ansi.Strip(strings.Join(m.imageTableLines(), "\n"))
	if !strings.Contains(screen, spinner[3]+" reading Dockerfiles and compose files") {
		t.Errorf("table %q, want the spinner in front of the reading line", screen)
	}

	refs := sampleImages()
	m = onImages(t, withImages(t, refs...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m.frame = 5
	m.setTab(tabVersions)
	r, _ := m.currentImg()
	m.imgTagBusy[r.Canonical()] = true
	if !m.working() {
		t.Error("the ticker must run while a repository is asked for tags")
	}
	if got := ansi.Strip(m.imageTabStatus()); !strings.Contains(got, spinner[5]+" asking") {
		t.Errorf("tab status %q, want the spinner in front of asking", got)
	}
	m.imgTagBusy[r.Canonical()] = false
	m.imgScanning[r.Canonical()] = true
	m.setTab(tabSecurity)
	if got := ansi.Strip(m.imageTabStatus()); !strings.Contains(got, spinner[5]+" scanning") {
		t.Errorf("tab status %q, want the spinner in front of scanning", got)
	}
}

// A dialog wraps what is in it: a long sentence grows the box instead of being
// cut at the border with an ellipsis.
func TestPopupsWrapTheirContent(t *testing.T) {
	long := "docker refuses to remove an image a container still uses, so remove that container first or keep the image as it is"
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m.confirm = &confirm{title: "🗑 Remove a-very-long-image-name:1.2.3-alpine?", lines: []string{long, "", "y remove it   n keep it"}}

	screen := ansi.Strip(m.View().Content)
	var dialog []string
	for i, line := range strings.Split(screen, "\n") {
		if lipgloss.Width(line) > 100 {
			t.Errorf("line %d is %d wide: %q", i, lipgloss.Width(line), line)
		}
		if strings.Contains(line, "┃") {
			dialog = append(dialog, line)
		}
	}
	if len(dialog) == 0 {
		t.Fatal("the dialog is not on screen")
	}
	for _, line := range dialog {
		if strings.Contains(line, "…") {
			t.Errorf("the dialog cut its text: %q", line)
		}
	}
	if got := strings.Count(screen, "docker refuses to remove an image"); got != 1 {
		t.Errorf("the sentence starts %d times, want it wrapped once", got)
	}
	for _, word := range strings.Fields(long) {
		if !strings.Contains(screen, word) {
			t.Errorf("word %q is missing, so the text was cut", word)
		}
	}
}

// However many containers use an image, the question at the bottom of the
// dialog stays on screen.
func TestImageRemoveKeepsItsQuestionVisible(t *testing.T) {
	users := []image.Container{}
	for _, n := range []string{"api", "db", "cache", "queue", "search", "worker"} {
		users = append(users, image.Container{Name: n, Image: "python:3.9-slim", State: "exited"})
	}
	imageUsers = func(context.Context, image.Ref) ([]image.Container, error) { return users, nil }
	t.Cleanup(func() { imageUsers = image.Users })

	refs := sampleImages()
	refs[0].Presence = image.OnDisk
	m := onImages(t, withImages(t, refs...))
	m = update(t, m, tea.WindowSizeMsg{Width: 100, Height: 16})
	m = update(t, m, key("D"))

	screen := ansi.Strip(m.View().Content)
	if !strings.Contains(screen, "y remove it") {
		t.Errorf("the question is off screen:\n%s", screen)
	}
	if !strings.Contains(screen, "… ") {
		t.Error("the dialog did not say how many containers it left out")
	}
}

// The Info tab says which containers are made from the image, since that is
// what stands between it and a removal.
func TestImageInfoListsItsContainers(t *testing.T) {
	imageUsers = func(context.Context, image.Ref) ([]image.Container, error) {
		return []image.Container{
			{Name: "shop-api", Image: "python:3.9-slim", State: "running"},
			{Name: "shop-db", Image: "python:3.9-slim", State: "exited"},
		}, nil
	}
	t.Cleanup(func() { imageUsers = image.Users })

	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = update(t, m, key("i"))

	r, _ := m.currentImg()
	screen := ansi.Strip(strings.Join(linesText(m.imageTabLines(40)), "\n"))
	for _, want := range []string{"containers", "2 in use", "shop-api", "running", "shop-db", "exited"} {
		if !strings.Contains(screen, want) {
			t.Errorf("info tab %q, want %q in it", screen, want)
		}
	}
	if m.imgUsers[r.Canonical()] == nil {
		t.Error("the tab did not keep what docker answered")
	}
}

// An image nothing was made from says so, instead of saying nothing.
func TestImageInfoSaysNoContainer(t *testing.T) {
	imageUsers = func(context.Context, image.Ref) ([]image.Container, error) { return nil, nil }
	t.Cleanup(func() { imageUsers = image.Users })

	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m = update(t, m, key("i"))

	screen := ansi.Strip(strings.Join(linesText(m.imageTabLines(40)), "\n"))
	if !strings.Contains(screen, "containers") || !strings.Contains(screen, "none") {
		t.Errorf("info tab %q, want it to say no container uses it", screen)
	}
}

// linesText is the plain text of a sidebar block.
func linesText(lines []line) []string {
	var out []string
	for _, l := range lines {
		if l.label != "" {
			out = append(out, l.label+" "+l.text)
			continue
		}
		out = append(out, l.text)
	}
	return out
}

// A state has one mark in the table and the sidebar, the one a package with
// the same problem has: stale is ↑ like outdated, pinned is ⚑ like pinned.
func TestImageStateMarks(t *testing.T) {
	tests := []struct {
		state       image.State
		table, side string
	}{
		{image.Stale, "↑ stale", "↑ stale"},
		{image.Gone, "✗ gone", "✗ tag gone"},
		{image.Pinned, "⚑ pinned", "⚑ pinned"},
		{image.EOL, "⚠ EOL", "⚠ past line"},
		{image.Fresh, "✓ fresh", "✓ fresh"},
		{image.Local, "· local", "· local"},
		{image.None, "· n/a", "· nothing to ask"},
		{image.Unknown, "· unverified", "· unverified"},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			r := image.Ref{State: tt.state}
			if got, want := [2]string{shortState(r), stateWord(r)}, [2]string{tt.table, tt.side}; got != want {
				t.Errorf("table and sidebar say %q, want %q", got, want)
			}
		})
	}
}
