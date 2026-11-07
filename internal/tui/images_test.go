package tui

import (
	"context"
	"os/exec"
	"strings"

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

// The table is drawn from the files before the registries answer: the rows are
// there, saying asking, and the answers replace them when they land.
func TestImagesPaintBeforeTheRegistriesAnswer(t *testing.T) {
	ref := image.Ref{Image: "node:22-alpine", Registry: "docker.io", Repo: "library/node", Tag: "22-alpine", File: "Dockerfile", Line: 1, State: image.Unknown}
	m := withProject(t, project.Scan{Root: "/work/app"}, false)
	m.dir, m.imgAsk = "/work/app", asker{}
	asked := 0
	inspectImages = func(_ context.Context, refs []image.Ref, _ []image.LocalImage, _ bool, ask image.Asker) []image.Ref {
		if ask != nil {
			asked++
			for i := range refs {
				refs[i].State = image.Fresh
			}
		}
		return refs
	}
	machineImages = func(context.Context, []image.LocalImage, image.Asker) []image.Ref { return nil }

	m.gotImages(imagesMsg{gen: m.imgGen, refs: []image.Ref{ref}, local: []image.LocalImage{}})
	if got := len(m.imgRows()); got != 1 {
		t.Fatalf("%d rows while asking, want the one from the file", got)
	}
	if got := ansi.Strip(m.imageState(m.imgList()[0])); !strings.Contains(got, "asking") {
		t.Errorf("the row says %q, want asking", got)
	}
	if !strings.Contains(ansi.Strip(m.imageTitle()), "reading") {
		t.Errorf("title %q does not say it is reading", ansi.Strip(m.imageTitle()))
	}
	if !strings.Contains(ansi.Strip(m.tableTitle()), "reading") && !strings.Contains(ansi.Strip(m.imageTitle()), "reading") {
		t.Errorf("nothing says reading")
	}
	m = update(t, m, m.factsCmd()())
	if asked == 0 {
		t.Fatal("the registries were never asked")
	}
	if got := m.imgRows(); len(got) != 1 || got[0].State != image.Fresh {
		t.Errorf("after the answer the row is %+v, want fresh", got)
	}
	if strings.Contains(ansi.Strip(m.imageTitle()), "reading") {
		t.Errorf("title %q still says reading", ansi.Strip(m.imageTitle()))
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
		if strings.Contains(l, "🐳 images") {
			line = l
		}
	}
	if !strings.Contains(line, "4") || !strings.Contains(line, "⚠2") || !strings.Contains(line, "⟳1") {
		t.Errorf("rail line %q should count 4 images, 2 past their line and 1 stale", line)
	}
}

func TestImagesTable(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	got := screen(m)
	for _, want := range []string{"· images · 3", "1 unverified hidden", "python:3.9-slim", "postgres:13",
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
	if !strings.Contains(got, "⚠ past line") {
		t.Errorf("the title should name the filter:\n%s", got)
	}
	// past line, stale, tracked, untracked, on disk, not pulled.
	m = press(t, m, "f", "f", "f")
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
	m = press(t, m, "f", "f", "f", "f")
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
	if !strings.Contains(got, "⚠ EOL") || !strings.Contains(got, "⟳ stale") {
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
	for _, want := range []string{"does not read inside an image", "scan this image with trivy"} {
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
	m = press(t, m, "f", "f", "f", "f")
	if !strings.Contains(screen(m), "BASE_IMAGE") {
		t.Errorf("the untracked filter should show it again:\n%s", screen(m))
	}
}
