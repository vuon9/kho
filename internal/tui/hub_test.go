package tui

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/registry"
	"github.com/vuon9/kho/internal/trivy"
)

var hubRepos = []registry.HubRepo{
	{Name: "kettle", Description: "Kettle boils water for every build.", Stars: 1204, Pulls: 51200000, Official: true},
	{Name: "acme/kettle-tools", Description: "Extra tools for kettle", Stars: 12, Pulls: 4300},
}

var hubTags = map[string][]image.Tag{
	"docker.io/library/kettle:latest": {
		{Name: "2.4.1", Digest: "sha256:2041", Pushed: time.Date(2031, 4, 2, 0, 0, 0, 0, time.UTC), Size: 48 << 20, Platforms: []string{"linux/amd64", "linux/arm64/v8"}},
		{Name: "latest", Pushed: time.Date(2031, 3, 30, 0, 0, 0, 0, time.UTC), Size: 48 << 20, Platforms: []string{"linux/amd64"}},
	},
	"docker.io/acme/kettle-tools:latest": {
		{Name: "0.3", Pushed: time.Date(2031, 1, 2, 0, 0, 0, 0, time.UTC)},
		{Name: "0.4", Pushed: time.Date(2031, 2, 2, 0, 0, 0, 0, time.UTC)},
	},
}

// What the network and docker were asked during one test.
type hubCalls struct {
	searches []string
	tags     []string
	pulls    []string
	named    []string
	mirrors  []string
	lists    int
	// mirror and stale are what the mirrors answer.
	mirror string
	stale  bool
}

// The machine has kettle:1.0 on disk. Docker Hub answers with hubRepos, and
// once a pull ran, docker lists the pulled image too.
func hubbed(t *testing.T, width int) (model, *hubCalls) {
	t.Helper()
	calls := &hubCalls{}
	m := update(t, loaded(t), tea.WindowSizeMsg{Width: width, Height: 40})
	searchHub = func(_ context.Context, _ image.Asker, q string, _ int) ([]registry.HubRepo, error) {
		calls.searches = append(calls.searches, q)
		return hubRepos, nil
	}
	tagsFor = func(_ context.Context, r image.Ref, _ image.Asker) ([]image.Tag, error) {
		calls.tags = append(calls.tags, r.Canonical())
		return hubTags[r.Canonical()], nil
	}
	pullCmd = func(ref string) *exec.Cmd {
		calls.pulls = append(calls.pulls, ref)
		return exec.Command("docker", "pull", ref)
	}
	tagCmd = func(from, to string) *exec.Cmd {
		calls.named = append(calls.named, to)
		return exec.Command("docker", "tag", from, to)
	}
	mirrorFor = func(_ context.Context, _ image.Asker, r image.Ref, digest string) (string, bool) {
		calls.mirrors = append(calls.mirrors, r.Canonical()+" "+digest)
		return calls.mirror, calls.stale
	}
	onDisk := image.Ref{Image: "kettle:1.0", Registry: image.DockerHub, Repo: "kettle", Tag: "1.0", Presence: image.OnDisk, State: image.Fresh}
	listImages = func(context.Context) ([]image.LocalImage, error) {
		calls.lists++
		return []image.LocalImage{}, nil
	}
	machineImages = func(context.Context, []image.LocalImage, image.Asker) []image.Ref {
		out := []image.Ref{onDisk}
		for _, p := range append(slices.Clone(calls.pulls), calls.named...) {
			r := image.Parse(p)
			r.Presence, r.State = image.OnDisk, image.Fresh
			out = append(out, r)
		}
		return out
	}
	t.Cleanup(func() {
		searchHub = func(context.Context, image.Asker, string, int) ([]registry.HubRepo, error) {
			return nil, errors.New("no Docker Hub in tests")
		}
		tagsFor = func(context.Context, image.Ref, image.Asker) ([]image.Tag, error) { return nil, nil }
		pullCmd = func(ref string) *exec.Cmd { return exec.Command("docker", "pull", ref) }
		tagCmd = func(from, to string) *exec.Cmd { return exec.Command("docker", "tag", from, to) }
		mirrorFor = func(context.Context, image.Asker, image.Ref, string) (string, bool) { return "", false }
	})
	m.machineImgs = []image.Ref{onDisk}
	return searchRail(t, m, "docker"), calls
}

func hubSearched(t *testing.T, width int, query string) (model, *hubCalls) {
	t.Helper()
	m, calls := hubbed(t, width)
	m = typeQuery(t, press(t, m, "n"), query)
	return press(t, m, "enter"), calls
}

func TestHubSearch(t *testing.T) {
	for _, size := range []struct {
		id     string
		width  int
		status []string
	}{
		{"full width", 160, []string{"● on disk", "○ not pulled", "1.2k"}},
		{"110 columns keeps names and drops stars and status words", 110, []string{"acme/kettle-tools   ", "●\n", "○\n"}},
		{"stacked at 90 columns", 90, []string{"● on disk", "○ not pulled", "1.2k"}},
	} {
		width := size.width
		t.Run(size.id, func(t *testing.T) {
			m, calls := hubbed(t, width)
			m = typeQuery(t, press(t, m, "n"), "kettle")
			if m.search == nil || len(calls.searches) != 0 {
				t.Fatalf("typing asked Docker Hub %v, or opened no prompt", calls.searches)
			}
			m = press(t, m, "enter")
			if !slices.Equal(calls.searches, []string{"kettle"}) {
				t.Fatalf("enter asked %v, want one search for kettle", calls.searches)
			}
			sc := screen(m)
			table := ""
			for _, line := range strings.Split(sc, "\n") {
				l := m.layout()
				table += strings.TrimRight(ansi.Cut(line, l.tableX+1, l.tableX+l.tableW-1), " ") + "\n"
			}
			for _, want := range append([]string{"kettle official", "51.2M", "acme/kettle-tools", "4.3k", "2 results · Docker Hub"}, size.status...) {
				if !strings.Contains(table, want) && !strings.Contains(sc, want) {
					t.Errorf("results lack %q:\n%s", want, sc)
				}
			}
			for i, line := range strings.Split(sc, "\n") {
				if w := ansi.StringWidth(line); w != width && i > 0 && i < 39 {
					t.Errorf("line %d is %d wide, want %d", i, w, width)
				}
			}

			m = press(t, m, "enter")
			if m.focus != focusSide || !slices.Equal(calls.tags, []string{"docker.io/library/kettle:latest"}) {
				t.Fatalf("opening a result asked for tags %v, focus %d", calls.tags, m.focus)
			}
			sc = screen(m)
			for _, want := range []string{"Kettle boils water", "hub.docker.com/_/kettle", "latest suggested", "48 MB", "docker pull kettle:latest"} {
				if !strings.Contains(sc, want) {
					t.Errorf("Info lacks %q:\n%s", want, sc)
				}
			}
			if len(calls.pulls) != 0 {
				t.Fatalf("browsing pulled %v", calls.pulls)
			}

			m = press(t, m, "v", "down")
			if !strings.Contains(screen(m), "→ latest") {
				t.Errorf("Versions should point at the suggested tag:\n%s", screen(m))
			}
			m = press(t, m, "up", "enter")
			if m.confirm == nil {
				t.Fatal("enter on a tag should ask first")
			}
			dialog := ansi.Strip(strings.Join(m.confirm.lines, "\n"))
			for _, want := range []string{"kettle:2.4.1", "48 MB", "linux/amd64, linux/arm64/v8", "docker pull kettle:2.4.1"} {
				if !strings.Contains(dialog, want) {
					t.Errorf("the dialog lacks %q:\n%s", want, dialog)
				}
			}
			m = press(t, m, "y")
			if !slices.Equal(ran, []string{"docker pull kettle:2.4.1"}) {
				t.Fatalf("ran %v, want the pull it showed", ran)
			}
			m = press(t, m, "enter")
			if m.search != nil || calls.lists == 0 {
				t.Fatalf("a pull should close the search and relist the images (search %v, lists %d)", m.search != nil, calls.lists)
			}
			if r, ok := m.currentImg(); !ok || r.Canonical() != "docker.io/library/kettle:2.4.1" {
				t.Errorf("selected %+v, want the pulled image", r)
			}
			if m.notice != "pulled kettle:2.4.1" {
				t.Errorf("notice %q", m.notice)
			}
		})
	}
}

func TestHubPullNeedsAYes(t *testing.T) {
	tests := []struct {
		id       string
		keys     []string
		ran      []string
		dialogue string
	}{
		{id: "n cancels", keys: []string{"enter", "n"}},
		{id: "a tag already on disk still asks", keys: []string{"enter", "v", "j", "y"},
			ran: []string{"docker pull kettle:latest"}, dialogue: "the machine has kettle:latest already"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, _ := hubSearched(t, 160, "kettle")
			m.machineImgs = append(m.machineImgs, image.Ref{Image: "kettle:latest", Registry: image.DockerHub, Repo: "kettle", Tag: "latest", Presence: image.OnDisk, State: image.Fresh})
			m = press(t, m, "enter")
			var dialog string
			for _, k := range tt.keys {
				if m.confirm != nil {
					dialog = ansi.Strip(strings.Join(m.confirm.lines, "\n"))
				}
				m = press(t, m, k)
			}
			if !slices.Equal(ran, tt.ran) {
				t.Errorf("ran %v, want %v", ran, tt.ran)
			}
			if !strings.Contains(dialog, tt.dialogue) {
				t.Errorf("dialog lacks %q:\n%s", tt.dialogue, dialog)
			}
		})
	}
}

func TestHubSearchStates(t *testing.T) {
	tests := []struct {
		id    string
		repos []registry.HubRepo
		err   error
		want  []string
	}{
		{id: "no match", repos: []registry.HubRepo{}, want: []string{`no images match "kettle" on Docker Hub`, "searched Docker Hub in"}},
		{id: "a rate limit names Docker Hub", err: registry.ErrHubRateLimited,
			want: []string{"could not search Docker Hub", "rate limiting", "⚠ Docker Hub: docker hub is rate"}},
		{id: "a failed source", err: errors.New("dial tcp: no route"), want: []string{"could not search Docker Hub", "no route"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, _ := hubbed(t, 160)
			searchHub = func(context.Context, image.Asker, string, int) ([]registry.HubRepo, error) { return tt.repos, tt.err }
			m = press(t, typeQuery(t, press(t, m, "n"), "kettle"), "enter")
			sc := screen(m)
			for _, want := range tt.want {
				if !strings.Contains(sc, want) {
					t.Errorf("screen lacks %q:\n%s", want, sc)
				}
			}
			m = press(t, m, "esc")
			if m.search != nil || m.curRow().kind != rowMachineImages {
				t.Errorf("esc should leave the images as they were")
			}
		})
	}
}

func TestHubSearchNeedsTwoCharacters(t *testing.T) {
	m, calls := hubbed(t, 160)
	m = press(t, typeQuery(t, press(t, m, "n"), "k"), "enter")
	if len(calls.searches) != 0 || m.notice != "type one more character" {
		t.Errorf("one character asked %v, notice %q", calls.searches, m.notice)
	}
}

func TestHubCandidateNeverScans(t *testing.T) {
	scans := 0
	scanImage = func(context.Context, string) ([]trivy.Vuln, error) { scans++; return nil, nil }
	trivyAvailable = func() bool { return true }
	m, _ := hubSearched(t, 160, "kettle")
	m = press(t, m, "enter", "a")
	if scans != 0 {
		t.Errorf("a candidate was scanned %d times", scans)
	}
	if !strings.Contains(screen(m), "nothing is scanned before a pull") {
		t.Errorf("Security should say trivy runs after the pull:\n%s", screen(m))
	}
}

func TestProjectImageRowsIgnoreSearch(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
	m = press(t, m, "n")
	if m.search != nil {
		t.Error("n opened a search on a project's images, which kho never changes")
	}
}

func TestHubPasteResolvesALink(t *testing.T) {
	m, calls := hubbed(t, 160)
	m = press(t, m, "n")
	m = update(t, m, tea.PasteMsg{Content: "https://hub.docker.com/r/acme/kettle-tools"})
	m = press(t, m, "enter")
	if !slices.Equal(calls.searches, []string{"https://hub.docker.com/r/acme/kettle-tools"}) {
		t.Errorf("asked %v, want the link as one query", calls.searches)
	}
}

func TestHubPullTriesTheMirrorsFirst(t *testing.T) {
	const mirrored = "mirror.gcr.io/library/kettle:2.4.1"
	tests := []struct {
		id      string
		mirror  string
		stale   bool
		failing bool
		dialog  []string
		ran     []string
		notice  string
	}{
		{id: "a mirror with the tag pulls from it, then names the image as Docker Hub does", mirror: mirrored,
			dialog: []string{"docker pull " + mirrored, "docker tag " + mirrored + " kettle:2.4.1", "from mirror.gcr.io"},
			ran:    []string{"docker pull " + mirrored, "docker tag " + mirrored + " kettle:2.4.1"}, notice: "pulled kettle:2.4.1"},
		{id: "a stale copy on every mirror sends it to Docker Hub", stale: true,
			dialog: []string{"docker pull kettle:2.4.1", "older copy"}, ran: []string{"docker pull kettle:2.4.1"}, notice: "pulled kettle:2.4.1"},
		{id: "no mirror with the tag sends it to Docker Hub",
			dialog: []string{"docker pull kettle:2.4.1", "no mirror has this tag"}, ran: []string{"docker pull kettle:2.4.1"}, notice: "pulled kettle:2.4.1"},
		{id: "a failed pull from a mirror never names anything", mirror: mirrored, failing: true,
			ran: []string{"docker pull " + mirrored}, notice: "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, calls := hubSearched(t, 160, "kettle")
			calls.mirror, calls.stale = tt.mirror, tt.stale
			if tt.failing {
				installScript = "exit 1"
			}
			m = press(t, m, "enter", "v", "up", "enter")
			if m.confirm == nil {
				t.Fatal("no dialog after kho asked the mirrors")
			}
			if !slices.Equal(calls.mirrors, []string{"docker.io/library/kettle:2.4.1 sha256:2041"}) {
				t.Errorf("asked the mirrors %v, want the tag and Docker Hub's digest for it", calls.mirrors)
			}
			dialog := ansi.Strip(strings.Join(m.confirm.lines, "\n"))
			for _, want := range tt.dialog {
				if !strings.Contains(dialog, want) {
					t.Errorf("the dialog lacks %q:\n%s", want, dialog)
				}
			}
			m = press(t, m, "y")
			if !slices.Equal(ran, tt.ran) {
				t.Errorf("ran %v, want %v", ran, tt.ran)
			}
			if !strings.Contains(m.notice, tt.notice) {
				t.Errorf("notice %q, want %q", m.notice, tt.notice)
			}
		})
	}
}

func TestVersionPullTriesTheMirrorsFirst(t *testing.T) {
	_, calls := hubbed(t, 160)
	calls.mirror = "mirror.gcr.io/library/python:3.13-slim"
	m := onImages(t, withImages(t, sampleImages()...))
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: m.images, tags: map[string][]image.Tag{
		"docker.io/library/python:3.9-slim": {{Name: "3.13-slim"}},
	}})
	m = press(t, m, "v")
	m.focus = focusSide
	m = press(t, m, "enter", "y")
	want := []string{"docker pull mirror.gcr.io/library/python:3.13-slim",
		"docker tag mirror.gcr.io/library/python:3.13-slim docker.io/library/python:3.13-slim"}
	if !slices.Equal(ran, want) {
		t.Errorf("ran %v, want %v", ran, want)
	}
}

func TestOtherRegistriesSkipTheMirrors(t *testing.T) {
	_, calls := hubbed(t, 160)
	calls.mirror = "mirror.gcr.io/never"
	r := image.Ref{Image: "ghcr.io/acme/kettle:1", Registry: "ghcr.io", Repo: "acme/kettle", Tag: "1", File: "Dockerfile", Line: 1, State: image.Fresh}
	m := onImages(t, withImages(t, r))
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: m.images, tags: map[string][]image.Tag{"ghcr.io/acme/kettle:1": {{Name: "2"}}}})
	m = press(t, m, "v")
	m.focus = focusSide
	m = press(t, m, "enter")
	if len(calls.mirrors) != 0 || m.confirm == nil {
		t.Fatalf("asked the mirrors %v for a ghcr.io image", calls.mirrors)
	}
	if dialog := ansi.Strip(strings.Join(m.confirm.lines, "\n")); !strings.Contains(dialog, "docker pull ghcr.io/acme/kettle:2") || strings.Contains(dialog, "mirror") {
		t.Errorf("dialog:\n%s", dialog)
	}
}
