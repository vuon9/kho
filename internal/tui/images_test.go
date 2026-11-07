package tui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/project"
)

// withImages loads a project and the images its files name, with the states
// the registries would have given them.
func withImages(t *testing.T, refs ...image.Ref) model {
	t.Helper()
	scan := project.Scan{Root: "/work/app", Projects: []project.Project{{Lockfiles: []project.Lockfile{
		{Path: "Dockerfile", Manager: "docker"},
	}}}}
	m := withProject(t, scan, false)
	m = update(t, m, imagesMsg{gen: m.imgGen, refs: refs})
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	return m
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
	for _, want := range []string{"· images · 4", "python:3.9-slim", "postgres:13", "node:22-alpine",
		"Dockerfile:3", "compose.yaml:3", "22.23.4", "EOL", "stale", "build"} {
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
	m = press(t, m, "f", "f", "f")
	if !strings.Contains(screen(m), "python:3.9-slim") || strings.Contains(screen(m), "node:22-alpine") {
		t.Errorf("the not pulled filter should show only what docker does not hold:\n%s", screen(m))
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
	for _, want := range []string{"Image", "upstream", "3.9.25", "not pulled", "ended 2025-10-31", "never what is inside"} {
		if !strings.Contains(got, want) {
			t.Errorf("sidebar does not show %q:\n%s", want, got)
		}
	}
}

func TestImagesUnresolvedIsHonest(t *testing.T) {
	m := onImages(t, withImages(t, sampleImages()...))
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
