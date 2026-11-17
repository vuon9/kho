package tui

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/image"
	"github.com/vuon9/kho/internal/project"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

type catalogFake struct {
	fake
	results         []provider.Package
	bulk            []provider.Package
	latest          map[string]string
	err             error
	findErr         error
	added           []provider.Package
	searches, finds int
}

func (f *catalogFake) List(context.Context) ([]provider.Package, error) {
	return append(slices.Clone(f.pkgs), f.added...), nil
}

func (f *catalogFake) Search(_ context.Context, q string, limit int) ([]provider.Package, error) {
	f.searches++
	if f.err != nil {
		return nil, f.err
	}
	if q == "bulk" {
		return f.bulk, nil
	}
	var out []provider.Package
	for _, p := range f.results {
		if strings.Contains(strings.ToLower(p.Name), strings.ToLower(q)) ||
			strings.Contains(strings.ToLower(p.Desc), strings.ToLower(q)) {
			out = append(out, p)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *catalogFake) Find(_ context.Context, source, name string) (provider.Package, error) {
	f.finds++
	if f.findErr != nil {
		return provider.Package{}, f.findErr
	}
	for _, p := range f.results {
		if p.Source == source && p.Name == name {
			if v, ok := f.latest[name]; ok {
				p.Latest = v
			}
			return p, nil
		}
	}
	return provider.Package{}, errors.New("not found")
}

// No keyword search, as pipx, uv and go have none.
type finderFake struct {
	fake
	results []provider.Package
	latest  map[string]string
	finds   int
}

func (f *finderFake) Find(_ context.Context, source, name string) (provider.Package, error) {
	f.finds++
	for _, p := range f.results {
		if p.Source == source && p.Name == name {
			if v, ok := f.latest[name]; ok {
				p.Latest = v
			}
			return p, nil
		}
	}
	return provider.Package{}, errors.New("not found")
}

type searchStack struct {
	brew, npm, composer *catalogFake
	pipx, gobin         *finderFake
	mise                *fake
	skills              *catalogFake
}

func searchable(t *testing.T) (model, *searchStack) {
	t.Helper()
	loaded(t)
	s := &searchStack{
		brew: &catalogFake{
			fake: fake{name: "brew", versions: map[string][]provider.Release{
				"yq": {{Version: "0.2.94"}, {Version: "0.2.89"}},
			}, pkgs: []provider.Package{
				{Source: "brew", Name: "anvil", Version: "0.2.89", Latest: "0.2.94", Outdated: true, Homepage: "https://anvil.example", Repo: "example/anvil"},
				{Source: "brew", Name: "focus", Version: "1.1.1", Latest: "1.1.1"},
				{Source: "brew", Name: "forge", Version: "2.0.0", Latest: "2.0.0", Origin: "acme/tools"},
			}},
			results: []provider.Package{
				{Source: "brew", Name: "anvil", Latest: "0.2.94"},
				{Source: "brew", Name: "yq", Latest: "0.2.94", Desc: "A lightweight and portable YAML processor",
					Homepage: "https://yq.example", Repo: "example/yq", Origin: "homebrew/core"},
				{Source: "cask", Name: "focus", Latest: "1.2.3"},
				{Source: "brew", Name: "acme/tools/forge", Latest: "2.0.0"},
			},
		},
		npm: &catalogFake{
			fake:    fake{name: "npm", versions: map[string][]provider.Release{"yaml": {{Version: "2.8.1"}, {Version: "2.7.0"}}}},
			results: []provider.Package{{Source: "npm", Name: "yaml", Latest: "2.8.1", Desc: "JavaScript parser for YAML"}},
		},
		composer: &catalogFake{
			fake:    fake{name: "composer"},
			results: []provider.Package{{Source: "composer", Name: "yaml-lint", Desc: "Lint a composer yaml file"}},
			latest:  map[string]string{"yaml-lint": "1.4.0"},
		},
		pipx: &finderFake{
			fake:    fake{name: "pipx", versions: map[string][]provider.Release{"ruff": {{Version: "0.14.0"}, {Version: "0.13.0"}}}},
			results: []provider.Package{{Source: "pipx", Name: "ruff", Latest: "0.14.0", Desc: "A fast Python linter"}},
		},
		gobin: &finderFake{
			fake:    fake{name: "go"},
			results: []provider.Package{{Source: "go", Name: "wren", Latest: "v1.2.0", Origin: "example.com/wren", Entry: "example.com/wren/cmd/wren"}},
		},
		mise: &fake{name: "mise"},
		skills: &catalogFake{
			fake: fake{name: "skills"},
			results: []provider.Package{
				{Source: "skills", Name: "pdf", Desc: "1200 installs", Latest: provider.SkillNewest,
					Origin: "acme/skills", Repo: "acme/skills", Entry: "pdf", Path: skillDocDir(t, "pdf"),
					Homepage: "https://www.skills.sh/acme/skills/pdf"},
				{Source: "skills", Name: "pdf-tools", Desc: "800 installs", Latest: provider.SkillNewest,
					Origin: "acme/skills", Repo: "acme/skills", Entry: "pdf-tools", Path: skillDocDir(t, "pdf-tools"),
					Homepage: "https://www.skills.sh/acme/skills/pdf-tools"},
			},
		},
	}
	ps := []provider.Provider{s.brew, s.npm, s.composer, s.pipx, s.gobin, s.mise, s.skills}
	m := update(t, newModel(ps, ""), tea.WindowSizeMsg{Width: 160, Height: 40})
	for _, p := range ps {
		pkgs, err := p.List(context.Background())
		m = update(t, m, listedMsg{p.Name(), pkgs, err})
	}
	return m, s
}

func searchRail(t *testing.T, m model, name string) model {
	t.Helper()
	for i, r := range m.railRows() {
		if r.name == name {
			m.rail, m.railKey = i, r.key
			m.cursor, m.offset = 0, 0
			return m
		}
	}
	t.Fatalf("no rail row named %q", name)
	return m
}

func typeQuery(t *testing.T, m model, query string) model {
	t.Helper()
	for _, r := range query {
		m = press(t, m, string(r))
	}
	return m
}

func runSearch(t *testing.T, m model, rail, query string) model {
	t.Helper()
	m = searchRail(t, m, rail)
	m = press(t, m, "n")
	m = typeQuery(t, m, query)
	return press(t, m, "enter")
}

func openCandidate(t *testing.T, m model, rail, query string, down int) model {
	t.Helper()
	m = runSearch(t, m, rail, query)
	for range down {
		m = press(t, m, "j")
	}
	return press(t, m, "enter")
}

func footerLine(m model) string {
	lines := strings.Split(screen(m), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func searchRowsNames(m model) []string {
	var out []string
	for _, p := range m.searchRows() {
		out = append(out, p.Name)
	}
	return out
}

func TestFilterBarStates(t *testing.T) {
	tests := []struct {
		id    string
		keys  []string
		shows []string
		lacks []string
	}{
		{id: "no match while a security check runs still says so",
			keys:  []string{"/", "z", "z", "q"},
			shows: []string{`no installed match for "zzq"`, "deps hidden · 0 of 3"}},
		{id: "an empty filter says what to type", keys: []string{"/"},
			shows: []string{"⌕ filter ▏part of a name", "deps hidden · 3 "}},
		{id: "typing counts what is left of the whole", keys: []string{"/", "a", "n"},
			shows: []string{"⌕ filter an▏", "deps hidden · 1 of 3"}, lacks: []string{"part of a name", "esc clears"}},
		{id: "a kept filter says how to drop it", keys: []string{"/", "a", "n", "enter"},
			shows: []string{"⌕ filter an  esc clears", "deps hidden · 1 of 3"}},
		{id: "esc drops it and the hint", keys: []string{"/", "a", "n", "enter", "esc"},
			shows: []string{"deps hidden · 3 "}, lacks: []string{"esc clears", " of 3"}},
		{id: "a long kept filter keeps its text over the hint",
			keys:  append(append([]string{"/"}, strings.Split("abcdefghijklmnop", "")...), "enter"),
			shows: []string{"abcdefghijklmnop"}, lacks: []string{"esc clears"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, _ := searchable(t)
			m = searchRail(t, m, "brew")
			m.busy["npm"] = "checking"
			sc := screen(press(t, m, tt.keys...))
			for _, want := range tt.shows {
				if !strings.Contains(sc, want) {
					t.Errorf("screen lacks %q:\n%s", want, sc)
				}
			}
			for _, want := range tt.lacks {
				if strings.Contains(sc, want) {
					t.Errorf("screen has %q", want)
				}
			}
		})
	}
}

func TestSearchPromptIsQuiet(t *testing.T) {
	tests := []struct {
		id        string
		rail      string
		query     string
		keys      []string
		nilSearch bool
		prompt    bool
		searches  int
		finds     int
		notice    string
		shows     []string
		lacks     []string
	}{
		{id: "n opens the prompt and reads nothing at all", rail: "brew", prompt: true,
			shows: []string{"⌕ search ▏a name or keyword", "type a name  enter search  esc cancel", "anvil"}},
		{id: "every manager's prompt says only search", rail: "pipx", prompt: true,
			shows: []string{"⌕ search"}, lacks: []string{"add to pipx"}},
		{id: "go says only search too", rail: "go", prompt: true,
			shows: []string{"⌕ search"}, lacks: []string{"module by path"}},
		{id: "the All row says only search", rail: "All", prompt: true,
			shows: []string{"⌕ search"}, lacks: []string{"every package manager for"}},
		{id: "typing is a draft and still reads nothing", rail: "brew", query: "yq", prompt: true,
			searches: 0, shows: []string{"⌕ search yq▏"}, lacks: []string{"a name or keyword"}},
		{id: "esc cancels the prompt", rail: "brew", query: "yq", keys: []string{"esc"}, nilSearch: true, shows: []string{"anvil"}},
		{id: "enter with nothing typed does nothing", rail: "brew", keys: []string{"enter"}, prompt: true,
			notice: "type a name to search", shows: []string{"type a name to search"}},
		{id: "enter with one character does nothing", rail: "brew", query: "y", keys: []string{"enter"}, prompt: true,
			notice: "type one more character", shows: []string{"type one more character"}},
		{id: "mise is deferred and stays on the installed list", rail: "mise", keys: []string{"n"}, nilSearch: true,
			notice: "mise can't search yet"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, s := searchable(t)
			m = searchRail(t, m, tt.rail)
			m = press(t, m, "n")
			m = typeQuery(t, m, tt.query)
			m = press(t, m, tt.keys...)
			if (m.search == nil) != tt.nilSearch {
				t.Fatalf("search %v, want gone %v", m.search, tt.nilSearch)
			}
			if tt.prompt && !m.inPrompt() {
				t.Fatalf("not in the prompt")
			}
			if got := s.brew.searches + s.npm.searches + s.composer.searches; got != tt.searches {
				t.Errorf("ran %d searches, want %d", got, tt.searches)
			}
			if got := s.pipx.finds + s.gobin.finds; got != tt.finds {
				t.Errorf("ran %d lookups, want %d", got, tt.finds)
			}
			if tt.notice != "" && m.notice != tt.notice {
				t.Errorf("notice %q, want %q", m.notice, tt.notice)
			}
			if tt.nilSearch && m.notice != "" && tt.notice == "" {
				t.Errorf("notice %q, want the prompt's state only", m.notice)
			}
			sc := screen(m)
			for _, want := range tt.shows {
				if !strings.Contains(sc, want) {
					t.Errorf("screen lacks %q:\n%s", want, sc)
				}
			}
			for _, want := range tt.lacks {
				if strings.Contains(sc, want) {
					t.Errorf("screen has %q", want)
				}
			}
		})
	}
}

func TestSearchRuns(t *testing.T) {
	tests := []struct {
		id            string
		rail          string
		query         string
		setup         func(*searchStack)
		names         []string
		brew, npm     int
		composer      int
		finds         int
		shows         []string
		lacks         []string
		onlyInstalled bool
	}{
		{id: "a manager's row searches its own registry", rail: "brew", query: "yq", names: []string{"yq"}, brew: 1,
			shows: []string{"brew · search · 1 result", "1 result · brew", "LATEST", "STATUS", "· not installed"}},
		{id: "All searches every keyword source", rail: "All", query: "yaml",
			names: []string{"yq", "yaml", "yaml-lint"}, brew: 1, npm: 1, composer: 1,
			shows: []string{"3 results", "3 results · every package manager"}},
		{id: "an installed hit keeps its status and version", rail: "brew", query: "anvil", names: []string{"anvil"}, brew: 1,
			shows: []string{"↑ newer 0.2.89"}},
		{id: "a tap's formula found as tap/name is the installed one", rail: "brew", query: "forge", names: []string{"forge"}, brew: 1,
			lacks: []string{"· not installed"}},
		{id: "a cask in the brew panel carries its source tag", rail: "brew", query: "focus", names: []string{"focus"}, brew: 1,
			shows: []string{"cask/focus"}},
		{id: "an exact-name manager resolves a name", rail: "go", query: "wren", finds: 1, names: []string{"wren"},
			shows: []string{"v1.2.0", "· not installed", "go · search · 1 result"}},
		{id: "an unknown exact name is a no match, not a failed source", rail: "go", query: "zzzz", finds: 1,
			shows: []string{`no package named "zzzz" on the Go proxy`}},
		{id: "an empty answer reads as no match", rail: "npm", query: "zzzz", npm: 1,
			shows: []string{`no packages match "zzzz"`, "searched npm in 0.0s"}},
		{id: "All names the exact-name managers under no match", rail: "All", query: "zzzz", brew: 1, npm: 1, composer: 1,
			shows: []string{`no packages match "zzzz"`, "searched brew, npm, composer, skills in 0.0s", "pipx and go install by exact name only"}},
		{id: "one source returns at most twenty rows", rail: "npm", query: "bulk", npm: 1,
			setup: func(s *searchStack) {
				var bulk []provider.Package
				for i := range 25 {
					bulk = append(bulk, provider.Package{Source: "npm", Name: "tool" + string(rune('a'+i))})
				}
				s.npm.bulk = bulk
			}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, s := searchable(t)
			if tt.setup != nil {
				tt.setup(s)
			}
			m = runSearch(t, m, tt.rail, tt.query)
			if m.search == nil || !m.inResults() {
				t.Fatalf("not in results")
			}
			if got := s.brew.searches; got != tt.brew {
				t.Errorf("brew searched %d times, want %d", got, tt.brew)
			}
			if got := s.npm.searches; got != tt.npm {
				t.Errorf("npm searched %d times, want %d", got, tt.npm)
			}
			if got := s.composer.searches; got != tt.composer {
				t.Errorf("composer searched %d times, want %d", got, tt.composer)
			}
			if got := s.pipx.finds + s.gobin.finds; got != tt.finds {
				t.Errorf("looked up %d names, want %d", got, tt.finds)
			}
			if tt.names != nil && !slices.Equal(searchRowsNames(m), tt.names) {
				t.Errorf("rows %v, want %v", searchRowsNames(m), tt.names)
			}
			if tt.id == "one source returns at most twenty rows" && len(m.searchRows()) != searchLimit {
				t.Errorf("%d rows, want the cap of %d", len(m.searchRows()), searchLimit)
			}
			sc := screen(m)
			for _, want := range tt.shows {
				if !strings.Contains(sc, want) {
					t.Errorf("screen lacks %q:\n%s", want, sc)
				}
			}
			for _, want := range tt.lacks {
				if strings.Contains(sc, want) {
					t.Errorf("screen has %q", want)
				}
			}
		})
	}
}

func TestSearchFindFailureStaysOnTheRow(t *testing.T) {
	m, s := searchable(t)
	s.composer.findErr = errors.New("rate limited")
	m = openCandidate(t, m, "composer", "yaml", 0)
	if len(m.search.errs) != 0 {
		t.Errorf("errs %v, want the manager's search untouched", m.search.errs)
	}
	if got := ansi.Strip(m.searchStatusBar()); strings.Contains(got, "⚠ composer") {
		t.Errorf("status bar marks composer failed: %q", got)
	}
	if !strings.Contains(screen(m), "no newest version for yaml-lint: rate limited") {
		t.Errorf("screen does not say the lookup failed:\n%s", screen(m))
	}
}

func TestSearchFailures(t *testing.T) {
	down := errors.New("rate limited")
	tests := []struct {
		id    string
		rail  string
		query string
		setup func(*searchStack)
		shows []string
	}{
		{id: "a failed source keeps the others' rows and is named on the status bar", rail: "All", query: "yaml",
			setup: func(s *searchStack) { s.npm.err = down },
			shows: []string{"⚠ npm: rate limited", "yq"}},
		{id: "a lone source failing is the total failure state", rail: "npm", query: "yaml",
			setup: func(s *searchStack) { s.npm.err = down },
			shows: []string{"⚠ npm: rate limited", "could not search any package manager", "npm: rate limited"}},
		{id: "with no rows the body lists the failure in red", rail: "All", query: "zzzz",
			setup: func(s *searchStack) { s.composer.err = down },
			shows: []string{`no packages match "zzzz"`, "composer: rate limited"}},
		{id: "every source failing says so", rail: "All", query: "yaml",
			setup: func(s *searchStack) { s.brew.err, s.npm.err, s.composer.err, s.skills.err = down, down, down, down },
			shows: []string{"could not search any package manager", "brew: rate limited", "npm: rate limited", "composer: rate limited", "skills: rate limited"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, s := searchable(t)
			tt.setup(s)
			m = runSearch(t, m, tt.rail, tt.query)
			sc := screen(m)
			for _, want := range tt.shows {
				if !strings.Contains(sc, want) {
					t.Errorf("screen lacks %q:\n%s", want, sc)
				}
			}
		})
	}
}

func TestSearchInfoReadsNothingUntilEnter(t *testing.T) {
	m, s := searchable(t)
	m = runSearch(t, m, "All", "yaml")
	versions := len(m.versions)
	for range 3 {
		m = press(t, m, "j")
	}
	if s.composer.finds != 0 || s.brew.finds != 0 {
		t.Errorf("moving read %d+%d versions, want none", s.composer.finds, s.brew.finds)
	}
	if len(m.versions) != versions {
		t.Errorf("moving loaded versions: %d, want %d", len(m.versions), versions)
	}
	// yaml-lint is the composer row: its search gave no newest version, so
	// enter resolves it before the sidebar reads anything else.
	m = press(t, m, "j", "enter")
	if s.composer.finds != 1 {
		t.Errorf("composer looked up %d times, want once", s.composer.finds)
	}
	sc := screen(m)
	for _, want := range []string{"yaml-lint", "latest    1.4.0", "runs      composer global require yaml-lint:1.4.0"} {
		if !strings.Contains(sc, want) {
			t.Errorf("screen lacks %q:\n%s", want, sc)
		}
	}
}

func TestSearchDropsStaleAnswers(t *testing.T) {
	m, _ := searchable(t)
	m = runSearch(t, m, "brew", "yq")
	gen := m.search.gen
	m = press(t, m, "/", "enter")
	m = update(t, m, searchMsg{gen: gen, manager: "brew", pkgs: []provider.Package{{Source: "brew", Name: "stale"}}})
	if got := searchRowsNames(m); slices.Contains(got, "stale") {
		t.Errorf("a stale answer landed: %v", got)
	}
}

func TestCandidateSidebar(t *testing.T) {
	yamlish := vuln.Advisory{ID: "GHSA-yaml", Summary: "YAML parser loops", Severity: "HIGH", Package: "yaml",
		Details: "A crafted doc loops.", Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "2.9.0"}}}
	tests := []struct {
		id    string
		rail  string
		query string
		down  int
		setup func()
		keys  []string
		shows []string
		lacks []string
		tabs  []int
	}{
		{id: "Info shows what a candidate is and what would run", rail: "brew", query: "yq", shows: []string{
			"🍺 yq · brew", "about     A lightweight and portable YAML", "latest    0.2.94", "status    not installed",
			"✓ no known advisories in 0.2.94", "from      homebrew/core", "home      https://yq.example",
			"repo      github.com/example/yq", "runs      brew install --formula yq"},
			lacks: []string{"🔗 Dependencies"}, tabs: []int{tabInfo, tabVersions, tabSecurity}},
		{id: "a name installed another way says so", rail: "brew", query: "focus",
			shows: []string{"status    installed as brew/focus 1.1.1"}},
		{id: "Versions lists the releases to choose from", rail: "npm", query: "yaml", keys: []string{"v"},
			shows: []string{"VERSION", "DATE", "SECURITY", "2.8.1", "2.7.0"}},
		{id: "a formula lists its source releases and says Homebrew installs only one",
			rail: "brew", query: "yq", keys: []string{"v"},
			shows: []string{"0.2.94", "0.2.89", "Homebrew installs only"}},
		{id: "Security lists what affects the newest version", rail: "npm", query: "yaml", keys: []string{"a"},
			setup: func() {
				fetchHistory = func(_ context.Context, _, name string) ([]vuln.Advisory, error) {
					if name == "yaml" {
						return []vuln.Advisory{yamlish}, nil
					}
					return nil, nil
				}
			},
			shows: []string{"HIGH", "GHSA-yaml", "≥ 2.9.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, _ := searchable(t)
			if tt.setup != nil {
				tt.setup()
			}
			m = openCandidate(t, m, tt.rail, tt.query, tt.down)
			p, ok := m.current()
			if !ok || !m.isCandidate(p) {
				t.Fatalf("current %+v is not a candidate", p)
			}
			m = press(t, m, tt.keys...)
			sc := screen(m)
			for _, want := range tt.shows {
				if !strings.Contains(sc, want) {
					t.Errorf("screen lacks %q:\n%s", want, sc)
				}
			}
			for _, want := range tt.lacks {
				if strings.Contains(sc, want) {
					t.Errorf("screen has %q", want)
				}
			}
			if tt.tabs != nil && !slices.Equal(m.tabs(), tt.tabs) {
				t.Errorf("tabs %v, want %v", m.tabs(), tt.tabs)
			}
		})
	}
}

func TestCandidateConfirm(t *testing.T) {
	lint := vuln.Advisory{ID: "GHSA-yaml", Summary: "YAML parser loops", Severity: "HIGH", Package: "yaml",
		Details: "A crafted doc loops.", Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "2.9.0"}}}
	tests := []struct {
		id    string
		rail  string
		query string
		down  int
		keys  []string
		setup func()
		title string
		shows []string
		lacks []string
	}{
		{id: "the newest version of a formula", rail: "brew", query: "yq", keys: []string{"v", "enter"},
			title: "＋ Install yq?", shows: []string{"yq  not installed → 0.2.94", "brew formula · homebrew/core",
				"runs  brew install --formula yq", "y run it   n cancel"}, lacks: []string{"not the newest"}},
		{id: "Homebrew refuses anything but the newest", rail: "brew", query: "yq", keys: []string{"v", "j", "enter"},
			title: "Can't install yq", shows: []string{"Homebrew can only install the newest version, 0.2.94"}, lacks: []string{"y run it"}},
		{id: "an older npm version is allowed, with a nudge", rail: "npm", query: "yaml", keys: []string{"v", "j", "enter"},
			title: "＋ Install yaml?", shows: []string{"not the newest, latest is 2.8.1", "npm global",
				"runs  npm install -g yaml@2.7.0"}},
		{id: "the advisory line is the installed confirm's sentence", rail: "npm", query: "yaml", keys: []string{"v", "j", "enter"},
			setup: func() {
				fetchHistory = func(_ context.Context, _, name string) ([]vuln.Advisory, error) {
					if name == "yaml" {
						return []vuln.Advisory{lint}, nil
					}
					return nil, nil
				}
			},
			title: "＋ Install yaml?", shows: []string{"⚠ 1 known advisory affects 2.7.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, _ := searchable(t)
			if tt.setup != nil {
				tt.setup()
			}
			m = openCandidate(t, m, tt.rail, tt.query, tt.down)
			m = press(t, m, tt.keys...)
			if m.confirm == nil {
				t.Fatalf("no dialog")
			}
			if m.confirm.title != tt.title {
				t.Errorf("dialog %q, want %q", m.confirm.title, tt.title)
			}
			joined := ansi.Strip(strings.Join(m.confirm.lines, "\n"))
			for _, want := range tt.shows {
				if !strings.Contains(joined, want) {
					t.Errorf("dialog lacks %q:\n%s", want, joined)
				}
			}
			for _, want := range tt.lacks {
				if strings.Contains(joined, want) {
					t.Errorf("dialog has %q", want)
				}
			}
		})
	}
}

func TestSearchInstallThenEsc(t *testing.T) {
	m, s := searchable(t)
	installProcess = func(c *exec.Cmd) *exec.Cmd {
		ran = append(ran, strings.Join(c.Args, " "))
		if len(c.Args) >= 4 && c.Args[0] == "npm" {
			if name, version, ok := strings.Cut(c.Args[3], "@"); ok && name == "yaml" {
				s.npm.added = append(s.npm.added, provider.Package{Source: "npm", Name: "yaml", Version: version, Latest: version})
			}
		}
		return exec.Command("sh", "-c", installScript)
	}
	m = openCandidate(t, m, "npm", "yaml", 0)
	m = press(t, m, "v", "enter", "y")
	if !slices.Equal(ran, []string{"npm install -g yaml@2.8.1"}) {
		t.Errorf("ran %v", ran)
	}
	if m.notice != "yaml is now 2.8.1" {
		t.Errorf("notice %q", m.notice)
	}
	if m.search == nil || !m.inResults() {
		t.Fatal("the panel left results")
	}
	// The install popup is still open; enter closes it. The relist the
	// installedMsg queued comes back next, as the program would deliver it.
	m = press(t, m, "enter")
	pkgs, _ := s.npm.List(context.Background())
	m = update(t, m, listedMsg{"npm", pkgs, nil})
	m = update(t, m, checkedMsg{"npm", pkgs, nil})
	if p, _ := m.current(); m.isCandidate(p) || p.Version != "2.8.1" {
		t.Errorf("current %+v is not the installed package", p)
	}
	if sc := screen(m); !strings.Contains(sc, "✓ installed 2.8.1") {
		t.Errorf("row was not patched:\n%s", sc)
	}
	m = press(t, m, "esc")
	if m.search != nil {
		t.Error("esc did not close results")
	}
	p, ok := m.current()
	if !ok || p.Name != "yaml" || p.Version != "2.8.1" {
		t.Errorf("esc selected %+v, want the new install", p)
	}
	if m.curRow().name != "npm" {
		t.Errorf("esc switched the rail to %q", m.curRow().name)
	}
}

func TestSearchModeResets(t *testing.T) {
	tests := []struct {
		id       string
		rail     string
		run      bool
		keys     []string
		msgs     []tea.Msg
		wantRail string
		wantRows []string
	}{
		{id: "esc closes results", rail: "brew", run: true, keys: []string{"esc"}, wantRail: "brew", wantRows: []string{"anvil", "focus", "forge"}},
		{id: "esc cancels the prompt", rail: "brew", keys: []string{"esc"}, wantRail: "brew", wantRows: []string{"anvil", "focus", "forge"}},
		{id: "a rail switch closes results", rail: "brew", run: true, keys: []string{"h", "j"}, wantRail: "npm"},
		{id: "a rail switch cancels the prompt", rail: "brew", keys: []string{"tab", "tab"},
			msgs: []tea.Msg{tea.KeyPressMsg{Code: tea.KeyUp}}, wantRail: "All", wantRows: []string{"anvil", "focus", "forge"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m, s := searchable(t)
			if tt.run {
				m = runSearch(t, m, tt.rail, "yq")
			} else {
				m = searchRail(t, m, tt.rail)
				m = press(t, m, "n")
			}
			m = press(t, m, tt.keys...)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			if m.search != nil {
				t.Errorf("search survived: %+v", m.search)
			}
			if got := m.curRow().name; got != tt.wantRail {
				t.Errorf("rail %q, want %q", got, tt.wantRail)
			}
			if tt.wantRows != nil && !slices.Equal(names(m), tt.wantRows) {
				t.Errorf("installed rows %v, want %v", names(m), tt.wantRows)
			}
			if tt.wantRows == nil && len(names(m)) != 0 {
				t.Errorf("rows %v, want none on the npm panel", names(m))
			}
			if s.brew.searches > 1 {
				t.Errorf("brew searched %d times", s.brew.searches)
			}
		})
	}
}

func TestSearchScopeAndCounts(t *testing.T) {
	m, _ := searchable(t)
	beforePkgs := len(m.allPkgs())
	before := m.count(m.allPkgs())
	m = runSearch(t, m, "All", "yaml")
	if got := len(m.allPkgs()); got != beforePkgs {
		t.Errorf("installed packages %d, want %d", got, beforePkgs)
	}
	if got := m.count(m.allPkgs()); got != before {
		t.Errorf("counts %+v, want %+v", got, before)
	}
	if sc := screen(m); !strings.Contains(sc, "3 results · every package manager") {
		t.Errorf("status bar does not count results:\n%s", sc)
	}
	m = press(t, m, "esc")
	if got := names(m); slices.Contains(got, "yq") {
		t.Errorf("a search result stayed in the installed list: %v", got)
	}
	if got := len(m.allPkgs()); got != beforePkgs {
		t.Errorf("installed packages %d after esc, want %d", got, beforePkgs)
	}
}

func TestSearchCarriesFilter(t *testing.T) {
	m, _ := searchable(t)
	m = searchRail(t, m, "brew")
	m = press(t, m, "/", "f", "o", "enter")
	if m.filter() != "fo" {
		t.Fatalf("filter %q", m.filter())
	}
	m = press(t, m, "n")
	if m.search == nil || m.search.draft != "fo" {
		t.Errorf("draft %q, want the filter", m.search.draft)
	}
	if sc := screen(m); !strings.Contains(sc, "⌕ search fo") {
		t.Errorf("prompt lacks the carried filter:\n%s", sc)
	}
}

func TestSearchNotOnProjectOrImageRows(t *testing.T) {
	m := loaded(t)
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	m.machineImgs = []image.Ref{{Image: "ghcr.io/example/api:1.0"}}
	tests := []struct {
		id   string
		rail string
	}{
		{id: "a docker image row", rail: "docker"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			mm := m
			for i, r := range mm.railRows() {
				if r.name == tt.rail {
					mm.setRail(i)
					break
				}
			}
			mm = press(t, mm, "n")
			if mm.search != nil {
				t.Errorf("n opened a search on %q", tt.rail)
			}
		})
	}
	scan := project.Scan{Root: "/work/app", Projects: []project.Project{{Lockfiles: []project.Lockfile{
		{Path: "package-lock.json", Manager: "npm"},
	}}}}
	with := withProject(t, scan, false)
	for i, r := range with.railRows() {
		if r.kind == rowProject {
			with.setRail(i)
			break
		}
	}
	with = press(t, with, "n")
	if with.search != nil {
		t.Errorf("n opened a search on the project row")
	}
}

func TestSearchSpinnerAndHints(t *testing.T) {
	m, _ := searchable(t)
	m = searchRail(t, m, "brew")
	m = press(t, m, "n")
	m.search = &searchState{mode: modeResults, scope: m.curRow().key, query: "yq",
		asks: []string{"brew"}, answered: map[string]bool{}, busy: true, started: clock}
	if !m.working() {
		t.Error("a search on its way is not counted as work")
	}
	sc := screen(m)
	for _, want := range []string{"searching…", "searching brew…", "0 results · brew"} {
		if !strings.Contains(sc, want) {
			t.Errorf("screen lacks %q:\n%s", want, sc)
		}
	}
	m.search.rows = []provider.Package{{Source: "brew", Name: "yq", Latest: "0.2.94"}}
	if sc := screen(m); !strings.Contains(sc, "yq") {
		t.Errorf("a refinement dropped its rows:\n%s", sc)
	}
}

func TestSearchFootersAndHelp(t *testing.T) {
	m, _ := searchable(t)
	m = searchRail(t, m, "brew")
	m = press(t, m, "n")
	if got := footerLine(m); got != "type a name  enter search  esc cancel" {
		t.Errorf("prompt footer %q", got)
	}
	m = typeQuery(t, m, "yq")
	m = press(t, m, "enter")
	if got := footerLine(m); got != "/ edit  ↑↓ select  enter details  w home  ? help  esc back" {
		t.Errorf("results footer %q", got)
	}
	m = press(t, m, "/")
	if got := footerLine(m); got != "type to search  enter run  esc cancel" {
		t.Errorf("editing footer %q", got)
	}
	m = press(t, m, "esc", "esc")
	m = press(t, m, "?")
	if sc := screen(m); !strings.Contains(sc, "this panel's registry for a package kho doesn't have") {
		t.Errorf("help lacks the n key:\n%s", sc)
	}
}

// Every line must fill the width exactly at the narrow sizes kho supports.
func TestSearchWidths(t *testing.T) {
	m, _ := searchable(t)
	m = searchRail(t, m, "brew")
	m = press(t, m, "n")
	m = typeQuery(t, m, "yq")
	for _, width := range []int{100, 110} {
		m = update(t, m, tea.WindowSizeMsg{Width: width, Height: 30})
		lines := strings.Split(screen(m), "\n")
		if len(lines) != 30 {
			t.Fatalf("at %d wide the prompt screen has %d lines", width, len(lines))
		}
		for i, line := range lines[:len(lines)-1] {
			if got := ansi.StringWidth(line); got != width {
				t.Errorf("at %d wide the prompt line %d is %d: %q", width, i, got, line)
			}
		}
	}
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	for _, width := range []int{100, 110} {
		m = update(t, m, tea.WindowSizeMsg{Width: width, Height: 30})
		lines := strings.Split(screen(m), "\n")
		if len(lines) != 30 {
			t.Fatalf("at %d wide the results screen has %d lines", width, len(lines))
		}
		for i, line := range lines[:len(lines)-1] {
			if got := ansi.StringWidth(line); got != width {
				t.Errorf("at %d wide the results line %d is %d: %q", width, i, got, line)
			}
		}
	}
}

func TestSearchStripsControlCharacters(t *testing.T) {
	m, s := searchable(t)
	s.brew.results = append(s.brew.results, provider.Package{Source: "brew", Name: "evil\x1b[31mname", Latest: "1.0.0\a", Desc: "wraps\x1b[0m badly"})
	m = runSearch(t, m, "brew", "evil")
	if strings.Contains(m.View().Content, "evil\x1b") || strings.Contains(m.View().Content, "\a") {
		t.Error("a result rendered a control character")
	}
	m = press(t, m, "enter")
	if strings.Contains(m.View().Content, "\a") {
		t.Error("the sidebar rendered a control character")
	}
}

func TestSearchFailedInstallKeepsCandidate(t *testing.T) {
	m, _ := searchable(t)
	installScript = "echo no space; exit 3"
	m = openCandidate(t, m, "npm", "yaml", 0)
	m = press(t, m, "v", "enter", "y")
	m = press(t, m, "enter")
	if m.search == nil || !m.inResults() {
		t.Fatal("a failed install left results")
	}
	p, ok := m.current()
	if !ok || !m.isCandidate(p) {
		t.Errorf("current %+v is not the candidate", p)
	}
	if !strings.Contains(m.notice, "yaml 2.8.1 failed") {
		t.Errorf("notice %q", m.notice)
	}
	m = press(t, m, "i")
	if sc := screen(m); !strings.Contains(sc, "· not installed") || !strings.Contains(sc, "runs      npm install -g yaml@2.8.1") {
		t.Errorf("the candidate did not stay:\n%s", sc)
	}
}

func TestSearchRefineReplacesRows(t *testing.T) {
	m, _ := searchable(t)
	m = runSearch(t, m, "brew", "yq")
	if got, want := searchRowsNames(m), []string{"yq"}; !slices.Equal(got, want) {
		t.Fatalf("first search rows %v, want %v", got, want)
	}
	m = press(t, m, "/")
	m = press(t, m, "backspace", "backspace")
	m = typeQuery(t, m, "anvil")
	m = press(t, m, "enter")
	if got, want := searchRowsNames(m), []string{"anvil"}; !slices.Equal(got, want) {
		t.Errorf("refined rows %v, want %v", got, want)
	}
}

func TestSearchWarnsAboutANameInstalledElsewhere(t *testing.T) {
	loaded(t)
	brew := &catalogFake{
		fake:    fake{name: "brew"},
		results: []provider.Package{{Source: "brew", Name: "shared", Latest: "1.0.0", Desc: "A shared tool"}},
	}
	npm := &catalogFake{
		fake: fake{name: "npm", pkgs: []provider.Package{{Source: "npm", Name: "shared", Version: "2.0.0", Latest: "2.0.0"}}},
	}
	m := update(t, newModel([]provider.Provider{brew, npm}, ""), tea.WindowSizeMsg{Width: 160, Height: 40})
	for _, p := range []provider.Provider{brew, npm} {
		pkgs, err := p.List(context.Background())
		m = update(t, m, listedMsg{p.Name(), pkgs, err})
	}
	m = searchRail(t, m, "brew")
	m = press(t, m, "n")
	m = typeQuery(t, m, "shared")
	m = press(t, m, "enter")
	rows := m.searchRows()
	if len(rows) != 1 {
		t.Fatalf("rows %v", searchRowsNames(m))
	}
	q, ok := m.otherInstall(rows[0])
	if !ok || q.Source != "npm" || q.Name != "shared" {
		t.Errorf("otherInstall = %+v, %v", q, ok)
	}
	m.askInstallNew(rows[0], "1.0.0")
	if m.confirm == nil {
		t.Fatal("no confirm")
	}
	if got := strings.Join(ansiLines(m.confirm.lines), "\n"); !strings.Contains(got, "shared is installed as npm/shared 2.0.0") {
		t.Errorf("confirm lacks the warning:\n%s", got)
	}
}

func TestSearchEscapeReturnsFocusToTheTable(t *testing.T) {
	m, _ := searchable(t)
	m = runSearch(t, m, "brew", "yq")
	m = press(t, m, "enter")
	if m.focus != focusSide {
		t.Fatalf("focus %d, want side", m.focus)
	}
	m = press(t, m, "esc")
	if m.search != nil || m.focus != focusTable {
		t.Errorf("search %v focus %d, want nil and the table", m.search, m.focus)
	}
}

func ansiLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = ansi.Strip(l)
	}
	return out
}

func TestSearchShowsItsSpinner(t *testing.T) {
	m, _ := searchable(t)
	m = searchRail(t, m, "brew")
	m.search = &searchState{mode: modeResults, scope: m.curRow().key, busy: true,
		asks: []string{"brew"}, answered: map[string]bool{}, errs: map[string]string{}}
	spin := ansi.Strip(m.spin())
	if got := ansi.Strip(m.searchTitle()); !strings.Contains(got, "searching") || !strings.Contains(got, spin) {
		t.Errorf("title %q lacks the spinner %q", got, spin)
	}
	if got := ansi.Strip(m.searchStatusBar()); !strings.Contains(got, "searching brew") || !strings.Contains(got, spin) {
		t.Errorf("status %q lacks the spinner %q", got, spin)
	}
	m.search.busy, m.search.finding = false, true
	if got := ansi.Strip(m.searchStatusBar()); !strings.Contains(got, "resolving the newest version") {
		t.Errorf("resolving status %q", got)
	}
}

func TestSearchBridgeIsCentered(t *testing.T) {
	m, _ := searchable(t)
	m = searchRail(t, m, "brew")
	// The harness does not drain every provider's latest lookup, so clear the
	// spun-up set and let the empty table draw.
	m.busy = map[string]string{}
	m = press(t, m, "/", "q", "q", "enter")
	raw := screen(m)
	if !strings.Contains(raw, `no installed match for "qq"`) {
		t.Fatalf("no bridge:\n%s", raw)
	}
	if strings.Contains(raw, "n searches the registry") {
		t.Errorf("the old bridge copy survived:\n%s", raw)
	}
	if want := accent().Render("n") + faint().Render(" search for a new package"); !strings.Contains(m.View().Content, want) {
		t.Errorf("n is not lit like a key:\n%s", m.View().Content)
	}
	var line string
	for _, l := range strings.Split(ansi.Strip(raw), "\n") {
		if strings.Contains(l, "no installed match for") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("no bridge line")
	}
	if at := strings.Index(line, "no installed"); at < 8 {
		t.Errorf("the bridge is not centered (text at %d):\n%s", at, line)
	}
}

func TestSearchBarSurvivesALongEmptyState(t *testing.T) {
	m, _ := searchable(t)
	m = update(t, m, tea.WindowSizeMsg{Width: 100, Height: 16})
	m = searchRail(t, m, "All")
	m.busy = map[string]string{}
	errs := map[string]string{}
	var asks []string
	for _, name := range []string{"brew", "npm", "composer", "pipx", "uv", "go", "mise", "skills"} {
		errs[name] = "registry unreachable"
		asks = append(asks, name)
	}
	m.search = &searchState{mode: modeResults, scope: m.curRow().key, query: "zz",
		errs: errs, answered: map[string]bool{}, asks: asks}
	sc := screen(m)
	if !strings.Contains(sc, "could not search any package manager") {
		t.Errorf("the empty state is missing:\n%s", sc)
	}
	if !strings.Contains(sc, "⌕ search zz") {
		t.Errorf("the bar was clipped by the empty state:\n%s", sc)
	}
}

// A blank release would compare equal to the candidate's empty version and
// grow an installed pill.
func TestCandidateVersionsDoNotLookInstalled(t *testing.T) {
	m, _ := searchable(t)
	m = openCandidate(t, m, "brew", "yq", 0)
	p, ok := m.current()
	if !ok || p.Version != "" {
		t.Fatalf("current %+v is not a candidate", p)
	}
	m.versions[cacheKey(p)] = &lazy[[]provider.Release]{done: true,
		val: []provider.Release{{Version: "0.2.94"}, {Version: ""}}}
	raw := m.View().Content
	if strings.Contains(raw, pill("installed", th.green)) {
		t.Errorf("a candidate version looks installed:\n%s", ansi.Strip(raw))
	}
	if !strings.Contains(ansi.Strip(raw), "0.2.94") {
		t.Errorf("the real version is missing:\n%s", ansi.Strip(raw))
	}
}

func TestCandidateVersionsLoadOnVWithoutEnter(t *testing.T) {
	m, _ := searchable(t)
	m = runSearch(t, m, "brew", "yq")
	m = press(t, m, "v")
	sc := screen(m)
	if strings.Contains(sc, "loading versions") {
		t.Errorf("versions kept loading:\n%s", sc)
	}
	if strings.Contains(sc, "press enter to load versions") {
		t.Errorf("pressing v did not open the row:\n%s", sc)
	}
	if !strings.Contains(sc, "0.2.94") {
		t.Errorf("the versions list did not arrive:\n%s", sc)
	}
}

func TestCandidateVersionsLoadWhenTabShows(t *testing.T) {
	m, _ := searchable(t)
	m = runSearch(t, m, "All", "yaml")
	m = press(t, m, "v")
	if sc := screen(m); !strings.Contains(sc, "0.2.94") {
		t.Errorf("the first row's versions did not load on the Versions tab:\n%s", sc)
	}
	m = press(t, m, "j")
	sc := screen(m)
	if strings.Contains(sc, "loading versions") {
		t.Errorf("moving on Versions left it loading:\n%s", sc)
	}
	if !strings.Contains(sc, "2.8.1") {
		t.Errorf("the next row's versions did not load:\n%s", sc)
	}
}

func skillDocDir(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"),
		[]byte("---\nname: "+name+"\n---\n# "+name+"\nUse it for documents.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The skills CLI has no version to pick: it always takes the newest commit.
func TestSkillsSearchAndInstall(t *testing.T) {
	m, _ := searchable(t)
	m = runSearch(t, m, "skills", "pdf")
	sc := screen(m)
	if !strings.Contains(sc, "skills/pdf") {
		t.Fatalf("the skill did not come back:\n%s", sc)
	}
	for _, want := range []string{"FROM", "acme/skills", "Use it for documents."} {
		if !strings.Contains(sc, want) {
			t.Fatalf("skills results lack %q:\n%s", want, sc)
		}
	}
	m = press(t, m, "enter")
	sc = screen(m)
	if !strings.Contains(sc, "Use it for documents.") {
		t.Fatalf("the candidate's SKILL.md is missing from Info:\n%s", sc)
	}
	flat := strings.Join(strings.Fields(strings.ReplaceAll(sc, "│", "")), " ")
	if !strings.Contains(flat, "npx -y skills add acme/skills --skill pdf -g -y --json") {
		t.Fatalf("the skill's command is missing; flat:\n%s", flat)
	}
	if footer := footerLine(m); !strings.Contains(footer, "enter install it") {
		t.Errorf("footer %q does not offer the install", footer)
	}
	m = press(t, m, "enter")
	sc = screen(m)
	flat = strings.Join(strings.Fields(strings.ReplaceAll(sc, "│", "")), " ")
	for _, want := range []string{"＋ Install pdf?", "installs the newest commit from acme/skills",
		"runs npx -y skills add acme/skills --skill pdf -g -y --json"} {
		if !strings.Contains(flat, want) && !strings.Contains(sc, want) {
			t.Errorf("confirm lacks %q:\n%s", want, sc)
		}
	}
}

func TestSkillDocDebounceDropsAStaleSelection(t *testing.T) {
	m, _ := searchable(t)
	var ticks []func(time.Time) tea.Msg
	old := settleTick
	t.Cleanup(func() { settleTick = old })
	settleTick = func(_ time.Duration, fn func(time.Time) tea.Msg) tea.Cmd {
		ticks = append(ticks, fn)
		return nil
	}
	m = runSearch(t, m, "skills", "pdf")
	if len(ticks) != 1 {
		t.Fatalf("first selection scheduled %d reads, want 1", len(ticks))
	}
	if sc := screen(m); strings.Contains(sc, "press enter to read SKILL.md") || !strings.Contains(sc, "loading SKILL.md") {
		t.Errorf("the waiting pane is wrong:\n%s", sc)
	}
	first, _ := m.current()
	firstKey := cacheKey(first)
	m = press(t, m, "j")
	second, _ := m.current()
	secondKey := cacheKey(second)
	if len(ticks) != 2 {
		t.Fatalf("second selection scheduled %d reads, want 2", len(ticks))
	}
	m = update(t, m, ticks[0](clock))
	if m.docs[firstKey] != nil {
		t.Error("the stale selection's SKILL.md was read")
	}
	m = update(t, m, ticks[1](clock))
	if m.docs[secondKey] == nil {
		t.Error("the selected skill's SKILL.md was not read")
	}
}

func TestSkillResultColumnsRebalance(t *testing.T) {
	m, _ := searchable(t)
	m = runSearch(t, m, "skills", "pdf")
	widths := func() map[int]int {
		out := map[int]int{}
		for _, c := range m.resultColumns() {
			out[c.id] = c.width
		}
		return out
	}
	w := widths()
	if w[colName] > 20 || w[colSource] <= w[colName] || w[colStatus] < 14 {
		t.Errorf("wide columns %v, want the repo wider than the capped name", w)
	}
	total := w[colName] + w[colSource] + w[colStatus] + 2
	if table := m.layout().tableW - 2; total > table {
		t.Errorf("columns take %d, want at most %d", total, table)
	}
	m = update(t, m, tea.WindowSizeMsg{Width: 100, Height: 20})
	w = widths()
	if w[colName] < 8 || w[colSource] < 10 || w[colStatus] < 14 {
		t.Errorf("narrow columns %v are too small", w)
	}
	if total := w[colName] + w[colSource] + w[colStatus] + 2; total > m.layout().tableW-2 {
		t.Errorf("narrow columns take %d, want at most %d", total, m.layout().tableW-2)
	}
}

func TestBrewCandidateScan(t *testing.T) {
	m, s := searchable(t)
	s.brew.versions["yq"] = []provider.Release{{Version: "v0.2.95"}, {Version: "v0.2.94"}}
	adv := vuln.Advisory{ID: "CVE-0000-0020", Severity: "HIGH", Summary: "yq reads past the file", Package: "yq",
		Versions: []string{"0.2.94"}, Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "0.2.95"}}}
	var asked []string
	scanFormula = func(_ context.Context, name string) (vuln.BrewResult, error) {
		asked = append(asked, name)
		return vuln.BrewResult{Checked: 1, Complete: true, Findings: []vuln.BrewFinding{{Formula: name, Version: "0.2.94", Advisories: []vuln.Advisory{adv}}}}, nil
	}
	m = openCandidate(t, m, "brew", "yq", 0)
	if !slices.Equal(asked, []string{"yq"}) {
		t.Errorf("asked Homebrew about %v, want yq once", asked)
	}
	tests := []struct {
		id    string
		key   string
		shows []string
	}{
		{"Info counts what affects the version brew would install", "i", []string{"⚠ 1 known advisory affects 0.2.94"}},
		{"Security names the release that fixes it", "a", []string{"CVE-0000-0020", "≥ 0.2.95"}},
		{"Versions marks the affected release", "v", []string{"v0.2.95", "v0.2.94", "⚠ 1"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			sc := screen(press(t, m, tt.key))
			for _, want := range tt.shows {
				if !strings.Contains(sc, want) {
					t.Errorf("screen lacks %q:\n%s", want, sc)
				}
			}
		})
	}
}

func TestBrewCandidateScanWaitsForTheCursorToSettle(t *testing.T) {
	m, s := searchable(t)
	s.brew.results = append(s.brew.results, provider.Package{Source: "brew", Name: "yqq", Latest: "1.0.0"})
	var ticks []func(time.Time) tea.Msg
	settleTick = func(_ time.Duration, fn func(time.Time) tea.Msg) tea.Cmd {
		ticks = append(ticks, fn)
		return nil
	}
	var asked []string
	scanFormula = func(_ context.Context, name string) (vuln.BrewResult, error) {
		asked = append(asked, name)
		return vuln.BrewResult{Checked: 1, Complete: true}, nil
	}
	m = runSearch(t, m, "brew", "yq")
	m = press(t, m, "j")
	if len(ticks) != 2 {
		t.Fatalf("scheduled %d scans, want one per selection", len(ticks))
	}
	m = update(t, m, ticks[0](clock))
	m = update(t, m, ticks[1](clock))
	if !slices.Equal(asked, []string{"yqq"}) {
		t.Errorf("asked Homebrew about %v, want only the row the cursor stayed on", asked)
	}
}

func TestBrewVersionsWithASpannedFinding(t *testing.T) {
	old := brewScanResult
	t.Cleanup(func() { brewScanResult = old })
	brewScanResult = vuln.BrewResult{Checked: 3, Complete: true, Findings: []vuln.BrewFinding{{Formula: "anvil", Version: "0.2.89",
		Advisories: []vuln.Advisory{{ID: "CVE-0000-0021", Severity: "HIGH", Package: "anvil", Versions: []string{"0.2.89"},
			Ranges: []vuln.Range{{Introduced: "0.2.0"}, {LastAffected: "0.2.89"}}}}}}}
	m, s := searchable(t)
	s.brew.versions["anvil"] = []provider.Release{{Version: "anvil-0.2.94"}, {Version: "anvil-0.2.89"}}
	m = searchRail(t, m, "brew")
	sc := screen(press(t, m, "v"))
	for _, want := range []string{"anvil-0.2.94", "✓ safe", "anvil-0.2.89", "⚠ 1", "installed"} {
		if !strings.Contains(sc, want) {
			t.Errorf("screen lacks %q:\n%s", want, sc)
		}
	}
	if sc := screen(press(t, m, "a")); !strings.Contains(sc, "> 0.2.89") {
		t.Errorf("Security does not say what follows the span:\n%s", sc)
	}
}
