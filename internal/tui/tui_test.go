package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/color"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/project"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

type fake struct {
	name     string
	pkgs     []provider.Package
	err      error
	versions map[string][]provider.Release
}

func (f fake) Name() string                                     { return f.name }
func (f fake) Missing() string                                  { return "" }
func (f fake) List(context.Context) ([]provider.Package, error) { return f.pkgs, f.err }
func (f fake) Latest(_ context.Context, p []provider.Package) ([]provider.Package, error) {
	return p, nil
}
func (f fake) Deps(_ context.Context, p provider.Package) ([]provider.Dep, error) { return p.Deps, nil }

// Versions lists the releases given for the package, or else only its
// newest, as Homebrew does for a formula with no repo.
func (f fake) Versions(_ context.Context, p provider.Package) ([]provider.Release, error) {
	if rels, ok := f.versions[p.Name]; ok {
		return rels, nil
	}
	return []provider.Release{{Version: p.Latest}}, nil
}

var clock = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

var redos = vuln.Advisory{ID: "GHSA-test", Aliases: []string{"CVE-0000-00001"}, Summary: "Bramble vulnerable to ReDoS", Severity: "MODERATE",
	Package: "bramble", Details: "A regular expression can take a long time.", Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "24.3.0"}}}

func fakes(t *testing.T) []provider.Provider {
	skill := t.TempDir()
	os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: pathmaker\ndescription: Plan big work\n---\n# Pathmaker\nSplit the work into tickets.\n"), 0o644)
	os.WriteFile(filepath.Join(skill, "README.md"), []byte("# Read me first\nHow to use it.\n"), 0o644)
	// The skill is listed from a home's ~/.agents/skills through a link, so
	// its path and the folder its files live in differ on every system, not
	// only where TMPDIR is a link.
	path := filepath.Join(t.TempDir(), ".agents", "skills", "pathmaker")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.Symlink(skill, path)
	return []provider.Provider{
		fake{name: "brew", pkgs: []provider.Package{
			{Source: "brew", Name: "anvil", Version: "0.2.89", Latest: "0.2.94", Outdated: true, Homepage: "https://anvil.example", Repo: "example/anvil",
				Desc: "Run your build jobs locally, a description long enough that it has to wrap at the very end",
				Deps: []provider.Dep{{Name: "openssl@4", Version: "4.1.0", Direct: true}, {Name: "ca-certificates", Version: "2026-10-20"}}},
			{Source: "brew", Name: "cobalt", Version: "1.18.4", Latest: "1.18.6", Outdated: true, Dependency: true},
			{Source: "brew", Name: "gust", Version: "1.27.1", Latest: "1.27.2", Outdated: true, Pinned: true},
		}, versions: map[string][]provider.Release{"anvil": {
			{Version: "v0.2.94", Notes: "Fixes the thing. See [the full list of changes in this release](https://example.com/anvil/releases/v0.2.94/changes-in-detail).", URL: "https://github.com/example/anvil/releases/tag/v0.2.94"},
			{Version: "v0.2.89", URL: "https://github.com/example/anvil/releases/tag/v0.2.89"},
			{Version: "v0.2.1"},
		}}},
		fake{name: "pipx", pkgs: []provider.Package{
			{Source: "pipx", Name: "bramble", Version: "22.12.0", Latest: "26.10.1", Outdated: true},
			{Source: "pipx", Name: "inkwell", Version: "9.0.2", Latest: "9.0.2"},
		}, versions: map[string][]provider.Release{"bramble": {
			{Version: "26.10.1", Notes: "Big release"}, {Version: "24.3.0"}, {Version: "22.12.0"}, {Version: "21.12.0"},
		}}},
		fake{name: "mise", err: errors.New("mise ls: boom")},
		fake{name: "skills", pkgs: []provider.Package{
			{Source: "skills", Name: "pathmaker", Version: "32b0ce9", Repo: "someone/skills", Path: path, Agents: []string{"claude", "pi"}},
		}},
	}
}

// update applies a message, then runs the commands it returns the way the
// program would, for the messages the model makes for itself.
func update(t *testing.T, m model, msg tea.Msg) model {
	tm, cmd := m.Update(msg)
	var drain func(tea.Cmd)
	drain = func(cmd tea.Cmd) {
		if cmd == nil {
			return
		}
		switch msg := cmd().(type) {
		case tea.BatchMsg:
			for _, c := range msg {
				drain(c)
			}
		case depsMsg, versionsMsg, docMsg, openedMsg, scanMsg, historyMsg, auditMsg, installStartedMsg, outputMsg, installedMsg, linkedMsg, projectMsg, projectLatestMsg, imagesMsg, imageFactMsg, imageFactsDoneMsg, imageScanMsg, imageTagsMsg, imageRemoveMsg, imageUsersMsg:
			tm, cmd = tm.Update(msg)
			drain(cmd)
		}
	}
	drain(cmd)
	return tm.(model)
}

var opened, ran, copied, toggled []string

// installScript stands in for the package manager an install runs, and
// reran is the command t last ran in the terminal.
var (
	installScript string
	reran         *exec.Cmd
)

// linkReads counts the times kho read a skill's links, and appeared puts a
// newly installed agent first in what it reads next.
var (
	linkReads int
	appeared  bool
)

func loaded(t *testing.T) model {
	th = themes[0]
	opened, ran, copied, toggled = nil, nil, nil, nil
	linkReads, appeared = 0, false
	installScript, reran = "echo fetched", nil
	live.Lock()
	live.in, live.leaving = nil, false
	live.Unlock()
	installProcess = func(c *exec.Cmd) *exec.Cmd {
		ran = append(ran, strings.Join(c.Args, " "))
		return exec.Command("sh", "-c", installScript)
	}
	runExec = func(c tea.ExecCommand, fn tea.ExecCallback) tea.Cmd {
		return func() tea.Msg {
			reran = c.(*terminalRun).cmd
			ran = append(ran, strings.Join(reran.Args, " "))
			return fn(nil)
		}
	}
	copyText = func(s string) tea.Cmd { copied = append(copied, s); return nil }
	skillLinks = func(_ provider.Package, all bool) []provider.SkillLink {
		links := []provider.SkillLink{
			{Agent: "claude", Path: "/h/.claude/skills/pathmaker", Kind: provider.LinkSymlink, Target: "/h/.agents/skills/pathmaker", Own: true, Installed: true},
			{Agent: "cursor", Path: "/h/.cursor/skills/pathmaker", Kind: provider.LinkMissing, Installed: true},
			{Agent: "codex", Path: "/h/.agents/skills/pathmaker", Kind: provider.LinkNoFolder, Shared: true, Installed: true},
		}
		if all {
			links = append(links, provider.SkillLink{Agent: "goose", Display: "Goose", Path: "/h/.config/goose/skills/pathmaker", Kind: provider.LinkMissing},
				provider.SkillLink{Agent: "cline", Display: "Cline", Path: "/h/.agents/skills/pathmaker", Kind: provider.LinkNoFolder, Shared: true})
		}
		if appeared {
			links = append([]provider.SkillLink{{Agent: "amp", Path: "/h/.config/agents/skills/pathmaker", Kind: provider.LinkMissing, Installed: true}}, links...)
		}
		linkReads++
		return links
	}
	linkSkill = func(l provider.SkillLink, _ provider.Package) error {
		toggled = append(toggled, "link "+l.Agent)
		return nil
	}
	unlinkSkill = func(l provider.SkillLink) error { toggled = append(toggled, "unlink "+l.Agent); return nil }
	now = func() time.Time { return clock }
	openURL = func(url string) error { opened = append(opened, url); return nil }
	scanOSV = func(_ context.Context, qs []vuln.Query, _ map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
		hits := map[string][]string{}
		for _, q := range qs {
			hits[q.Key()] = nil
			if q.Name == "bramble" {
				hits[q.Key()] = []string{redos.ID}
			}
		}
		return hits, map[string]vuln.Advisory{redos.ID: redos}, nil
	}
	fetchHistory = func(_ context.Context, _, name string) ([]vuln.Advisory, error) {
		if name == "bramble" {
			return []vuln.Advisory{redos}, nil
		}
		return nil, nil
	}
	fetchAudits = func(_ context.Context, bySource map[string][]string) (map[string]vuln.SkillAudit, error) {
		return map[string]vuln.SkillAudit{"someone/skills/pathmaker": {Gen: "safe", Socket: "safe", Snyk: "medium"}}, nil
	}
	ps := fakes(t)
	m := update(t, newModel(ps, ""), tea.WindowSizeMsg{Width: 160, Height: 40})
	for _, p := range ps {
		pkgs, err := p.List(context.Background())
		m = update(t, m, listedMsg{p.Name(), pkgs, err})
		if err == nil {
			m = update(t, m, checkedMsg{p.Name(), pkgs, nil})
		}
	}
	return m
}

func press(t *testing.T, m model, keys ...string) model {
	codes := map[string]rune{"tab": tea.KeyTab, "enter": tea.KeyEnter, "esc": tea.KeyEscape, "left": tea.KeyLeft, "right": tea.KeyRight}
	for _, k := range keys {
		var msg tea.Msg = tea.KeyPressMsg{Code: rune(k[0]), Text: k}
		if code, ok := codes[k]; ok {
			msg = tea.KeyPressMsg{Code: code}
		}
		if k == "paste:bl" {
			msg = tea.PasteMsg{Content: "bl\n"}
		}
		m = update(t, m, msg)
	}
	return m
}

func names(m model) []string {
	var out []string
	for _, p := range m.rows() {
		out = append(out, p.Name)
	}
	return out
}

func screen(m model) string {
	return ansi.Strip(m.View().Content)
}

func TestKeys(t *testing.T) {
	tests := []struct {
		id   string
		keys []string
		want []string
	}{
		{"all sources, deps hidden", nil, []string{"anvil", "gust", "bramble", "inkwell", "pathmaker"}},
		{"k on the first row stays put", []string{"k", "k"}, []string{"anvil", "gust", "bramble", "inkwell", "pathmaker"}},
		{"! keeps the vulnerable ones", []string{"!"}, []string{"bramble"}},
		{"o keeps outdated only", []string{"o"}, []string{"anvil", "gust", "bramble"}},
		{"h then j picks the first source", []string{"h", "j"}, []string{"anvil", "gust"}},
		{"j again picks the next source", []string{"h", "j", "j"}, []string{"bramble", "inkwell"}},
		{"d shows dependencies", []string{"d"}, []string{"anvil", "cobalt", "gust", "bramble", "inkwell", "pathmaker"}},
		{"s sorts by version, naturally", []string{"s"}, []string{"anvil", "gust", "inkwell", "bramble", "pathmaker"}},
		{"status sort puts vulnerabilities first", []string{"s", "s", "s"}, []string{"bramble", "anvil", "gust", "pathmaker", "inkwell"}},
		{"S reverses the order", []string{"S"}, []string{"pathmaker", "bramble", "inkwell", "anvil", "gust"}},
		{"filter by name", []string{"/", "b", "l", "enter"}, []string{"bramble"}},
		{"pasted text filters too", []string{"/", "paste:bl", "enter"}, []string{"bramble"}},
		{"esc clears the filter", []string{"/", "b", "l", "enter", "esc"}, []string{"anvil", "gust", "bramble", "inkwell", "pathmaker"}},
		{"q while filtering is text", []string{"/", "q"}, nil},
		{"f steps through status filters", []string{"f"}, []string{"bramble"}},
		{"f again shows the next status", []string{"f", "f"}, []string{"anvil", "gust", "bramble"}},
		{"F goes back round to up to date", []string{"F"}, []string{"inkwell"}},
		{"a status filter stays on its own screen", []string{"!", "h", "j"}, []string{"anvil", "gust"}},
		{"a filter stays on its own screen", []string{"/", "b", "l", "enter", "h", "j"}, []string{"anvil", "gust"}},
		{"coming back finds the filter again", []string{"/", "b", "l", "enter", "h", "j", "k"}, []string{"bramble"}},
		{"each screen keeps its own filter", []string{"h", "j", "/", "g", "o", "enter", "k"}, []string{"anvil", "gust", "bramble", "inkwell", "pathmaker"}},
		{"and keeps it while away", []string{"h", "j", "/", "g", "u", "enter", "k", "j"}, []string{"gust"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := names(press(t, loaded(t), tt.keys...)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestView(t *testing.T) {
	bramble := []string{"/", "b", "r", "a", "m", "enter"}
	keys := func(groups ...[]string) []string {
		var all []string
		for _, g := range groups {
			all = append(all, g...)
		}
		return all
	}
	tests := []struct {
		id     string
		keys   []string
		want   []string
		lacks  []string
		opened []string
	}{
		{id: "header pills count vulnerable, outdated and pinned", want: []string{"6 packages", "⚠ 1 vulnerable", "↑ 3 outdated", "⚑ 1 pinned"}},
		{id: "the rail flags the source with a vulnerability", want: []string{"pipx", "⚠1"}},
		{id: "the table flags the package", want: []string{"⚠ 1 vuln"}},
		{id: "the rail marks screens with a filter", keys: []string{"h", "j", "/", "g", "o", "enter", "k"}, want: []string{"3 ⌕"}},
		{id: "selection looks the same in rail and table", want: []string{"▌ ✨ All", "▌ anvil"}},
		{id: "dependencies sit under the info", want: []string{"🔗 Dependencies · 2", "• openssl@4", "ca-certificates"}},
		{id: "info shows links", want: []string{"home      https://anvil.example", "repo      github.com/example/anvil", "not covered: OSV has no data for brew"}},
		{id: "info sums up security", keys: bramble, want: []string{"⚠ 1 known in 22.12.0", "fixed in 24.3.0"}},
		{id: "pinned and outdated reads as newer", keys: []string{"j"}, want: []string{"⚑ newer", "1.27.1 → 1.27.2"}},
		{id: "a failing source shows its error", keys: []string{"h", "j", "j", "j"}, want: []string{"mise ls: boom"}},
		{id: "versions list with the changelog below", keys: []string{"v"}, want: []string{"v0.2.94", "≡ yes", "installed", "📜 Changelog · v0.2.94", "Fixes the thing"}},
		{
			id: "a version without notes offers its page", keys: []string{"l", "v", "j"},
			want: []string{"No changelog found for v0.2.89.", "Open the release page in your browser?", "https://github.com/example/anvil/rel"},
		},
		{id: "y opens that page", keys: []string{"l", "v", "j", "y"}, opened: []string{"https://github.com/example/anvil/releases/tag/v0.2.89"}},
		{id: "no notes and no page says so", keys: []string{"l", "v", "j", "j"}, want: []string{"No changelog or release page found for v0.2.1."}},
		{id: "versions ahead show which are safe", keys: keys(bramble, []string{"v"}), want: []string{"26.10.1", "✓ safe", "22.12.0", "⚠ 1"}},
		{id: "the security tab lists advisories", keys: keys(bramble, []string{"a"}), want: []string{"MED", "GHSA-test", "≥ 24.3.0", "🛡 GHSA-test", "Bramble vulnerable to ReDoS",
			"fixed in  24.3.0 · latest 26.10.1 is clear", "https://osv.dev/vulnerability/GHSA-test"}},
		{id: "brew is not covered by OSV", keys: []string{"a"}, want: []string{"OSV has no data for brew"}},
		{id: "skills show their audits", keys: []string{"G", "a"}, want: []string{"Security audits", "Gen Agent Trust Hub", "Pass", "Snyk", "Warn", "https://www.skills.sh/someone/"}},
		{id: "skills show SKILL.md", keys: []string{"G", "3"}, want: []string{"description Plan big work", "📄 SKILL.md", "Split the work into tickets."}},
		{id: "skills show their README", keys: []string{"G", "4"}, want: []string{"Read me first", "How to use it."}, lacks: []string{"📄 SKILL.md"}},
		{id: "the filter bar sits in the package panel", want: []string{"⌕ / to filter", "All 5", "⚠ 1", "↑ 3", "⚑ 1", "◌ 0", "✓ 1"}},
		{id: "the active chip is named in full", keys: []string{"o"}, want: []string{"↑ Outdated 3", "⚠ 1", "All 5"}},
		{id: "typing shows in the filter bar", keys: []string{"/", "b"}, want: []string{"⌕ b▏"}},
		{id: "long sidebar text wraps instead of being cut", want: []string{"wrap at the very end"}},
		{id: "enter on a version asks to upgrade", keys: []string{"l", "v", "enter"}, want: []string{"⬆ Upgrade anvil?", "0.2.89 → v0.2.94", "runs  brew upgrade anvil"}},
		{id: "brew can't go back a version", keys: []string{"l", "v", "j", "j", "enter"}, want: []string{"Can't change anvil", "Homebrew can only install the newest version, 0.2.94"}},
		{id: "a downgrade warns about advisories", keys: keys(bramble, []string{"l", "v", "j", "j", "j", "enter"}),
			want: []string{"⬇ Downgrade bramble?", "⚠ 1 known advisories affect 21.12.0", "runs  pipx install --force bramble==21.12.0"}},
		{id: "n cancels", keys: []string{"l", "v", "enter", "n"}, lacks: []string{"⬆ Upgrade anvil?"}},
		{id: "links list every agent", keys: []string{"G", "5"}, want: []string{"AGENT", "claude", "🔗 linked", "cursor", "· none", "codex", "≈ shared"}},
		{id: "skill info shows who sees it", keys: []string{"G"}, want: []string{"🔗 Seen by 2 agents"}},
		{id: "and lists installed agents only, even after A on the Links tab", keys: []string{"G", "5", "A", "i"}, want: []string{"🔗 Seen by 2 agents", "claude", "codex"},
			lacks: []string{"Goose", "Cline", "not installed"}},
		{id: "enter on a link asks to remove it", keys: []string{"G", "5", "l", "enter"}, want: []string{"✂ Unlink pathmaker from claude?", "removes  /h/.claude/skills/pathmaker"}},
		{id: "a shared agent has nothing to link", keys: []string{"G", "5", "l", "j", "j", "enter"}, want: []string{"Nothing to link", "codex reads ~/.agents/skills directly,"}},
		{id: "? shows every key", keys: []string{"?"}, want: []string{"⌨ Keys", "show or hide these keys", "Sidebar", "check security again"}},
		{id: "? again hides them", keys: []string{"?", "?"}, lacks: []string{"⌨ Keys"}},
		{id: "w opens the homepage", keys: []string{"w"}, opened: []string{"https://anvil.example"}, want: []string{"opened https://anvil.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			s := screen(press(t, loaded(t), tt.keys...))
			for _, w := range tt.want {
				if !strings.Contains(s, w) {
					t.Errorf("screen lacks %q:\n%s", w, s)
				}
			}
			for _, w := range tt.lacks {
				if strings.Contains(s, w) {
					t.Errorf("screen has %q:\n%s", w, s)
				}
			}
			if !reflect.DeepEqual(opened, tt.opened) {
				t.Errorf("opened %v, want %v", opened, tt.opened)
			}
		})
	}
}

func TestSecurityCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security.json")
	m := loaded(t)
	m.dbPath = path
	m = press(t, m, "R")
	if db := vuln.Load(path); len(db.For(vuln.Query{Ecosystem: "PyPI", Name: "bramble", Version: "22.12.0"})) != 1 {
		t.Fatal("R did not save the scan")
	}
	scanOSV = func(context.Context, []vuln.Query, map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
		t.Error("a fresh cache should not be scanned again")
		return nil, nil, nil
	}
	ps := fakes(t)
	m = newModel(ps, path)
	m = update(t, m, tea.WindowSizeMsg{Width: 160, Height: 40})
	pkgs, _ := ps[1].List(context.Background())
	m = update(t, m, listedMsg{"pipx", pkgs, nil})
	if s := screen(m); !strings.Contains(s, "⚠ 1 vulnerable") {
		t.Errorf("the cached result should show at once:\n%s", s)
	}
}

func TestSkillAuditCache(t *testing.T) {
	const key = "someone/skills/pathmaker"
	high := vuln.SkillAudit{Gen: "safe", Socket: "high", Snyk: "low"}
	down := errors.New("skills.sh: down")
	tests := []struct {
		id        string
		audits    map[string]vuln.SkillAudit
		err       error
		asks      int
		kept      map[string]vuln.SkillAudit
		auditedAt map[string]time.Time
	}{
		{"a failed ask marks nothing fresh, so the next listing asks again", nil, down, 2,
			map[string]vuln.SkillAudit{}, map[string]time.Time{}},
		{"an audit that came back with an error is kept but not fresh", map[string]vuln.SkillAudit{key: high}, down, 2,
			map[string]vuln.SkillAudit{key: high}, map[string]time.Time{}},
		{"telemetry off asks nothing, so the next listing asks again", nil, nil, 2,
			map[string]vuln.SkillAudit{}, map[string]time.Time{}},
		{"an answer marks the skill fresh even without an audit", map[string]vuln.SkillAudit{}, nil, 1,
			map[string]vuln.SkillAudit{}, map[string]time.Time{key: clock}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			loaded(t)
			asks := 0
			fetchAudits = func(context.Context, map[string][]string) (map[string]vuln.SkillAudit, error) {
				asks++
				return tt.audits, tt.err
			}
			ps := fakes(t)
			m := update(t, newModel(ps, ""), tea.WindowSizeMsg{Width: 160, Height: 40})
			pkgs, _ := ps[3].List(context.Background())
			m = update(t, m, listedMsg{"skills", pkgs, nil})
			m = update(t, m, listedMsg{"skills", pkgs, nil})
			if asks != tt.asks || !reflect.DeepEqual(m.db.Audits, tt.kept) || !reflect.DeepEqual(m.db.AuditedAt, tt.auditedAt) {
				t.Errorf("asked %d times, kept %v, audited at %v\nwant %d, %v, %v", asks, m.db.Audits, m.db.AuditedAt, tt.asks, tt.kept, tt.auditedAt)
			}
		})
	}
}

func TestMouse(t *testing.T) {
	l := loaded(t).layout()
	click := func(x, y int) tea.Msg { return tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft} }
	at := func(r int) int { return l.top + 1 + r }
	versionsTab := l.sideX + 3 + lipgloss.Width(loaded(t).tabLabels()[0]) + 2
	homeY := 0
	for i, line := range loaded(t).topView(l.sideW - 2) {
		if line.url == "https://anvil.example" {
			homeY = at(i)
			break
		}
	}
	outdatedChip := l.tableX + 1
	for m := loaded(t); m.chipAt(outdatedChip-l.tableX-1) != statusOutdated; outdatedChip++ {
	}
	// tap is a press and release on one cell, which the sidebar's text takes
	// as a click.
	tap := func(x, y int) []tea.Msg {
		return []tea.Msg{click(x, y), tea.MouseReleaseMsg{X: x, Y: y, Button: tea.MouseLeft}}
	}
	dep := func(i int) int { return at(l.topRows + 1 + i) }
	tests := []struct {
		id      string
		msgs    []tea.Msg
		rows    []string
		current string
		check   func(model) bool
		opened  []string
	}{
		{id: "click a dependency selects it", msgs: tap(l.sideX+5, dep(1)), current: "anvil",
			check: func(m model) bool { return m.depCursor == 1 && m.depPop == nil && m.focus == focusSide }},
		{id: "click it again opens its advisories", msgs: append(tap(l.sideX+5, dep(1)), tap(l.sideX+5, dep(1))...), current: "anvil",
			check: func(m model) bool { return m.depPop != nil && m.depPop.dep.Name == "ca-certificates" }},
		{id: "a click closes a finished install", msgs: []tea.Msg{key("l"), key("v"), tea.KeyPressMsg{Code: tea.KeyEnter}, key("y"), click(1, 1)}, current: "anvil",
			check: func(m model) bool { return m.inst == nil }},
		{id: "the wheel leaves the packages alone under an install dialog", msgs: []tea.Msg{key("l"), key("v"), tea.KeyPressMsg{Code: tea.KeyEnter},
			tea.MouseWheelMsg{X: l.tableX + 5, Y: at(3), Button: tea.MouseWheelDown}}, current: "anvil",
			check: func(m model) bool { return m.confirm != nil && m.confirm.title == "⬆ Upgrade anvil?" }},
		{id: "click a source", msgs: []tea.Msg{click(5, at(2))}, rows: []string{"bramble", "inkwell"}, current: "bramble",
			check: func(m model) bool { return m.focus == focusRail }},
		{id: "click a package", msgs: []tea.Msg{click(l.tableX+5, at(2))}, current: "gust",
			check: func(m model) bool { return m.focus == focusTable }},
		{id: "click a header sorts by it", msgs: []tea.Msg{click(l.tableX+3, at(0))}, current: "anvil",
			check: func(m model) bool { return m.sortCol == colName && !m.sortDesc }},
		{id: "click it again reverses", msgs: []tea.Msg{click(l.tableX+3, at(0)), click(l.tableX+3, at(0))}, current: "pathmaker",
			check: func(m model) bool { return m.sortCol == colName && m.sortDesc }},
		{id: "click the Versions tab", msgs: []tea.Msg{click(versionsTab, at(-1))}, current: "anvil",
			check: func(m model) bool { return m.activeTab() == tabVersions && m.focus == focusSide }},
		{id: "click a version selects it", msgs: []tea.Msg{click(versionsTab, at(-1)), click(l.sideX+5, at(2))}, current: "anvil",
			check: func(m model) bool { return m.sideCursor == 1 && m.sidePart == 0 }},
		{id: "click the selected version asks to install it", msgs: []tea.Msg{click(versionsTab, at(-1)), click(l.sideX+5, at(1))}, current: "anvil",
			check: func(m model) bool { return m.confirm != nil && m.confirm.title == "⬆ Upgrade anvil?" }},
		{id: "click outside the dialog closes it", msgs: []tea.Msg{click(versionsTab, at(-1)), click(l.sideX+5, at(1)), click(1, 1)}, current: "anvil",
			check: func(m model) bool { return m.confirm == nil }},
		{id: "click a status chip", msgs: []tea.Msg{click(outdatedChip, at(l.bodyH-3))}, rows: []string{"anvil", "gust", "bramble"}, current: "anvil"},
		{id: "first click into an unfocused sidebar only selects", msgs: []tea.Msg{click(versionsTab, at(-1)), click(l.tableX+5, at(1)), click(l.sideX+5, at(1))}, current: "anvil",
			check: func(m model) bool { return m.focus == focusSide && m.sidePart == 0 }},
		{id: "click the home link", msgs: []tea.Msg{click(l.sideX+8, homeY), tea.MouseReleaseMsg{X: l.sideX + 8, Y: homeY, Button: tea.MouseLeft}},
			current: "anvil", opened: []string{"https://anvil.example"}},
		{id: "wheel moves the package cursor", msgs: []tea.Msg{tea.MouseWheelMsg{X: l.tableX + 5, Y: at(3), Button: tea.MouseWheelDown}}, current: "gust"},
		{id: "wheel up past the first package stays on it", msgs: []tea.Msg{
			tea.MouseWheelMsg{X: l.tableX + 5, Y: at(3), Button: tea.MouseWheelUp}, tea.MouseWheelMsg{X: l.tableX + 5, Y: at(3), Button: tea.MouseWheelUp}}, current: "anvil"},
		{id: "wheel up past the first version stays on it", msgs: []tea.Msg{click(versionsTab, at(-1)),
			tea.MouseWheelMsg{X: l.sideX + 5, Y: at(2), Button: tea.MouseWheelUp}, tea.MouseWheelMsg{X: l.sideX + 5, Y: at(l.bodyH - 3), Button: tea.MouseWheelUp}}, current: "anvil",
			check: func(m model) bool { return m.sideCursor == 0 && m.bodyOffset == 0 }},
		{id: "any click closes help", msgs: []tea.Msg{tea.KeyPressMsg{Code: '?', Text: "?"}, click(1, 1)}, current: "anvil",
			check: func(m model) bool { return !m.help }},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			if tt.rows != nil && !reflect.DeepEqual(names(m), tt.rows) {
				t.Errorf("rows %v, want %v", names(m), tt.rows)
			}
			if p, _ := m.current(); p.Name != tt.current {
				t.Errorf("current %q, want %q", p.Name, tt.current)
			}
			if tt.check != nil && !tt.check(m) {
				t.Errorf("check failed:\n%s", screen(m))
			}
			if !reflect.DeepEqual(opened, tt.opened) {
				t.Errorf("opened %v, want %v", opened, tt.opened)
			}
		})
	}
}

// The package cursor is a row number, so a listing or a security result that
// adds or moves rows must not swap the selected package for another.
func TestKeepSelection(t *testing.T) {
	ps := fakes(t)
	listed := func(i int, extra ...provider.Package) tea.Msg {
		f := ps[i].(fake)
		return listedMsg{f.name, append(slices.Clone(f.pkgs), extra...), nil}
	}
	brew, pipx, skills := 0, 1, 3
	awl := provider.Package{Source: "brew", Name: "awl", Version: "1.0.0"}
	all := []string{"anvil", "gust", "bramble", "inkwell", "pathmaker"}
	withAwl := []string{"anvil", "awl", "gust", "bramble", "inkwell", "pathmaker"}
	l := loaded(t).layout()
	tests := []struct {
		id string
		// fresh starts from a kho that has listed nothing yet.
		fresh  bool
		keys   []string
		msgs   []tea.Msg
		rows   []string
		cursor int
	}{
		{id: "at startup the cursor stays on the first row while sources answer", fresh: true,
			msgs: []tea.Msg{listed(skills), listed(pipx), listed(brew)}, rows: all},
		{id: "and again after r", keys: []string{"j", "r"},
			msgs: []tea.Msg{listed(skills), listed(pipx), listed(brew)}, rows: all},
		{id: "a listing that adds rows ahead keeps the package picked", keys: []string{"G"}, msgs: []tea.Msg{listed(brew, awl)}, rows: withAwl, cursor: 5},
		{id: "so does a security result that moves it", keys: []string{"s", "s", "s", "j", "j", "j"},
			msgs: []tea.Msg{scanMsg{hits: map[string][]string{"PyPI/inkwell@9.0.2": {redos.ID}}, advisories: map[string]vuln.Advisory{redos.ID: redos}}},
			rows: []string{"bramble", "inkwell", "anvil", "gust", "pathmaker"}, cursor: 4},
		{id: "a filter is a pick too", keys: []string{"/", "i", "n", "k", "enter"},
			msgs: []tea.Msg{listed(brew, provider.Package{Source: "brew", Name: "inkjet", Version: "2.0.0"})}, rows: []string{"inkjet", "inkwell"}, cursor: 1},
		{id: "so is a click on a package", msgs: []tea.Msg{tea.MouseClickMsg{X: l.tableX + 5, Y: l.top + 3, Button: tea.MouseLeft}, listed(brew, awl)}, rows: withAwl, cursor: 2},
		{id: "and the wheel over the packages", msgs: []tea.Msg{tea.MouseWheelMsg{X: l.tableX + 5, Y: l.top + 3, Button: tea.MouseWheelDown}, listed(brew, awl)},
			rows: withAwl, cursor: 2},
		{id: "a listing that drops it leaves the cursor where it was", keys: []string{"j"},
			msgs: []tea.Msg{listedMsg{"brew", ps[brew].(fake).pkgs[:1], nil}}, rows: []string{"anvil", "bramble", "inkwell", "pathmaker"}, cursor: 1},
		{id: "moving still moves", keys: []string{"j"}, rows: all, cursor: 1},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			if tt.fresh {
				m = update(t, newModel(ps, ""), tea.WindowSizeMsg{Width: 160, Height: 40})
			}
			m = press(t, m, tt.keys...)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			if !slices.Equal(names(m), tt.rows) || m.cursor != tt.cursor {
				t.Errorf("rows %v at %d, want %v at %d", names(m), m.cursor, tt.rows, tt.cursor)
			}
		})
	}
}

func TestDefaultRail(t *testing.T) {
	tests := []struct{ width, rail int }{
		{222, 42}, {160, 42}, {130, 42}, {120, 34}, {110, 24}, {100, 24},
	}
	for _, tt := range tests {
		m := update(t, loaded(t), tea.WindowSizeMsg{Width: tt.width, Height: 40})
		if l := m.layout(); l.railW != tt.rail || l.tableW < minTable {
			t.Errorf("at %d wide the rail is %d and the list %d, want rail %d", tt.width, l.railW, l.tableW, tt.rail)
		}
	}
}

func TestResize(t *testing.T) {
	tests := []struct {
		id   string
		deps bool
		keys []string
		// split are what a split-pane width must still show.
		split []string
	}{
		{id: "a dependency popup with two advisories", deps: true, keys: pick("tidyup", "j", "j", "enter")},
		{id: "the packages", split: []string{"LATEST", "STATUS", "↑ outdated"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			if tt.deps {
				m = withDeps(t, "")
			}
			m = press(t, m, tt.keys...)
			for _, size := range [][2]int{{1, 1}, {10, 10}, {80, 20}, {100, 16}, {110, 30}, {220, 50}} {
				m = update(t, m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
				s := screen(m)
				if size[0] < minWidth {
					if want := fmt.Sprintf("kho needs at least 100x16, this terminal is %dx%d.", size[0], size[1]); !strings.Contains(s, want) {
						t.Errorf("small screen:\n%s", s)
					}
					continue
				}
				lines := strings.Split(s, "\n")
				if len(lines) != size[1] {
					t.Errorf("got %d lines at %v, want %d", len(lines), size, size[1])
				}
				for i, line := range lines {
					if w := ansi.StringWidth(line); w != size[0] && i > 0 && i < size[1]-1 {
						t.Errorf("line %d is %d wide at %v", i, w, size)
					}
				}
				for _, want := range tt.split {
					if size == [2]int{110, 30} && !strings.Contains(s, want) {
						t.Errorf("a split-pane width should still show %q:\n%s", want, s)
					}
				}
			}
		})
	}
}

func TestActions(t *testing.T) {
	bramble := []string{"/", "b", "r", "a", "m", "enter"}
	tests := []struct {
		id      string
		keys    []string
		ran     []string
		toggled []string
		notice  string
		// after are keys pressed once the screen is drawn and a new agent
		// has appeared.
		after []string
	}{
		{id: "y runs the upgrade", keys: []string{"l", "v", "enter", "y"}, ran: []string{"brew upgrade anvil"}, notice: "anvil is now v0.2.94"},
		{id: "n runs nothing", keys: []string{"l", "v", "enter", "n"}},
		{id: "y on a downgrade", keys: append(bramble, "l", "v", "j", "j", "j", "enter", "y"), ran: []string{"pipx install --force bramble==21.12.0"}, notice: "bramble is now 21.12.0"},
		{id: "y links the skill", keys: []string{"G", "5", "l", "j", "enter", "y"}, toggled: []string{"link cursor"}, notice: "linked pathmaker into cursor"},
		{id: "y unlinks it", keys: []string{"G", "5", "l", "enter", "y"}, toggled: []string{"unlink claude"}, notice: "removed pathmaker from claude"},
		{id: "a copied or shared agent is never touched", keys: []string{"G", "5", "l", "j", "j", "enter", "y"}},
		{id: "A lists agents not installed yet, and links one", keys: []string{"G", "5", "A", "l", "j", "j", "j", "enter", "y"}, toggled: []string{"link goose"}, notice: "linked pathmaker into Goose"},
		{id: "enter acts on the row on screen, even if an agent appeared since", keys: []string{"G", "5", "l", "j"}, after: []string{"enter", "y"},
			toggled: []string{"link cursor"}, notice: "linked pathmaker into cursor"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, loaded(t), tt.keys...)
			screen(m)
			appeared = true
			m = press(t, m, tt.after...)
			if !reflect.DeepEqual(ran, tt.ran) || !reflect.DeepEqual(toggled, tt.toggled) {
				t.Errorf("ran %v toggled %v, want %v %v", ran, toggled, tt.ran, tt.toggled)
			}
			if m.notice != tt.notice && tt.notice != "" {
				t.Errorf("notice %q, want %q", m.notice, tt.notice)
			}
		})
	}
}

func TestLinkReads(t *testing.T) {
	skills, _ := fakes(t)[3].List(context.Background())
	tests := []struct {
		id    string
		keys  []string
		msgs  []tea.Msg
		reads int
	}{
		{id: "a skill's links are read once when it is picked, however often they are drawn", keys: []string{"G", "5", "l", "j", "j"}, reads: 1},
		{id: "A reads them again", keys: []string{"G", "5", "A"}, reads: 2},
		{id: "so does a link kho makes", keys: []string{"G", "5", "l", "j", "enter", "y"}, reads: 2},
		{id: "and a relist of the skills", keys: []string{"G"}, msgs: []tea.Msg{listedMsg{"skills", skills, nil}}, reads: 2},
		{id: "coming back to the skill reads them again", keys: []string{"G", "k", "G"}, reads: 2},
		{id: "a package that isn't a skill has none to read", keys: []string{"j"}, reads: 0},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, loaded(t), tt.keys...)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			screen(m)
			screen(m)
			if linkReads != tt.reads {
				t.Errorf("read the links %d times, want %d", linkReads, tt.reads)
			}
		})
	}
}

// TestLinkStates shows the skill to one agent at a time and reads what each
// part of kho says: the count on the Info tab, the agent's row and detail on
// the Links tab, the dialog enter opens, and what y then changes.
func TestLinkStates(t *testing.T) {
	unlink := func(name string) []string {
		return []string{"✂ Unlink pathmaker from " + name + "?", "removes  /h/.config/" + strings.ToLower(name) + "/skills/pathmaker",
			"the skill itself stays in {real}", "", "y remove the link   n cancel"}
	}
	// at starts a detail: the agent's path, then the skill's folder.
	at := func(path string, rest ...string) []string {
		return append([]string{"path: " + path, "skill: {real}"}, rest...)
	}
	const removes = "enter removes this link. The skill's files stay where they are."
	tests := []struct {
		id   string
		link provider.SkillLink
		// atHome makes the skill's home HOME, so it is listed from
		// ~/.agents/skills. Otherwise HOME is an empty folder.
		atHome  bool
		seen    string
		row     string
		detail  []string
		dialog  []string
		toggled []string
		logged  []string
	}{
		{
			id:     "an agent that sees the shared copy has nothing to link, since a link would load it twice",
			link:   provider.SkillLink{Agent: "opencode", Display: "OpenCode", Path: "/h/.config/opencode/skills/pathmaker", Kind: provider.LinkMissing, Shared: true, Installed: true},
			seen:   "🔗 Seen by 1 agents",
			row:    "OpenCode ≈ shared /h/.config/opencode/skills/pathmaker",
			detail: at("/h/.config/opencode/skills/pathmaker", "OpenCode already sees it through ~/.agents/skills, so there is nothing to link."),
			dialog: []string{"Nothing to link", "OpenCode already sees pathmaker through ~/.agents/skills,", "so a link of its own would load it twice."},
		},
		{
			id:     "an agent that reads only ~/.agents/skills doesn't see a skill that isn't there",
			link:   provider.SkillLink{Agent: "codex", Display: "Codex", Path: "/h/.agents/skills/pathmaker", Kind: provider.LinkNoFolder, Installed: true},
			seen:   "🔗 Seen by 0 agents",
			row:    "Codex · none /h/.agents/skills/pathmaker",
			detail: at("/h/.agents/skills/pathmaker", "Codex reads only ~/.agents/skills, and this skill isn't there."),
			dialog: []string{"Nothing to link", "Codex reads only ~/.agents/skills,", "and pathmaker isn't there."},
		},
		{
			id:     "and sees one that is",
			link:   provider.SkillLink{Agent: "codex", Display: "Codex", Path: "/h/.agents/skills/pathmaker", Kind: provider.LinkNoFolder, Shared: true, Installed: true},
			seen:   "🔗 Seen by 1 agents",
			row:    "Codex ≈ shared /h/.agents/skills/pathmaker",
			detail: at("/h/.agents/skills/pathmaker", "Codex reads ~/.agents/skills directly, so it always sees this skill."),
			dialog: []string{"Nothing to link", "Codex reads ~/.agents/skills directly,", "so it always sees pathmaker."},
		},
		{
			id:      "an agent with nothing in its own folder gets a link",
			link:    provider.SkillLink{Agent: "cursor", Display: "Cursor", Path: "/h/.cursor/skills/pathmaker", Kind: provider.LinkMissing, Installed: true},
			seen:    "🔗 Seen by 0 agents",
			row:     "Cursor · none /h/.cursor/skills/pathmaker",
			detail:  at("/h/.cursor/skills/pathmaker", "enter links it into Cursor's own folder."),
			dialog:  []string{"🔗 Link pathmaker into Cursor?", "creates  /h/.cursor/skills/pathmaker", "      →  {real}", "", "y link it   n cancel"},
			toggled: []string{"link cursor"},
			logged:  []string{"ln -s {real} /h/.cursor/skills/pathmaker"},
		},
		{
			id:      "an agent not installed yet gets a link that waits for it, and isn't counted",
			link:    provider.SkillLink{Agent: "goose", Display: "Goose", Path: "/h/.config/goose/skills/pathmaker", Kind: provider.LinkMissing},
			seen:    "🔗 Seen by 0 agents",
			row:     "Goose · not installed /h/.config/goose/skills/pathmaker",
			detail:  at("/h/.config/goose/skills/pathmaker", "Goose isn't installed yet; the link waits for it.", "enter links it into Goose's own folder."),
			dialog:  []string{"🔗 Link pathmaker into Goose?", "creates  /h/.config/goose/skills/pathmaker", "      →  {real}", "", "y link it   n cancel"},
			toggled: []string{"link goose"},
			logged:  []string{"ln -s {real} /h/.config/goose/skills/pathmaker"},
		},
		{
			id:      "a skill whose entry in ~/.agents/skills is a link is linked through the entry, as the CLI does",
			link:    provider.SkillLink{Agent: "cursor", Display: "Cursor", Path: "/h/.cursor/skills/pathmaker", Kind: provider.LinkMissing, Installed: true},
			atHome:  true,
			seen:    "🔗 Seen by 0 agents",
			row:     "Cursor · none /h/.cursor/skills/pathmaker",
			detail:  at("/h/.cursor/skills/pathmaker", "enter links it into Cursor's own folder."),
			dialog:  []string{"🔗 Link pathmaker into Cursor?", "creates  /h/.cursor/skills/pathmaker", "      →  ~/.agents/skills/pathmaker", "", "y link it   n cancel"},
			toggled: []string{"link cursor"},
			logged:  []string{"ln -s {skill} /h/.cursor/skills/pathmaker"},
		},
		{
			id:      "a link can be removed",
			link:    provider.SkillLink{Agent: "goose", Display: "Goose", Path: "/h/.config/goose/skills/pathmaker", Kind: provider.LinkSymlink, Target: "/h/.agents/skills/pathmaker", Own: true, Installed: true},
			seen:    "🔗 Seen by 1 agents",
			row:     "Goose 🔗 linked /h/.config/goose/skills/pathmaker",
			detail:  at("/h/.config/goose/skills/pathmaker", "points to: /h/.agents/skills/pathmaker", removes),
			dialog:  unlink("Goose"),
			toggled: []string{"unlink goose"},
			logged:  []string{"rm /h/.config/goose/skills/pathmaker"},
		},
		{
			id:      "a broken link says so, isn't counted, and can still be removed",
			link:    provider.SkillLink{Agent: "goose", Display: "Goose", Path: "/h/.config/goose/skills/pathmaker", Kind: provider.LinkSymlink, Installed: true},
			seen:    "🔗 Seen by 0 agents",
			row:     "Goose ⚠ broken /h/.config/goose/skills/pathmaker",
			detail:  at("/h/.config/goose/skills/pathmaker", "This link leads to no SKILL.md, so Goose doesn't load the skill from it.", removes),
			dialog:  unlink("Goose"),
			toggled: []string{"unlink goose"},
			logged:  []string{"rm /h/.config/goose/skills/pathmaker"},
		},
		{
			id: "a link next to the shared copy loads the skill twice",
			link: provider.SkillLink{Agent: "opencode", Display: "OpenCode", Path: "/h/.config/opencode/skills/pathmaker", Kind: provider.LinkSymlink, Target: "/h/.agents/skills/pathmaker",
				Shared: true, Own: true, Installed: true},
			seen:    "🔗 Seen by 1 agents",
			row:     "OpenCode 🔗 linked /h/.config/opencode/skills/pathmaker",
			detail:  at("/h/.config/opencode/skills/pathmaker", "points to: /h/.agents/skills/pathmaker", "OpenCode also reads ~/.agents/skills, so it loads this skill twice.", removes),
			dialog:  unlink("OpenCode"),
			toggled: []string{"unlink opencode"},
			logged:  []string{"rm /h/.config/opencode/skills/pathmaker"},
		},
		{
			id:      "a broken one there doesn't, though it still sees the shared copy",
			link:    provider.SkillLink{Agent: "opencode", Display: "OpenCode", Path: "/h/.config/opencode/skills/pathmaker", Kind: provider.LinkSymlink, Shared: true, Installed: true},
			seen:    "🔗 Seen by 1 agents",
			row:     "OpenCode ⚠ broken /h/.config/opencode/skills/pathmaker",
			detail:  at("/h/.config/opencode/skills/pathmaker", "This link leads to no SKILL.md, so OpenCode doesn't load the skill from it.", "OpenCode still sees the skill through ~/.agents/skills.", removes),
			dialog:  unlink("OpenCode"),
			toggled: []string{"unlink opencode"},
			logged:  []string{"rm /h/.config/opencode/skills/pathmaker"},
		},
		{
			id:     "a copied folder stays",
			link:   provider.SkillLink{Agent: "cursor", Display: "Cursor", Path: "/h/.cursor/skills/pathmaker", Kind: provider.LinkCopy, Own: true, Installed: true},
			seen:   "🔗 Seen by 1 agents",
			row:    "Cursor 📁 copy /h/.cursor/skills/pathmaker",
			detail: at("/h/.cursor/skills/pathmaker", "A copied folder, not a link. kho won't delete it."),
			dialog: []string{"Nothing to toggle", "/h/.cursor/skills/pathmaker is a folder, not a link.", "kho won't delete it."},
		},
		{
			id:     "a folder with no SKILL.md says so and isn't counted",
			link:   provider.SkillLink{Agent: "cursor", Display: "Cursor", Path: "/h/.cursor/skills/pathmaker", Kind: provider.LinkCopy, Installed: true},
			seen:   "🔗 Seen by 0 agents",
			row:    "Cursor ⚠ no SKILL.md /h/.cursor/skills/pathmaker",
			detail: at("/h/.cursor/skills/pathmaker", "A folder with no SKILL.md, so Cursor doesn't load the skill from it. kho won't delete it."),
			dialog: []string{"Nothing to toggle", "/h/.cursor/skills/pathmaker is a folder, not a link.", "kho won't delete it."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			home := t.TempDir()
			if tt.atHome {
				home = filepath.Dir(filepath.Dir(filepath.Dir(m.pkgs["skills"][0].Path)))
			}
			t.Setenv("HOME", home)
			skillLinks = func(provider.Package, bool) []provider.SkillLink { return []provider.SkillLink{tt.link} }
			m = press(t, m, "G")
			p, _ := m.current()
			seen := m.bottomTitle()
			m = press(t, m, "5")
			row := strings.Join(strings.Fields(ansi.Strip(linkLines(m.links)[1].text)), " ")
			var detail []string
			for _, l := range m.linkDetail(p) {
				switch {
				case l.label != "":
					detail = append(detail, l.label+": "+ansi.Strip(l.text))
				case l.text != "":
					detail = append(detail, strings.TrimSpace(ansi.Strip(l.text)))
				}
			}
			m = press(t, m, "l", "enter")
			var dialog []string
			if m.confirm != nil {
				dialog = append(dialog, m.confirm.title)
				for _, l := range m.confirm.lines {
					dialog = append(dialog, ansi.Strip(l))
				}
			}
			m = press(t, m, "y")
			var logged []string
			for _, e := range m.log.Entries() {
				if e.Kind == history.Change {
					logged = append(logged, strings.Join(e.Command, " "))
				}
			}
			fill := strings.NewReplacer("{real}", provider.RealPath(p), "{skill}", p.Path)
			want, wantDetail, wantLogged := slices.Clone(tt.dialog), slices.Clone(tt.detail), slices.Clone(tt.logged)
			for _, s := range [][]string{want, wantDetail, wantLogged} {
				for i := range s {
					s[i] = fill.Replace(s[i])
				}
			}
			if seen != tt.seen || row != tt.row || !slices.Equal(detail, wantDetail) || !slices.Equal(dialog, want) ||
				!slices.Equal(toggled, tt.toggled) || !slices.Equal(logged, wantLogged) {
				t.Errorf("got  %q\n     %q\n     %q\n     %q\n     %q\n     %q\nwant %q\n     %q\n     %q\n     %q\n     %q\n     %q",
					seen, row, detail, dialog, toggled, logged, tt.seen, tt.row, wantDetail, want, tt.toggled, wantLogged)
			}
		})
	}
}

func TestSkillLayout(t *testing.T) {
	m := press(t, loaded(t), "G", "3")
	l := m.layout()
	if l.topRows > 6 || l.bottomRows < 25 {
		t.Errorf("SKILL.md front matter takes %d rows and the body %d", l.topRows, l.bottomRows)
	}
}

func TestCopy(t *testing.T) {
	m := loaded(t)
	l := m.layout()
	y := l.top + 1 + l.topRows + 1
	m = update(t, m, tea.MouseClickMsg{X: l.sideX + 2, Y: y, Button: tea.MouseLeft})
	m = update(t, m, tea.MouseMotionMsg{X: l.sideX + 12, Y: y, Button: tea.MouseLeft})
	m = update(t, m, tea.MouseReleaseMsg{X: l.sideX + 12, Y: y, Button: tea.MouseLeft})
	if !reflect.DeepEqual(copied, []string{"• openssl@4"}) {
		t.Errorf("drag copied %q", copied)
	}
	if !strings.Contains(m.notice, "copied 1 lines") {
		t.Errorf("notice %q", m.notice)
	}
	copied = nil
	press(t, m, "c")
	if len(copied) != 1 || !strings.Contains(copied[0], "openssl@4") || !strings.Contains(copied[0], "ca-certificates") {
		t.Errorf("c copied %q", copied)
	}
}

// A drag lights the text it covers before it is let go and copied.
func TestHighlight(t *testing.T) {
	lit := regexp.MustCompile("\x1b\\[7m([^\x1b]*)")
	l := loaded(t).layout()
	deps := l.top + 1 + l.topRows + 1
	text := popupText(loaded(t).depRect())
	drag := func(x0, x1, y int) []tea.Msg {
		return []tea.Msg{tea.MouseClickMsg{X: x0, Y: y, Button: tea.MouseLeft}, tea.MouseMotionMsg{X: x1, Y: y, Button: tea.MouseLeft}}
	}
	tests := []struct {
		id    string
		popup bool
		msgs  []tea.Msg
		want  []string
	}{
		{id: "a drag in the sidebar lights what it covers", msgs: drag(l.sideX+2, l.sideX+12, deps), want: []string{"• openssl@4"}},
		{id: "a drag in the dependency popup lights what it covers", popup: true, msgs: drag(text.x, text.x+11, text.y), want: []string{" GO-TEST-000"}},
		{id: "a press alone lights nothing", msgs: drag(l.sideX+2, l.sideX+2, deps)},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			if tt.popup {
				m = press(t, withDeps(t, ""), pick("tidyup", "j", "enter")...)
			}
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			var got []string
			for _, match := range lit.FindAllStringSubmatch(m.View().Content, -1) {
				got = append(got, match[1])
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("lit %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResizePanels(t *testing.T) {
	base := loaded(t).layout()
	drag := func(x0, y0, x1, y1 int) []tea.Msg {
		return []tea.Msg{
			tea.MouseClickMsg{X: x0, Y: y0, Button: tea.MouseLeft},
			tea.MouseMotionMsg{X: x1, Y: y1, Button: tea.MouseLeft},
			tea.MouseReleaseMsg{X: x1, Y: y1, Button: tea.MouseLeft},
		}
	}
	keys := func(ks ...string) []tea.Msg {
		var msgs []tea.Msg
		for _, k := range ks {
			msgs = append(msgs, tea.KeyPressMsg{Code: rune(k[0]), Text: k})
		}
		return msgs
	}
	tests := []struct {
		id    string
		msgs  []tea.Msg
		check func(layout) bool
	}{
		{"> widens the focused package panel", keys(">"), func(l layout) bool { return l.tableW == base.tableW+2 && l.sideW == base.sideW-2 }},
		{"< narrows the focused rail", keys("h", "<"), func(l layout) bool { return l.railW == base.railW-2 }},
		{"> widens the focused sidebar", keys("l", ">"), func(l layout) bool { return l.sideW == base.sideW+2 }},
		{"} moves the divider down", keys("}", "}"), func(l layout) bool { return l.topRows == base.topRows+2 }},
		{"= puts everything back", keys(">", ">", "}", "="), func(l layout) bool { return l == base }},
		{"the rail never gets too thin", keys("h", "<", "<", "<", "<", "<", "<", "<", "<", "<", "<", "<", "<", "<", "<", "<"), func(l layout) bool { return l.railW == minRail }},
		{"the package panel keeps its minimum", keys("l", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">", ">"),
			func(l layout) bool { return l.tableW == minTable }},
		{"drag the rail's border", drag(base.tableX, 5, base.tableX+10, 5), func(l layout) bool { return l.railW == base.railW+10 }},
		{"drag the sidebar's border", drag(base.sideX, 5, base.sideX-20, 5), func(l layout) bool { return l.sideW == base.sideW+20 }},
		{"drag the sidebar's divider", drag(base.sideX+5, base.top+1+base.topRows, base.sideX+5, base.top+6+base.topRows), func(l layout) bool { return l.topRows == base.topRows+5 }},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			if l := m.layout(); !tt.check(l) {
				t.Errorf("layout %+v from %+v", l, base)
			}
			lines := strings.Split(screen(m), "\n")
			for i, line := range lines[1 : len(lines)-1] {
				if w := ansi.StringWidth(line); w != 160 {
					t.Errorf("line %d is %d wide after resizing", i+1, w)
				}
			}
		})
	}
}

func TestHistory(t *testing.T) {
	withLog := func(t *testing.T) model {
		m := loaded(t)
		m.log.Add(history.Entry{At: clock, Kind: history.Read, Command: []string{"brew", "info", "--json=v2", "--installed"}, Took: 1300 * time.Millisecond})
		m.log.Add(history.Entry{At: clock.Add(time.Minute), Kind: history.Change, Command: []string{"pipx", "install", "--force", "bramble==26.10.1"},
			Err: "exit status 1", Output: "Collecting bramble\r\x1b[31mboom:\x1b[0m\tno matching distribution\a"})
		m.log.Add(history.Entry{At: clock.Add(2 * time.Minute), Kind: history.Change, Command: []string{"ln", "-s", "/h/.agents/skills/pathmaker", "/h/.cursor/skills/pathmaker"}})
		return m
	}
	tests := []struct {
		id     string
		keys   []string
		want   []string
		lacks  []string
		copied []string
		opened []string
		// like are keys whose screen this row's must be, key for key.
		like []string
	}{
		{id: "enter opens no dependency behind the history", keys: []string{"l", "H", "enter"}, want: []string{"🕘 History · 3"}, lacks: []string{"◆ openssl@4"}},
		{id: "nor an install", keys: []string{"v", "l", "H", "enter"}, want: []string{"🕘 History · 3"}, lacks: []string{"Upgrade anvil?"}},
		{id: "w opens no homepage behind it", keys: []string{"H", "w"}, want: []string{"🕘 History · 3"}},
		{id: "nor y a release page", keys: []string{"v", "l", "j", "H", "y"}, want: []string{"🕘 History · 3"}},
		{id: "and the panels behind it keep their state", keys: []string{"H", "J", "K", "]", "[", "2", "s", "S", "o", "!", "d", "A", "<", ">", "{", "}", "=", "esc"},
			like: []string{"H", "esc"}},
		{id: "H lists every command, newest first", keys: []string{"H"}, want: []string{"🕘 History · 3", "ln -s /h/.agents", "pipx install --force", "brew info --json=v2 --installed", "1.3s", "⌨ ln", "change: kho changed the machine"}},
		{id: "f keeps the changes", keys: []string{"H", "f"}, want: []string{"🕘 History · 2 · ✎ Changes", "✎ Changes 2"}, lacks: []string{"brew info"}},
		{id: "f again keeps the failures", keys: []string{"H", "f", "f"}, want: []string{"✗ Failed 1", "✗ exit status 1", "boom:   no matching distribution"}, lacks: []string{"ln -s"}},
		{id: "an install's output shows as its popup showed it", keys: []string{"H", "j"}, want: []string{"│ boom:   no matching distribution"},
			lacks: []string{"Collecting bramble", "\r", "\a"}},
		{id: "/ filters the commands", keys: []string{"H", "/", "b", "r", "e", "w", "enter"}, want: []string{"🕘 History · 1", "brew info"}, lacks: []string{"pipx install"}},
		{id: "c copies the selected command", keys: []string{"H", "j", "c"}, copied: []string{"pipx install --force bramble==26.10.1"}},
		{id: "esc goes back to the packages", keys: []string{"H", "esc"}, want: []string{"💻 Machine"}, lacks: []string{"🕘 History"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			s := screen(press(t, withLog(t), tt.keys...))
			for _, w := range tt.want {
				if !strings.Contains(s, w) {
					t.Errorf("screen lacks %q:\n%s", w, s)
				}
			}
			for _, w := range tt.lacks {
				if strings.Contains(s, w) {
					t.Errorf("screen has %q", w)
				}
			}
			if !reflect.DeepEqual(copied, tt.copied) || !reflect.DeepEqual(opened, tt.opened) {
				t.Errorf("copied %q, opened %q, want %q, %q", copied, opened, tt.copied, tt.opened)
			}
			if tt.like != nil {
				if like := screen(press(t, withLog(t), tt.like...)); s != like {
					t.Errorf("screen\n%s\nwant\n%s", s, like)
				}
			}
		})
	}
}

func TestRecording(t *testing.T) {
	log := history.Open("")
	var out bytes.Buffer
	run := &terminalRun{cmd: exec.Command("sh", "-c", "echo fetched; exit 3"), log: log}
	run.SetStdin(strings.NewReader("\n"))
	run.SetStdout(&out)
	run.SetStderr(&out)
	if err := run.Run(); err == nil {
		t.Fatal("the command failed, Run should say so")
	}
	es := log.Entries()
	if len(es) != 1 || es[0].Kind != history.Change || es[0].Err != "exit status 3" || !strings.Contains(es[0].Output, "fetched") {
		t.Errorf("logged %+v", es)
	}
	if !strings.Contains(out.String(), "fetched") || !strings.Contains(out.String(), "Press enter to go back to kho") {
		t.Errorf("terminal showed %q", out.String())
	}

	m := press(t, loaded(t), "G", "5", "l", "j", "enter", "y")
	if es := m.log.Entries(); len(es) != 1 || es[0].Kind != history.Change || es[0].Command[0] != "ln" || es[0].Command[3] != "/h/.cursor/skills/pathmaker" {
		t.Errorf("linking logged %+v", es)
	}
}

func TestThemes(t *testing.T) {
	white := tea.BackgroundColorMsg{Color: color.White}
	tests := []struct {
		id   string
		msgs []tea.Msg
		want string
	}{
		{"t picks the next theme", []tea.Msg{key("t")}, "Paper"},
		{"T goes back round to the last", []tea.Msg{key("T")}, "Ember"},
		{"a dark terminal starts on Ocean", []tea.Msg{tea.BackgroundColorMsg{Color: color.Black}}, "Ocean"},
		{"t cycles all five", []tea.Msg{key("t"), key("t"), key("t"), key("t"), key("t")}, "Ocean"},
		{"a light terminal gets Paper", []tea.Msg{white}, "Paper"},
		{"a picked theme stays on a light terminal", []tea.Msg{key("t"), key("t"), white}, "Forest"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			m.themePath = filepath.Join(t.TempDir(), "theme")
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			if th.name != tt.want {
				t.Errorf("theme %s, want %s", th.name, tt.want)
			}
			if saved, err := os.ReadFile(m.themePath); m.themePicked && (err != nil || strings.TrimSpace(string(saved)) != tt.want) {
				t.Errorf("saved %q, %v", saved, err)
			}
			s := screen(m)
			if !strings.Contains(s, "🎨 "+tt.want) {
				t.Errorf("status bar lacks the theme name")
			}
			for i, line := range strings.Split(s, "\n")[:39] {
				if w := ansi.StringWidth(line); w != 160 {
					t.Errorf("line %d is %d wide in %s", i, w, tt.want)
				}
			}
		})
	}
	th = themes[0]
}

func key(k string) tea.Msg { return tea.KeyPressMsg{Code: rune(k[0]), Text: k} }

// A link left open at the end of a line runs into the next screen row, which
// terminals draw as a dotted underline across every panel.
func TestLinksCloseOnTheirLine(t *testing.T) {
	osc8 := regexp.MustCompile("\x1b\\]8;[^;\x07\x1b]*;([^\x07\x1b]*)(?:\x07|\x1b\\\\)")
	tests := []struct {
		id   string
		keys []string
	}{
		{"skill audit report link", []string{"G", "a"}},
		{"homepage on Info", nil},
		{"release page of a version", []string{"l", "v", "j"}},
		{"advisory link", []string{"/", "b", "r", "a", "m", "enter", "a"}},
		{"README repo link", []string{"G", "4"}},
		{"markdown link in a changelog", []string{"v"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, loaded(t), tt.keys...)
			for _, width := range []int{110, 160, 220} {
				m = update(t, m, tea.WindowSizeMsg{Width: width, Height: 40})
				for i, line := range strings.Split(m.View().Content, "\n") {
					open := false
					for _, match := range osc8.FindAllStringSubmatch(line, -1) {
						open = match[1] != ""
					}
					if open {
						t.Errorf("at %d wide, line %d leaves a link open: %q", width, i, ansi.Strip(line))
					}
				}
			}
		})
	}
}

func TestHelp(t *testing.T) {
	first, last := "show or hide these keys", "scroll whatever is under the pointer"
	// A 40-row screen fits 35 lines of help.
	end := len(helpLines()) - 35
	wheel := tea.MouseWheelMsg{X: 80, Y: 20, Button: tea.MouseWheelDown}
	tests := []struct {
		id           string
		height       int
		msgs         []tea.Msg
		top          int
		shows, hides string
		hint         bool
	}{
		{"a short screen starts at the top", 40, []tea.Msg{key("?")}, 0, first, last, true},
		{"j scrolls to the last key", 40, append([]tea.Msg{key("?")}, slices.Repeat([]tea.Msg{key("j")}, end)...), end, last, first, true},
		{"scrolling stops at the last key", 40, append([]tea.Msg{key("?")}, slices.Repeat([]tea.Msg{key("j")}, end+3)...), end, last, first, true},
		{"k scrolls back up", 40, []tea.Msg{key("?"), key("j"), key("j"), key("j"), key("k")}, 2, "", first, true},
		{"the wheel scrolls it", 40, []tea.Msg{key("?"), wheel, wheel}, 2, "", first, true},
		{"it opens at the top again", 40, []tea.Msg{key("?"), key("j"), key("j"), key("?"), key("?")}, 0, first, last, true},
		{"a tall screen shows every key", 52, []tea.Msg{key("?"), key("j")}, 0, first + "|" + last, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := update(t, loaded(t), tea.WindowSizeMsg{Width: 160, Height: tt.height})
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			s := screen(m)
			if m.helpTop != tt.top {
				t.Errorf("top %d, want %d", m.helpTop, tt.top)
			}
			for _, want := range strings.Split(tt.shows, "|") {
				if want != "" && !strings.Contains(s, want) {
					t.Errorf("help lacks %q:\n%s", want, s)
				}
			}
			if tt.hides != "" && strings.Contains(s, tt.hides) {
				t.Errorf("help shows %q, which should be scrolled out of view", tt.hides)
			}
			if strings.Contains(s, "↑↓ scroll") != tt.hint {
				t.Errorf("scroll hint shown is %v, want %v", !tt.hint, tt.hint)
			}
		})
	}
}

func TestInstall(t *testing.T) {
	upgrade := []string{"l", "v", "enter", "y"}
	brew := "brew upgrade anvil"
	pkgtool := exec.Command("pkgtool", "upgrade", "anvil")
	pkgtool.Env, pkgtool.Dir = []string{"PKGTOOL_NO_AUTO_UPDATE=1"}, t.TempDir()
	tests := []struct {
		id string
		// script stands in for the command; {pids} in it is a file for the
		// pids of children it leaves behind, killed once the row is done.
		script string
		// missing makes the command one that can't start.
		missing bool
		// cmd starts the install with this command instead of through the
		// dialog.
		cmd   *exec.Cmd
		keys  []string
		ran   []string
		shows []string
		hides string
		open  bool
		// logged is the history entry: its kind, command, error and output.
		logged []string
	}{
		{id: "a command that can't start says so, with nothing left to stop", missing: true, keys: upgrade, ran: []string{brew},
			shows: []string{"anvil v0.2.94 failed: fork/exec"}, hides: "ctrl+c", logged: []string{`change brew upgrade anvil: fork/exec {missing}: no such file or directory ""`}},
		{id: "a child that keeps the output open can't hold the popup open", script: "perl -e 'setpgrp(0,0); exec @ARGV' sh -c 'sleep 4; echo late' & echo $! > {pids}; echo started", keys: upgrade, ran: []string{brew},
			shows: []string{"started", "✓ done"}, hides: "late", open: true, logged: []string{`change brew upgrade anvil:  "started\n"`}},
		{id: "but one still writing is read to its end", script: "(for i in 1 2 3; do sleep 0.4; echo tick $i; done) & echo started", keys: upgrade, ran: []string{brew},
			shows: []string{"started", "tick 3", "✓ done"}, open: true, logged: []string{`change brew upgrade anvil:  "started\ntick 1\ntick 2\ntick 3\n"`}},
		{id: "output streams into a popup", script: "echo fetched anvil; echo poured", keys: upgrade, ran: []string{brew},
			shows: []string{"⬆ Upgrade anvil", "runs  brew upgrade anvil", "fetched anvil", "poured", "✓ done", "enter close"}, open: true,
			logged: []string{`change brew upgrade anvil:  "fetched anvil\npoured\n"`}},
		{id: "a failure says so and offers the terminal", script: "echo no space left; exit 3", keys: upgrade, ran: []string{brew},
			shows: []string{"no space left", "✗ exit status 3", "t run it in the terminal"}, open: true, logged: []string{`change brew upgrade anvil: exit status 3 "no space left\n"`}},
		{id: "t runs a failed install in the terminal", script: "exit 3", keys: append(upgrade, "t"), ran: []string{brew, brew}, hides: "✗ exit status 3",
			logged: []string{`change brew upgrade anvil: exit status 3 ""`}},
		{id: "t runs the very command again, where it ran", script: "exit 3", cmd: pkgtool, keys: []string{"t"}, ran: []string{"pkgtool upgrade anvil", "pkgtool upgrade anvil"},
			logged: []string{`change pkgtool upgrade anvil: exit status 3 ""`}},
		{id: "enter closes it once done", script: "echo fetched", keys: append(upgrade, "enter"), ran: []string{brew}, hides: "fetched",
			logged: []string{`change brew upgrade anvil:  "fetched\n"`}},
		{id: "t does nothing after a success", script: "echo fetched", keys: append(upgrade, "t"), ran: []string{brew}, shows: []string{"✓ done"}, open: true,
			logged: []string{`change brew upgrade anvil:  "fetched\n"`}},
		{id: "a progress line keeps its last state", script: `printf 'step 1\rstep 2\n'`, keys: upgrade, ran: []string{brew}, shows: []string{"step 2"}, hides: "step 1", open: true,
			logged: []string{`change brew upgrade anvil:  "step 1\rstep 2\n"`}},
		{id: "colors are dropped", script: `printf '\033[32mgreen\033[0m\n'`, keys: upgrade, ran: []string{brew}, shows: []string{"green"}, hides: "[32m", open: true,
			logged: []string{`change brew upgrade anvil:  "\x1b[32mgreen\x1b[0m\n"`}},
		{id: "tabs become spaces", script: `printf '\tgo: missing module\n'`, keys: upgrade, ran: []string{brew}, shows: []string{"┃         go: missing module"}, hides: "\t", open: true,
			logged: []string{`change brew upgrade anvil:  "\tgo: missing module\n"`}},
		{id: "other control characters are dropped", script: `printf 'ding\a dong\n'`, keys: upgrade, ran: []string{brew}, shows: []string{"ding dong"}, hides: "\a", open: true,
			logged: []string{`change brew upgrade anvil:  "ding\a dong\n"`}},
		{id: "the command can't reach the terminal", script: `(exec 3</dev/tty) 2>/dev/null && echo has-tty || echo no-tty`, keys: upgrade, ran: []string{brew},
			shows: []string{"no-tty"}, hides: "has-tty", open: true, logged: []string{`change brew upgrade anvil:  "no-tty\n"`}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			pids, missing := filepath.Join(t.TempDir(), "pids"), filepath.Join(t.TempDir(), "missing")
			t.Cleanup(func() { reap(pids) })
			installScript = strings.ReplaceAll(tt.script, "{pids}", pids)
			if tt.missing {
				installProcess = func(c *exec.Cmd) *exec.Cmd {
					ran = append(ran, strings.Join(c.Args, " "))
					return exec.Command(missing)
				}
			}
			if tt.cmd != nil {
				m = update(t, m, startInstall("⬆ Upgrade anvil", tt.cmd, m.log, installedMsg{provider: "brew", name: "anvil", version: "v0.2.94"})())
			}
			m = press(t, m, tt.keys...)
			s := screen(m)
			var logged []string
			for _, e := range m.log.Entries() {
				logged = append(logged, fmt.Sprintf("%s %s: %s %q", e.Kind, strings.Join(e.Command, " "), e.Err, e.Output))
			}
			want := slices.Clone(tt.logged)
			for i := range want {
				want[i] = strings.ReplaceAll(want[i], "{missing}", missing)
			}
			if !slices.Equal(ran, tt.ran) || (m.inst != nil) != tt.open || !slices.Equal(logged, want) {
				t.Errorf("ran %q, popup open %v, logged %q\nwant %q, %v, %q", ran, m.inst != nil, logged, tt.ran, tt.open, want)
			}
			if r := reran; tt.cmd != nil && (r == nil || r.Path != tt.cmd.Path || !slices.Equal(r.Args, tt.cmd.Args) || !slices.Equal(r.Env, tt.cmd.Env) || r.Dir != tt.cmd.Dir) {
				t.Errorf("t ran %+v, want %+v", r, tt.cmd)
			}
			for _, want := range tt.shows {
				if !strings.Contains(s, want) {
					t.Errorf("screen lacks %q:\n%s", want, s)
				}
			}
			if tt.hides != "" && strings.Contains(s, tt.hides) {
				t.Errorf("screen shows %q:\n%s", tt.hides, s)
			}
		})
	}
}

// selectPkg puts the cursor on a package by name, so a test does not depend on
// the order the fakes list them in.
func selectPkg(t *testing.T, m model, name string) model {
	t.Helper()
	m = press(t, m, "g")
	for i := 0; i < 50; i++ {
		if p, ok := m.current(); ok && p.Name == name {
			return m
		}
		m = press(t, m, "j")
	}
	t.Fatalf("no package named %q", name)
	return m
}

// D asks before it removes anything, and a refusal explains itself instead of
// leaving a person guessing.
func TestRemoveAsks(t *testing.T) {
	tests := []struct {
		id    string
		pkg   string
		deps  bool
		keys  []string
		title string
		lines string
		ran   []string
	}{
		{id: "D asks first", pkg: "anvil", keys: []string{"D"}, title: "🗑 Remove anvil?", lines: "0.2.89|brew uninstall anvil|remove it"},
		{id: "n changes nothing", pkg: "anvil", keys: []string{"D", "n"}},
		{id: "y removes it and says so", pkg: "anvil", keys: []string{"D", "y"}, ran: []string{"brew uninstall anvil"}},
		{id: "a dependency is named as one", pkg: "cobalt", deps: true, keys: []string{"D"}, title: "🗑 Remove cobalt?", lines: "another installed package needs it"},
		{id: "a pinned package can still go", pkg: "gust", keys: []string{"D"}, title: "🗑 Remove gust?", lines: "brew uninstall gust"},
		{id: "a skill says why kho won't", pkg: "pathmaker", keys: []string{"D"}, title: "Can't remove pathmaker", lines: "npx skills remove pathmaker"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			if tt.deps {
				m = press(t, m, "d")
			}
			m = selectPkg(t, m, tt.pkg)
			m = press(t, m, tt.keys...)
			if !slices.Equal(ran, tt.ran) {
				t.Errorf("ran %q, want %q", ran, tt.ran)
			}
			if tt.title == "" {
				if m.confirm != nil {
					t.Errorf("dialog %q, want none", m.confirm.title)
				}
				return
			}
			if m.confirm == nil {
				t.Fatalf("no dialog, want %q", tt.title)
			}
			if m.confirm.title != tt.title {
				t.Errorf("dialog %q, want %q", m.confirm.title, tt.title)
			}
			joined := strings.Join(m.confirm.lines, "\n")
			for _, want := range strings.Split(tt.lines, "|") {
				if want != "" && !strings.Contains(joined, want) {
					t.Errorf("dialog lacks %q:\n%s", want, joined)
				}
			}
		})
	}
}

// A removal that ran is logged like an install, and the notice says what
// happened rather than which version it landed on.
func TestRemoveIsLogged(t *testing.T) {
	m := selectPkg(t, loaded(t), "anvil")
	m = press(t, m, "D", "y")
	if m.notice != "anvil is removed" {
		t.Errorf("notice %q", m.notice)
	}
	entries := m.log.Entries()
	if len(entries) != 1 || entries[0].Kind != history.Change || !slices.Equal(entries[0].Command, []string{"brew", "uninstall", "anvil"}) {
		t.Errorf("history %+v", entries)
	}
}

// reap kills the children a test's script left behind on purpose, and their
// process groups, from the pids it wrote to path.
func reap(path string) {
	data, _ := os.ReadFile(path)
	for _, f := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(f); err == nil {
			syscall.Kill(-pid, syscall.SIGKILL)
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// Quitting mid-install would cut the package manager off with nothing
// logged, so ctrl+c stops the install and quits only once it is over.
func TestStopInstall(t *testing.T) {
	ctrlC := tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	quits := func(cmd tea.Cmd) bool {
		if cmd == nil {
			return false
		}
		_, ok := cmd().(tea.QuitMsg)
		return ok
	}
	tests := []struct {
		id, script string
		stops      int
		err        string
	}{
		{"ctrl+c interrupts the install", "echo started; sleep 5; echo finished", 1, "signal: interrupt"},
		{"a second ctrl+c kills one that ignores the first", "trap '' INT; echo started; sleep 5; echo finished", 2, "signal: killed"},
		{"and ends it even when a child it left behind keeps the output open", "trap '' INT; perl -e 'setpgrp(0,0); exec @ARGV' sh -c 'sleep 4; echo finished' & echo $! > {pids}; echo started; sleep 5",
			2, "signal: killed"},
		{"and lets go of one that keeps writing after the command is done", "echo started; perl -e 'setpgrp(0,0); exec @ARGV' sh -c 'while :; do echo tick; sleep 0.3; done' & echo $! > {pids}",
			2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			pids := filepath.Join(t.TempDir(), "pids")
			t.Cleanup(func() { reap(pids) })
			installScript = strings.ReplaceAll(tt.script, "{pids}", pids)
			m = press(t, m, "l", "v", "enter")
			tm, cmd := m.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
			tm, _ = tm.Update(cmd())
			tm, _ = tm.Update(tm.(model).inst.next()())
			if s := screen(tm.(model)); !strings.Contains(s, "started") || !strings.Contains(s, "ctrl+c stop it") {
				t.Fatalf("running popup:\n%s", s)
			}
			// A command that has exited is gone once it is reaped.
			for pid := tm.(model).inst.pid; tt.err == "" && syscall.Kill(pid, 0) == nil; {
				time.Sleep(10 * time.Millisecond)
			}
			for range tt.stops {
				if tm, cmd = tm.Update(ctrlC); quits(cmd) {
					t.Fatal("ctrl+c quit while the install ran")
				}
			}
			if s := screen(tm.(model)); !strings.Contains(s, "ctrl+c kill it") {
				t.Errorf("stopping popup:\n%s", s)
			}
			m = update(t, tm.(model), tm.(model).inst.next()())
			status := "✗ " + tt.err
			if tt.err == "" {
				status = "✓ done"
			}
			if s := screen(m); !strings.Contains(s, status) || strings.Contains(s, "finished") {
				t.Errorf("stopped popup:\n%s", s)
			}
			if es := m.log.Entries(); len(es) != 1 || es[0].Kind != history.Change || es[0].Err != tt.err || !strings.Contains(es[0].Output, "started") || strings.Contains(es[0].Output, "finished") {
				t.Errorf("logged %+v", es)
			}
			if _, cmd := m.Update(ctrlC); !quits(cmd) {
				t.Error("ctrl+c should quit once the install is over")
			}
		})
	}
}

// While an install runs, its popup takes every click, turn of the wheel and
// key but ctrl+c, so nothing behind it changes and it can't be closed.
func TestRunningInstall(t *testing.T) {
	l := loaded(t).layout()
	tests := []struct {
		id   string
		msgs []tea.Msg
	}{
		{"a click leaves it open", []tea.Msg{tea.MouseClickMsg{X: 1, Y: 1, Button: tea.MouseLeft}}},
		{"the wheel moves nothing under it", []tea.Msg{tea.MouseWheelMsg{X: l.tableX + 5, Y: l.top + 4, Button: tea.MouseWheelDown}}},
		{"keys do nothing", []tea.Msg{key("q"), key("j"), tea.KeyPressMsg{Code: tea.KeyEnter}, tea.KeyPressMsg{Code: tea.KeyEscape}, key("t")}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, loaded(t), "l", "v", "enter")
			installScript = "echo started; sleep 5"
			tm, cmd := m.Update(key("y"))
			tm, _ = tm.Update(cmd())
			tm, _ = tm.Update(tm.(model).inst.next()())
			m = tm.(model)
			defer m.inst.finish(time.Second)
			for _, msg := range tt.msgs {
				var cmd tea.Cmd
				if tm, cmd = m.Update(msg); cmd != nil {
					if _, quit := cmd().(tea.QuitMsg); quit {
						t.Fatal("kho quit while the install ran")
					}
				}
				m = tm.(model)
			}
			if p, _ := m.current(); !m.inst.running() || p.Name != "anvil" || m.activeTab() != tabVersions || m.sideCursor != 0 || len(ran) != 1 {
				t.Errorf("running %v, current %q, tab %d, version %d, ran %v:\n%s", m.inst.running(), p.Name, m.activeTab(), m.sideCursor, ran, screen(m))
			}
		})
	}
}

// A progress bar redraws its line after a \r. The popup shows each state as
// it comes, rather than nothing until the line ends.
func TestProgress(t *testing.T) {
	// Each printf lands on its own, so each shows as a state of its own.
	tests := []struct {
		id, script string
		// states are the popup's output lines after each message.
		states [][]string
	}{
		{"a progress bar shows each state as it redraws", `printf 'step 1\r'; sleep 0.1; printf 'step 2\r'; sleep 0.1; printf 'step 3\n'; sleep 0.1; echo done`,
			[][]string{{"step 1"}, {"step 2"}, {"step 3"}, {"step 3", "done"}}},
		{"a \\r before a \\n leaves the line as it was", `printf 'step 1\r'; sleep 0.1; printf '\nnext\n'`, [][]string{{"step 1"}, {"step 1", "next"}}},
		{"a bare \\r changes nothing", `printf '\r'; sleep 0.1; printf 'ten\r'; sleep 0.1; printf '\r'; sleep 0.1; printf 'twenty\n'`, [][]string{{"ten"}, {"twenty"}}},
		{"an empty line stays", `printf 'a\n'; sleep 0.1; printf '\n'; sleep 0.1; printf 'b\n'`, [][]string{{"a"}, {"a", ""}, {"a", "", "b"}}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, loaded(t), "l", "v", "enter")
			installScript = tt.script
			tm, cmd := m.Update(key("y"))
			tm, _ = tm.Update(cmd())
			var states [][]string
			for tm.(model).inst.done == nil {
				tm, _ = tm.Update(tm.(model).inst.next()())
				// The result brings the last lines too, which may have come
				// with it.
				if lines := tm.(model).inst.lines; len(states) == 0 || !slices.Equal(lines, states[len(states)-1]) {
					states = append(states, slices.Clone(lines))
				}
			}
			if !reflect.DeepEqual(states, tt.states) {
				t.Errorf("got  %q\nwant %q", states, tt.states)
			}
		})
	}
}

// stream shows the output as a terminal would, each write as soon as it is
// read, even a line that hasn't ended yet.
func TestStream(t *testing.T) {
	tests := []struct {
		id     string
		writes []string
		// screens are the output lines after each write, or nil for a write
		// that changes nothing on screen.
		screens [][]string
	}{
		{"a bar drawn after its \\r shows as soon as it is drawn", []string{"downloading\n", "\r[#   ] 10%", "\r[##  ] 20%", "\n", "done\n"},
			[][]string{{"downloading"}, {"downloading", "[#   ] 10%"}, {"downloading", "[##  ] 20%"}, nil, {"downloading", "[##  ] 20%", "done"}}},
		{"a line written in parts shows as it grows", []string{"fetch", "ing", "\n"}, [][]string{{"fetch"}, {"fetching"}, nil}},
		{"a bar drawn before its \\r redraws its line", []string{"step 1\r", "step 2\r", "step 3\n", "done\n"},
			[][]string{{"step 1"}, {"step 2"}, {"step 3"}, {"step 3", "done"}}},
		{"a \\r before a \\n leaves the line as it was", []string{"step 1\r", "\n", "next\n"}, [][]string{{"step 1"}, nil, {"step 1", "next"}}},
		{"a bare \\r changes nothing", []string{"\r", "ten\r", "\r", "twenty\n"}, [][]string{nil, {"ten"}, nil, {"twenty"}}},
		{"an empty line stays", []string{"a\n", "\n", "b\n"}, [][]string{{"a"}, {"a", ""}, {"a", "", "b"}}},
		{"styles and control bytes go", []string{"\x1b[32mgreen\x1b[0m\a\n"}, [][]string{{"green"}}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			in := &installing{changed: make(chan struct{}, 1)}
			r, w := io.Pipe()
			ended := make(chan struct{})
			go func() {
				in.stream(r)
				close(ended)
			}()
			for i, s := range tt.writes {
				w.Write([]byte(s))
				if tt.screens[i] == nil {
					select {
					case <-in.changed:
						t.Errorf("%q changed the screen to %q", s, in.screen())
					case <-time.After(50 * time.Millisecond):
					}
					continue
				}
				select {
				case <-in.changed:
					if got := in.screen(); !slices.Equal(got, tt.screens[i]) {
						t.Errorf("after %q the screen is %q, want %q", s, got, tt.screens[i])
					}
				case <-time.After(time.Second):
					t.Errorf("%q never showed, the screen is %q, want %q", s, in.screen(), tt.screens[i])
				}
			}
			w.Close()
			<-ended
		})
	}
}

// Once the command has exited, kho reads on until the output ends, goes
// quiet, has run on too long, or the install is cut short.
func TestQuiet(t *testing.T) {
	const grace, limit = 50 * time.Millisecond, 300 * time.Millisecond
	tests := []struct {
		id string
		// ended closes the output, writing keeps bytes coming, and cut cuts
		// the install short.
		ended, writing, cut bool
		// within is how long quiet may take, at least the first and less
		// than the second.
		within [2]time.Duration
	}{
		{id: "a child that writes on and on is let go at the limit", writing: true, within: [2]time.Duration{limit, 3 * limit}},
		{id: "and at once when the install is cut short", writing: true, cut: true, within: [2]time.Duration{0, grace}},
		{id: "output that went quiet is let go after the grace", within: [2]time.Duration{grace, limit}},
		{id: "output that ended is done at once", ended: true, within: [2]time.Duration{0, grace}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			read, cut, stop := make(chan struct{}), make(chan struct{}, 1), make(chan struct{})
			defer close(stop)
			var got counter
			if tt.ended {
				close(read)
			}
			if tt.cut {
				cut <- struct{}{}
			}
			if tt.writing {
				go func() {
					for {
						select {
						case <-stop:
							return
						case <-time.After(grace / 5):
							got.Write([]byte("tick\n"))
						}
					}
				}()
			}
			start := time.Now()
			quiet(read, cut, &got, grace, limit)
			if took := time.Since(start); took < tt.within[0] || took >= tt.within[1] {
				t.Errorf("took %v, want %v to %v", took, tt.within[0], tt.within[1])
			}
		})
	}
}

// The screen takes a while to draw each update, but the output is read as
// fast as the command writes it, so none is lost, on screen or in the
// history.
func TestSlowScreen(t *testing.T) {
	tests := []struct {
		id, script string
		// draw is how long the screen takes per update. never is a screen
		// that takes no update until the result.
		draw  time.Duration
		never bool
		// last are the popup's last lines, and logged how the history entry
		// ends.
		last   []string
		logged string
	}{
		{id: "a failing build's last error survives a slow screen", script: "seq 1 30000; echo LAST LINE; exit 1", draw: time.Millisecond,
			last: []string{"29999", "30000", "LAST LINE"}, logged: "exit status 1: ...29999\n30000\nLAST LINE\n"},
		{id: "even one that only takes the result", script: "seq 1 30000; echo LAST LINE; exit 1", never: true,
			last: []string{"29999", "30000", "LAST LINE"}, logged: "exit status 1: ...29999\n30000\nLAST LINE\n"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, loaded(t), "l", "v", "enter")
			installScript = tt.script
			tm, cmd := m.Update(key("y"))
			tm, _ = tm.Update(cmd())
			if in := tm.(model).inst; tt.never {
				<-in.logged
				tm, _ = tm.Update(<-in.over)
			}
			for tm.(model).inst.done == nil {
				msg := tm.(model).inst.next()()
				time.Sleep(tt.draw)
				tm, _ = tm.Update(msg)
			}
			lines := tm.(model).inst.lines
			lines = lines[max(len(lines)-len(tt.last), 0):]
			es := tm.(model).log.Entries()
			logged := ""
			if len(es) == 1 {
				out := es[0].Output
				logged = es[0].Err + ": ..." + out[max(len(out)-len("29999\n30000\nLAST LINE\n"), 0):]
			}
			if !slices.Equal(lines, tt.last) || logged != tt.logged {
				t.Errorf("popup ends %q, logged %q (%d entries), want %q, %q", lines, logged, len(es), tt.last, tt.logged)
			}
		})
	}
}

// A signal, or the terminal closing, ends kho without a key press, so an
// install still running is stopped and logged before kho is gone.
func TestSignal(t *testing.T) {
	tests := []struct {
		id, script string
		// unseen starts the install without the screen hearing of it, as
		// when a signal comes right after y.
		unseen bool
		// crash runs a screen that panics.
		crash bool
		// patience is how long kho waits on an interrupted install before
		// it kills it; 0 leaves kho through serve, as a hangup does.
		patience time.Duration
		// late asks for an install once kho has left.
		late   bool
		said   string
		ran    []string
		logged []string
		err    error
	}{
		{id: "an install asked for once kho is leaving never starts", late: true, err: ErrHangup},
		{id: "a signal mid-install stops it and logs it before kho leaves", script: "echo started; sleep 30", said: "kho: stopping brew upgrade anvil\n",
			ran: []string{"brew upgrade anvil"}, logged: []string{"brew upgrade anvil: signal: interrupt"}, err: ErrHangup},
		{id: "so does one that comes before the screen heard the install started", script: "echo started; sleep 30", unseen: true, said: "kho: stopping brew upgrade anvil\n",
			ran: []string{"brew upgrade anvil"}, logged: []string{"brew upgrade anvil: signal: interrupt"}, err: ErrHangup},
		{id: "a crash in the screen comes back as an error", crash: true, err: tea.ErrProgramPanic},
		{id: "one that ignores the interrupt is killed once kho runs out of patience", script: "trap '' INT; echo started; sleep 30", patience: 50 * time.Millisecond,
			ran: []string{"brew upgrade anvil"}, logged: []string{"brew upgrade anvil: signal: killed"}},
		{id: "and so is a child out of reach that keeps writing", script: "trap '' INT; echo started; perl -e 'setpgrp(0,0); exec @ARGV' sh -c 'while :; do echo tick; sleep 0.3; done' & echo $! > {pids}; sleep 30",
			patience: 50 * time.Millisecond, ran: []string{"brew upgrade anvil"}, logged: []string{"brew upgrade anvil: signal: killed"}},
		{id: "with nothing running a hangup still says it was one", err: ErrHangup},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			pids := filepath.Join(t.TempDir(), "pids")
			t.Cleanup(func() { reap(pids) })
			if tt.script != "" {
				installScript = strings.ReplaceAll(tt.script, "{pids}", pids)
				m = press(t, m, "l", "v", "enter")
				tm, cmd := m.Update(key("y"))
				msg := cmd()
				if !tt.unseen {
					tm, _ = tm.Update(msg)
					tm, _ = tm.Update(tm.(model).inst.next()())
					m = tm.(model)
				}
			}
			var said bytes.Buffer
			var err error
			switch {
			case tt.patience > 0:
				m.inst.finish(tt.patience)
			case tt.crash:
				err = serve(panics{}, make(chan os.Signal, 1), &said, tea.WithInput(nil), tea.WithOutput(io.Discard))
			default:
				sigs := make(chan os.Signal, 1)
				sigs <- syscall.SIGHUP
				err = serve(m, sigs, &said, tea.WithInput(nil), tea.WithOutput(io.Discard))
			}
			if tt.late {
				if msg := startInstall("⬆ Upgrade anvil", exec.Command("brew", "upgrade", "anvil"), m.log, installedMsg{provider: "brew", name: "anvil", version: "v0.2.94"})(); msg != nil {
					t.Errorf("an install started as kho left: %T", msg)
				}
			}
			var logged []string
			for _, e := range m.log.Entries() {
				if e.Kind == history.Change {
					logged = append(logged, strings.Join(e.Command, " ")+": "+e.Err)
				}
			}
			if said.String() != tt.said || !slices.Equal(ran, tt.ran) || !slices.Equal(logged, tt.logged) || !errors.Is(err, tt.err) || (err == nil) != (tt.err == nil) {
				t.Errorf("said %q, ran %q, logged %q, err %v, want %q, %q, %q, %v", said.String(), ran, logged, err, tt.said, tt.ran, tt.logged, tt.err)
			}
		})
	}
}

// kho listens for these signals for as long as it runs; one it didn't hear
// would kill this test.
func TestListen(t *testing.T) {
	sigs := listen()
	defer signal.Stop(sigs)
	tests := []struct {
		id  string
		sig syscall.Signal
	}{
		{"a closed terminal's hangup", syscall.SIGHUP},
		{"a termination", syscall.SIGTERM},
		{"an interrupt", syscall.SIGINT},
		{"a second hangup, after the first was heard", syscall.SIGHUP},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			syscall.Kill(os.Getpid(), tt.sig)
			select {
			case got := <-sigs:
				if got != tt.sig {
					t.Errorf("heard %v, want %v", got, tt.sig)
				}
			case <-time.After(time.Second):
				t.Errorf("%v never came", tt.sig)
			}
		})
	}
}

// panics is a screen that crashes on the first message.
type panics struct{}

func (panics) Init() tea.Cmd                       { return nil }
func (panics) Update(tea.Msg) (tea.Model, tea.Cmd) { panic("boom") }
func (panics) View() tea.View                      { return tea.NewView("") }

// Tabs line columns up the way a terminal does, at every 8th column.
func TestExpandTabs(t *testing.T) {
	tests := []struct{ id, in, want string }{
		{"a tab after text goes to the next stop", "ab\tcd", "ab      cd"},
		{"columns stay lined up", "name\tversion\nanvil-cli\t0.2.89", "name    version\nanvil-cli       0.2.89"},
		{"a leading tab is a whole stop", "\tgo: missing module", "        go: missing module"},
		{"text that ends on a stop gets a whole one more", "abcdefgh\tz", "abcdefgh        z"},
		{"a wide character takes two columns", "✨\tz", "✨      z"},
		{"no tab, no change", "plain", "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := expandTabs(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// A box laid over a line must keep the line's width even when its edge cuts a
// wide character in half, or everything after it shifts by a column.
func TestOverlay(t *testing.T) {
	tests := []struct {
		id   string
		base string
		x, w int
		want string
	}{
		{"left edge through a wide character", "ab✨cdef", 3, 2, "ab XYdef"},
		{"right edge through a wide character", "ab✨cdef", 1, 2, "aXY cdef"},
		{"no wide character in the way", "abcdef", 2, 2, "abXYef"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := ansi.Strip(overlay(tt.base, "XY", tt.x, 0, tt.w)); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	m := loaded(t)
	installScript = "echo fetched"
	m = press(t, m, "l", "v", "enter", "y")
	for width := 100; width <= 120; width++ {
		m = update(t, m, tea.WindowSizeMsg{Width: width, Height: 30})
		for i, line := range strings.Split(m.View().Content, "\n") {
			if w := ansi.StringWidth(line); w != width {
				t.Errorf("at %d wide, line %d is %d wide: %q", width, i, w, ansi.Strip(line))
			}
		}
	}
}

// The Security tab's list says what osv.dev knows about the package, or why
// it doesn't know yet.
func TestSecurityTab(t *testing.T) {
	tests := []struct {
		id, scan, pkg string
		want          []string
	}{
		{id: "a failed check says so", scan: "failed", pkg: "tidyup", want: []string{"", "security check failed: osv.dev answered 503", "R checks again."}},
		{id: "one still out is still checking", scan: "pending", pkg: "tidyup", want: []string{"", "⣾ checking osv.dev…"}},
		{id: "a source osv.dev has no data for", pkg: "anvil", want: []string{"", "🛡 OSV has no data for brew,", "so kho can't check this one yet."}},
		{id: "a clean package says when it was checked", pkg: "inkwell", want: []string{"", "✓ No known advisories for 9.0.2", "checked just now on osv.dev"}},
		{id: "one with advisories in its dependencies lists them", pkg: "tidyup", want: []string{"SEV ID FIX",
			"HIGH GO-TEST-0001 ≥ 0.52.0 via example.org/net@v0.50.0",
			"MED GO-TEST-0003 no fix yet via example.org/crypto@v0.20.0",
			"LOW GO-TEST-0002 ≥ 0.21.0 via example.org/crypto@v0.20.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, withDeps(t, tt.scan), pick(tt.pkg, "a")...)
			var got []string
			for _, l := range m.topView(m.layout().sideW - 2) {
				got = append(got, strings.Join(strings.Fields(ansi.Strip(l.text)), " "))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// The Info tab lists the selected package's dependencies, flagging those with
// advisories.
func TestDependencyList(t *testing.T) {
	upgraded := provider.Package{Source: "go", Name: "tidyup", Version: "v1.3.0", Latest: "v1.3.0", Origin: "example.com/tidyup",
		Deps: []provider.Dep{{Name: "example.org/text", Version: "v0.31.0"}}}
	// brew lists again after an install with anvil's openssl@4 moved on,
	// and gust's newest version too, while their own versions stay.
	brew := slices.Clone(fakes(t)[0].(fake).pkgs)
	brew[0].Deps = []provider.Dep{{Name: "openssl@4", Version: "4.2.0", Direct: true}, {Name: "ca-certificates", Version: "2026-10-20"}}
	brew[2].Latest = "1.27.3"
	relisted := []tea.Msg{installedMsg{provider: "brew", name: "openssl@4", version: "4.2.0"}, listedMsg{"brew", brew, nil}}
	tests := []struct {
		id   string
		keys []string
		msgs []tea.Msg
		// top reads the top half, as the Versions tab lists them there.
		top  bool
		want []string
	}{
		{id: "after an install the list is the new version's", keys: pick("tidyup"),
			msgs: []tea.Msg{installedMsg{provider: "go", name: "tidyup", version: "v1.3.0"}, listedMsg{"go", []provider.Package{upgraded}, nil}},
			want: []string{" · example.org/text   v0.31.0"}},
		{id: "and a dependency upgraded on its own shows its new version", keys: pick("anvil"), msgs: relisted,
			want: []string{" • openssl@4 4.2.0", " · ca-certificates 2026-10-20"}},
		{id: "a newer version a listing brings is offered", keys: pick("gust", "v"), msgs: relisted, top: true,
			want: []string{"VERSION DATE NOTES SECURITY", "1.27.3"}},
		{id: "the list flags the dependencies with advisories", keys: pick("tidyup"), want: []string{
			" · example.org/text   v0.30.0",
			" ⚠ example.org/net    v0.50.0 1 vuln",
			" ⚠ example.org/crypto v0.20.0 2 vuln",
			" · example.org/local  (devel)",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, withDeps(t, ""), tt.keys...)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			view := m.bottomView
			if tt.top {
				view = m.topView
			}
			var got []string
			for _, l := range view(m.layout().sideW - 2) {
				got = append(got, strings.Join(strings.Fields(ansi.Strip(l.text)), " "))
			}
			want := slices.Clone(tt.want)
			for i := range want {
				want[i] = strings.Join(strings.Fields(want[i]), " ")
			}
			if !slices.Equal(got, want) {
				t.Errorf("got  %q\nwant %q", got, want)
			}
		})
	}
}

// With more dependencies than the Info tab's bottom half shows, the keys and
// the wheel that scroll the detail move through the list.
func TestDependencyScroll(t *testing.T) {
	var deps []provider.Dep
	for i := range 30 {
		deps = append(deps, provider.Dep{Name: fmt.Sprintf("example.org/mod%02d", i), Version: "v1.0.0"})
	}
	sprawl := fake{name: "go", pkgs: []provider.Package{{Source: "go", Name: "sprawl", Version: "v1.0.0", Origin: "example.com/sprawl", Deps: deps}}}
	ctrl := func(r rune) tea.Msg { return tea.KeyPressMsg{Code: r, Mod: tea.ModCtrl} }
	repeat := func(n int, msgs ...tea.Msg) []tea.Msg { return slices.Repeat(msgs, n) }
	l := loaded(t).layout()
	if l.bottomRows != 17 {
		t.Fatalf("the rows below assume the list shows 17 dependencies, it shows %d", l.bottomRows)
	}
	wheel := tea.MouseWheelMsg{X: l.sideX + 5, Y: l.top + 1 + l.topRows + 3, Button: tea.MouseWheelDown}
	tests := []struct {
		id             string
		keys           []string
		msgs           []tea.Msg
		cursor, offset int
	}{
		{id: "J moves the dependency cursor", keys: pick("sprawl"), msgs: repeat(20, key("J")), cursor: 20, offset: 4},
		{id: "K moves it back", keys: pick("sprawl"), msgs: append(repeat(20, key("J")), repeat(5, key("K"))...), cursor: 15, offset: 4},
		{id: "ctrl+d moves it half a page", keys: pick("sprawl"), msgs: repeat(3, ctrl('d')), cursor: 24, offset: 8},
		{id: "ctrl+u moves it back", keys: pick("sprawl"), msgs: append(repeat(3, ctrl('d')), ctrl('u')), cursor: 16, offset: 8},
		{id: "the wheel over the list moves it", keys: pick("sprawl"), msgs: repeat(20, wheel), cursor: 20, offset: 4},
		{id: "J works from the package list too", keys: []string{"/", "s", "p", "r", "a", "w", "l", "enter"}, msgs: repeat(20, key("J")), cursor: 20, offset: 4},
		{id: "and stops at the last one", keys: pick("sprawl"), msgs: repeat(40, key("J")), cursor: 29, offset: 13},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			m.providers = append(m.providers, sprawl)
			m = update(t, m, listedMsg{"go", sprawl.pkgs, nil})
			m = press(t, m, tt.keys...)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			if m.depCursor != tt.cursor || m.bodyOffset != tt.offset {
				t.Errorf("cursor %d, offset %d, want %d, %d", m.depCursor, m.bodyOffset, tt.cursor, tt.offset)
			}
		})
	}
}

// TestFooter reads the key hints under the panels, which change with what
// has focus and what is open.
func TestFooter(t *testing.T) {
	tests := []struct {
		id   string
		keys []string
		want string
	}{
		{"the Info tab says how to open a dependency", pick("tidyup"), "↑↓ select  tab panel  [ ] tabs  enter its advisories  D remove  i v a tabs  s sort  f status  / filter  w home  ? help"},
		{"the Links tab offers every agent", pick("pathmaker", "5"), "↑↓ select  tab panel  [ ] tabs  enter link or unlink  D remove  i v a tabs  s sort  f status  / filter  w home  A all agents  ? help"},
		{"and after A, the installed ones again", pick("pathmaker", "5", "A"), "↑↓ select  tab panel  [ ] tabs  enter link or unlink  D remove  i v a tabs  s sort  f status  / filter  w home  A installed only  ? help"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			lines := strings.Split(screen(press(t, withDeps(t, ""), tt.keys...)), "\n")
			if got := strings.TrimSpace(lines[len(lines)-1]); got != tt.want {
				t.Errorf("footer %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChrome(t *testing.T) {
	for _, size := range [][2]int{{100, 30}, {160, 40}, {220, 50}} {
		m := update(t, loaded(t), tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		raw := strings.Split(m.View().Content, "\n")
		lines := strings.Split(screen(m), "\n")
		if len(lines) != size[1] {
			t.Fatalf("at %v the screen has %d lines", size, len(lines))
		}
		if rule := lines[len(lines)-2]; rule != strings.Repeat("─", size[0]) {
			t.Errorf("at %v the line above the keys is %q", size, rule)
		}
		if !strings.Contains(lines[len(lines)-3], "packages") || !strings.Contains(lines[len(lines)-1], "? help") {
			t.Errorf("at %v the stats and keys are not around the rule:\n%s", size, strings.Join(lines[len(lines)-3:], "\n"))
		}
		if !strings.Contains(raw[0], "kho") {
			t.Errorf("the logo's letters are styled one by one: %q", raw[0])
		}
	}
}

// withDeps adds a go binary with a clean dependency, one with an advisory, one
// with two and one with no release version, and a uv tool whose dependencies
// kho never asks osv.dev about. scan is how osv.dev answers for them:
// "" answers, "failed" fails, and "pending" hasn't come back yet.
func withDeps(t *testing.T, scan string) model {
	m := loaded(t)
	loop := vuln.Advisory{ID: "GO-TEST-0001", Summary: "Header parsing can loop forever", Severity: "HIGH", Package: "example.org/net",
		Details: "A crafted header makes the parser loop.", Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "0.52.0"}}}
	leak := vuln.Advisory{ID: "GO-TEST-0002", Summary: "Keys leak through timing", Severity: "LOW", Package: "example.org/crypto",
		Details: "Comparing keys takes longer when more of them match.", Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "0.21.0"}}}
	spill := vuln.Advisory{ID: "GO-TEST-0003", Summary: "A short read panics", Severity: "MODERATE", Package: "example.org/crypto",
		Details: "A truncated block makes the reader panic.", Ranges: []vuln.Range{{Introduced: "0"}}}
	scanOSV = func(_ context.Context, qs []vuln.Query, _ map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
		if scan == "failed" {
			return nil, nil, errors.New("osv.dev answered 503")
		}
		hits := map[string][]string{}
		for _, q := range qs {
			hits[q.Key()] = nil
			switch q.Name {
			case loop.Package:
				hits[q.Key()] = []string{loop.ID}
			case leak.Package:
				hits[q.Key()] = []string{leak.ID, spill.ID}
			}
		}
		return hits, map[string]vuln.Advisory{loop.ID: loop, leak.ID: leak, spill.ID: spill}, nil
	}
	tidy := fake{name: "go", pkgs: []provider.Package{{Source: "go", Name: "tidyup", Version: "v1.2.0", Latest: "v1.2.0", Origin: "example.com/tidyup",
		Deps: []provider.Dep{{Name: "example.org/text", Version: "v0.30.0"}, {Name: "example.org/net", Version: "v0.50.0"},
			{Name: "example.org/crypto", Version: "v0.20.0"}, {Name: "example.org/local", Version: "(devel)"}}}}}
	quill := fake{name: "uv", pkgs: []provider.Package{{Source: "uv", Name: "quill", Version: "2.4.0", Latest: "2.4.0",
		Deps: []provider.Dep{{Name: "inkpot", Version: "3.1.0"}}}}}
	for _, f := range []fake{tidy, quill} {
		m.providers = append(m.providers, f)
		if scan == "pending" {
			tm, _ := m.Update(listedMsg{f.name, f.pkgs, nil})
			m = tm.(model)
			continue
		}
		m = update(t, m, listedMsg{f.name, f.pkgs, nil})
		m = update(t, m, checkedMsg{f.name, f.pkgs, nil})
	}
	return m
}

// pick filters the packages down to name, moves to the sidebar, then presses
// keys.
func pick(name string, keys ...string) []string {
	ks := []string{"/"}
	for _, r := range name {
		ks = append(ks, string(r))
	}
	return append(append(ks, "enter", "l"), keys...)
}

// depPopupLines is the dependency popup's title, then its lines as drawn.
func depPopupLines(m model) []string {
	if m.depPop == nil {
		return nil
	}
	out := []string{ansi.Strip(m.depPopTitle())}
	for _, l := range m.depPopView() {
		out = append(out, strings.TrimRight(ansi.Strip(l.text), " "))
	}
	return out
}

func TestDependencyPopup(t *testing.T) {
	sep := " " + strings.Repeat("─", 96)
	netAdvisory := []string{"◆ example.org/net v0.50.0 · 1 advisory",
		" GO-TEST-0001",
		"  HIGH  Header parsing can loop forever",
		"",
		" affects   v0.50.0",
		" fixed in  0.52.0",
		" details   https://osv.dev/vulnerability/GO-TEST-0001",
		"",
		"  A crafted header makes the parser loop.",
	}
	cryptoAdvisories := []string{"◆ example.org/crypto v0.20.0 · 2 advisories",
		" GO-TEST-0003",
		"  MED   A short read panics",
		"",
		" affects   v0.20.0",
		" fixed in  no fix published yet",
		" details   https://osv.dev/vulnerability/GO-TEST-0003",
		"",
		"  A truncated block makes the reader panic.",
		"",
		sep,
		"",
		" GO-TEST-0002",
		"  LOW   Keys leak through timing",
		"",
		" affects   v0.20.0",
		" fixed in  0.21.0",
		" details   https://osv.dev/vulnerability/GO-TEST-0002",
		"",
		"  Comparing keys takes longer when more of them match.",
	}
	// short leaves the popup 13 rows for its text, fewer than the 19 the two
	// advisories take.
	short := []tea.Msg{tea.WindowSizeMsg{Width: 160, Height: 20}}
	crypto := func(keys ...string) []string { return pick("tidyup", append([]string{"j", "j", "enter"}, keys...)...) }
	text := popupText(loaded(t).depRect())
	mouse := func(kind string, x, y int) tea.Msg {
		ev := tea.Mouse{X: text.x + x, Y: text.y + y, Button: tea.MouseLeft}
		return map[string]tea.Msg{"click": tea.MouseClickMsg(ev), "drag": tea.MouseMotionMsg(ev), "release": tea.MouseReleaseMsg(ev), "wheel": tea.MouseWheelMsg{X: ev.X, Y: ev.Y, Button: tea.MouseWheelDown}}[kind]
	}
	tests := []struct {
		id, scan string
		msgs     []tea.Msg
		keys     []string
		// after are messages that arrive once the popup is open.
		after  []tea.Msg
		text   []string
		top    int
		copied []string
		opened []string
	}{
		{id: "a listing that adds rows ahead leaves the popup on its package", keys: pick("tidyup", "j", "enter"),
			after: []tea.Msg{listedMsg{"brew", []provider.Package{{Source: "brew", Name: "tidyup", Version: "3.0.0"}}, nil}}, text: netAdvisory},
		{id: "so does one that drops the package", keys: pick("tidyup", "j", "enter"), after: []tea.Msg{listedMsg{"go", nil, nil}}, text: netAdvisory},
		{id: "a uv tool's dependency, never sent to osv.dev, isn't called clean", keys: pick("quill", "enter"),
			text: []string{"◆ inkpot 3.1.0", "", " kho doesn't check uv dependencies on osv.dev, so inkpot isn't checked."}},
		{id: "a dependency osv.dev hasn't answered for is still being checked", scan: "pending", keys: pick("tidyup", "j", "enter"),
			text: []string{"◆ example.org/net v0.50.0", "", " ⣾ checking osv.dev…"}},
		{id: "a lookup that failed says so", scan: "failed", keys: pick("tidyup", "j", "enter"),
			text: []string{"◆ example.org/net v0.50.0", "", " security check failed: osv.dev answered 503", " R checks again."}},
		{id: "a dependency with no release version can't be checked", keys: pick("tidyup", "j", "j", "j", "enter"),
			text: []string{"◆ example.org/local (devel)", "", " example.org/local has no release version to check on osv.dev."}},
		{id: "the advisories are the shown version's, not another version's", keys: pick("tidyup", "j", "enter"),
			msgs: []tea.Msg{depsMsg{"go\x00tidyup\x00v1.2.0", []provider.Dep{{Name: "example.org/text", Version: "v0.30.0"}, {Name: "example.org/net", Version: "v0.53.0"}}, nil}},
			text: []string{"◆ example.org/net v0.53.0", "", " example.org/net isn't checked yet.", " R checks again."}},
		{id: "OSV has no data for a brew dependency", keys: pick("anvil", "enter"),
			text: []string{"◆ openssl@4 4.1.0", "", " OSV has no data for brew, so kho can't check openssl@4."}},
		{id: "a checked dependency with no advisories says so", keys: pick("tidyup", "enter"),
			text: []string{"◆ example.org/text v0.30.0", "", " ✓ No known advisories for example.org/text v0.30.0"}},
		{id: "enter opens a dependency's advisory", keys: pick("tidyup", "j", "enter"), text: netAdvisory},
		{id: "two advisories have a line between them", keys: crypto(), text: cryptoAdvisories},
		{id: "j scrolls a popup taller than the screen", msgs: short, keys: crypto("j", "j", "j"), text: cryptoAdvisories, top: 3},
		{id: "k scrolls it back", msgs: short, keys: crypto("j", "j", "j", "k"), text: cryptoAdvisories, top: 2},
		{id: "scrolling stops at the last line", msgs: short, keys: crypto(slices.Repeat([]string{"j"}, 20)...), text: cryptoAdvisories, top: 6},
		{id: "and at the first", msgs: short, keys: crypto("j", "k", "k"), text: cryptoAdvisories},
		{id: "the wheel scrolls it", msgs: short, keys: crypto(), after: []tea.Msg{mouse("wheel", 5, 5), mouse("wheel", 5, 5)}, text: cryptoAdvisories, top: 2},
		{id: "a click on its link opens it", keys: pick("tidyup", "j", "enter"), after: []tea.Msg{mouse("click", 20, 5), mouse("release", 20, 5)},
			text: netAdvisory, opened: []string{"https://osv.dev/vulnerability/GO-TEST-0001"}},
		{id: "a drag in it copies what it covers", keys: pick("tidyup", "j", "enter"), after: []tea.Msg{mouse("click", 0, 0), mouse("drag", 11, 0), mouse("release", 11, 0)},
			text: netAdvisory, copied: []string{" GO-TEST-000"}},
		{id: "a click outside closes it", keys: pick("tidyup", "j", "enter"), after: []tea.Msg{tea.MouseClickMsg{X: 1, Y: 1, Button: tea.MouseLeft}}},
		{id: "esc closes it", keys: pick("tidyup", "j", "enter", "esc")},
		{id: "c copies all of it", keys: pick("tidyup", "j", "enter", "c"), text: netAdvisory,
			copied: []string{strings.TrimSpace(strings.Join(netAdvisory[1:], "\n"))}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := withDeps(t, tt.scan)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			m = press(t, m, tt.keys...)
			for _, msg := range tt.after {
				m = update(t, m, msg)
			}
			top := 0
			if m.depPop != nil {
				top = m.depPop.top
			}
			if got := depPopupLines(m); !slices.Equal(got, tt.text) || top != tt.top || !slices.Equal(copied, tt.copied) || !slices.Equal(opened, tt.opened) {
				t.Errorf("popup at %d\n%s\ncopied %q, opened %q\nwant at %d\n%s\ncopied %q, opened %q",
					top, strings.Join(got, "\n"), copied, opened, tt.top, strings.Join(tt.text, "\n"), tt.copied, tt.opened)
			}
		})
	}
}

func TestRail(t *testing.T) {
	many := func(t *testing.T) model {
		var ps []provider.Provider
		for i := range 12 {
			ps = append(ps, fake{name: fmt.Sprintf("tool%02d", i)})
		}
		m := update(t, newModel(ps, ""), tea.WindowSizeMsg{Width: 120, Height: minHeight})
		return press(t, m, "tab", "tab")
	}
	railX := 2
	tests := []struct {
		id    string
		model func(*testing.T) model
		msgs  []tea.Msg
		check func(model) string
	}{
		{id: "the rail scrolls to keep the last row in view in a short terminal", model: many, msgs: []tea.Msg{key("G")},
			check: func(m model) string {
				if !strings.Contains(strings.Join(m.railBody(m.layout().bodyH-2), "\n"), "tool11") || m.curRow().name != "tool11" {
					return "tool11 is selected but not on screen"
				}
				return ""
			}},
		{id: "and back to the top", model: many, msgs: []tea.Msg{key("G"), key("g")},
			check: func(m model) string {
				if !strings.Contains(strings.Join(m.railBody(m.layout().bodyH-2), "\n"), "All") || m.rail != 0 {
					return "All is not back on screen"
				}
				return ""
			}},
		{id: "a click below the last row selects nothing", model: loaded,
			msgs: []tea.Msg{tea.MouseClickMsg{X: railX, Y: 20, Button: tea.MouseLeft}},
			check: func(m model) string {
				if m.rail != 0 {
					return fmt.Sprintf("rail moved to %q", m.curRow().name)
				}
				return ""
			}},
		{id: "the rail is headed Machine", model: loaded,
			check: func(m model) string {
				if !strings.Contains(screen(m), "💻 Machine") {
					return "no Machine header"
				}
				return ""
			}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := tt.model(t)
			for _, msg := range tt.msgs {
				m = update(t, m, msg)
			}
			if why := tt.check(m); why != "" {
				t.Error(why)
			}
		})
	}
}

func TestHiddenDependencies(t *testing.T) {
	m := loaded(t)
	cobalt := provider.Package{Source: "brew", Name: "cobalt"}
	if slices.Contains(names(m), "cobalt") {
		t.Fatal("a clean dependency shows with deps hidden")
	}
	m.vulns[pkgKey(cobalt)] = []vuln.Advisory{redos}
	if !slices.Contains(names(m), "cobalt") {
		t.Error("a vulnerable dependency is hidden with deps hidden")
	}
}

// withProject is the loaded model opened on a made-up project, with its
// scan already back unless pending.
func withProject(t *testing.T, scan project.Scan, pending bool) model {
	m := loaded(t)
	watchEvery = time.Millisecond
	findProject = func(context.Context, string) (project.Scan, error) { return scan, nil }
	projectLatest = func(_ context.Context, pkgs []provider.Package) []provider.Package {
		for i := range pkgs {
			if !pkgs[i].Dependency {
				pkgs[i].Latest = "9.9.9"
				pkgs[i].Outdated = true
			}
		}
		return pkgs
	}
	m.dir, m.projBusy = "/work/app", projReading
	if pending {
		return m
	}
	return update(t, m, m.findCmd()())
}

func TestProject(t *testing.T) {
	npm := func(name, version string, dep, dev bool, via ...string) provider.Package {
		return provider.Package{Source: "npm", Name: name, Version: version, Dependency: dep, Dev: dev, Via: via, Lockfile: "package-lock.json"}
	}
	one := project.Scan{Root: "/work/app", Projects: []project.Project{{Lockfiles: []project.Lockfile{
		{Path: "package-lock.json", Manager: "npm", Packages: []provider.Package{
			npm("left-trim", "1.0.2", false, false),
			npm("bramble", "22.12.0", true, false, "left-trim"),
			npm("clean-dep", "1.0.0", true, false, "left-trim"),
			npm("test-kit", "3.0.0", false, true),
		}},
		{Path: "composer.json", Manager: "composer", Missing: "no lockfile, versions unknown. Run composer install to create one"},
	}}}}
	several := project.Scan{Root: "/work/code", Projects: []project.Project{
		{Dir: "api", Lockfiles: []project.Lockfile{{Path: "api/go.mod", Manager: "go"}}},
		{Dir: "web", Lockfiles: []project.Lockfile{{Path: "web/package-lock.json", Manager: "npm"}}},
	}}
	rail := func(m model) string { return ansi.Strip(strings.Join(m.railBody(m.layout().bodyH-2), "\n")) }
	header := func(m model) model {
		m.focus = focusRail
		return press(t, m, "G")
	}
	tests := []struct {
		id    string
		model func(*testing.T) model
		check func(model) string
	}{
		{"while the lockfiles are read, the project can't be selected and Machine stays selected", func(t *testing.T) model { return withProject(t, one, true) },
			func(m model) string {
				m.focus = focusRail
				m = press(t, m, "G")
				if !strings.Contains(rail(m), "── Project ──") || !strings.Contains(rail(m), "reading lockfiles") || m.curRow().kind != rowProvider {
					return fmt.Sprintf("rail %q, selected %+v", rail(m), m.curRow())
				}
				return ""
			}},
		{"closed, the header still shows the project's risk", func(t *testing.T) model { return withProject(t, one, false) },
			func(m model) string {
				if !strings.Contains(rail(m), "── Project ──") || !strings.Contains(rail(m), "▸ 📁 app") || !strings.Contains(rail(m), "⚠1") || m.curRow().kind != rowAll {
					return fmt.Sprintf("rail %q", rail(m))
				}
				return ""
			}},
		{"a vulnerable dependency shows with deps hidden, a clean one doesn't", func(t *testing.T) model { return header(withProject(t, one, false)) },
			func(m model) string {
				if got := names(m); !slices.Contains(got, "bramble") || slices.Contains(got, "clean-dep") || !slices.Contains(got, "test-kit") {
					return fmt.Sprintf("rows %v", got)
				}
				if !strings.Contains(screen(m), "bramble via") || !strings.Contains(screen(m), "via       left-trim") {
					return "no via on the vulnerable dependency"
				}
				return ""
			}},
		{"p hides dev packages", func(t *testing.T) model { return press(t, header(withProject(t, one, false)), "p") },
			func(m model) string {
				if got := names(m); slices.Contains(got, "test-kit") || !strings.Contains(screen(m), "dev hidden") {
					return fmt.Sprintf("rows %v", got)
				}
				return ""
			}},
		{"the status bar counts the project while it is selected", func(t *testing.T) model { return header(withProject(t, one, false)) },
			func(m model) string {
				if !strings.Contains(screen(m), "4 in app") {
					return "status bar does not count the project"
				}
				return ""
			}},
		{"enter opens it with a row per lockfile, and a bare manifest says what to run", func(t *testing.T) model {
			return press(t, header(withProject(t, one, false)), "enter", "G")
		}, func(m model) string {
			if !strings.Contains(rail(m), "▾ 📁 app") || m.curRow().name != "composer" || !strings.Contains(screen(m), "composer.json: no lockfile, versions unknown. Run composer") {
				return fmt.Sprintf("rail %q, selected %+v", rail(m), m.curRow())
			}
			return ""
		}},
		{"enter on the header closes it again", func(t *testing.T) model {
			return press(t, header(withProject(t, one, false)), "enter", "G", "k", "k", "enter")
		}, func(m model) string {
			if m.projOpen || strings.Contains(rail(m), "composer") {
				return fmt.Sprintf("rail %q", rail(m))
			}
			return ""
		}},
		{"the fix command shows in Security and c copies it", func(t *testing.T) model {
			m := header(withProject(t, one, false))
			m.focus = focusTable
			for names(m)[m.cursor] != "bramble" {
				m = press(t, m, "j")
			}
			return press(t, m, "a", "c")
		}, func(m model) string {
			if !strings.Contains(screen(m), "npm update bramble") || !slices.Contains(copied, "npm update bramble") {
				return fmt.Sprintf("copied %v", copied)
			}
			return ""
		}},
		{"a direct package lists what it pulls in from the lockfile", func(t *testing.T) model {
			m := header(withProject(t, one, false))
			m.focus = focusTable
			for names(m)[m.cursor] != "left-trim" {
				m = press(t, m, "j")
			}
			return m
		}, func(m model) string {
			deps := m.deps[cacheKey(provider.Package{Source: "npm", Name: "left-trim", Version: "1.0.2", Lockfile: "package-lock.json"})]
			if deps == nil || len(deps.val) != 2 || deps.val[0].Name != "bramble" || !deps.val[0].Direct {
				return fmt.Sprintf("deps %+v", deps)
			}
			return ""
		}},
		{"a rescan keeps the selected part selected, during and after", func(t *testing.T) model {
			m := press(t, header(withProject(t, one, false)), "enter", "G")
			tm, _ := m.Update(watchMsg{gen: m.projGen, changed: true})
			if busy := tm.(model); busy.curRow().key != "project:composer.json" {
				t.Errorf("while reading, %q is selected", busy.curRow().key)
			}
			return update(t, m, watchMsg{gen: m.projGen, changed: true})
		}, func(m model) string {
			if m.curRow().key != "project:composer.json" {
				return fmt.Sprintf("after the rescan, %q is selected", m.curRow().key)
			}
			return ""
		}},
		{"when a rescan drops a lockfile above it, the selection stays on its lockfile", func(t *testing.T) model {
			three := project.Scan{Root: "/work/app", Projects: []project.Project{{Lockfiles: []project.Lockfile{
				{Path: "Cargo.toml", Manager: "cargo", Missing: "no lockfile"},
				{Path: "composer.json", Manager: "composer", Missing: "no lockfile"},
				{Path: "package.json", Manager: "npm", Missing: "no lockfile"},
			}}}}
			m := press(t, header(withProject(t, three, false)), "enter", "G", "k")
			findProject = func(context.Context, string) (project.Scan, error) {
				return project.Scan{Root: "/work/app", Projects: []project.Project{{Lockfiles: three.Projects[0].Lockfiles[1:]}}}, nil
			}
			return update(t, m, watchMsg{gen: m.projGen, changed: true})
		}, func(m model) string {
			if m.curRow().key != "project:composer.json" {
				return fmt.Sprintf("selected %q", m.curRow().key)
			}
			return ""
		}},
		{"closing the project from a part selects its header", func(t *testing.T) model {
			m := press(t, header(withProject(t, one, false)), "enter", "G")
			m.projOpen = false
			return update(t, m, tickMsg{})
		}, func(m model) string {
			if m.curRow().kind != rowProject {
				return fmt.Sprintf("selected %+v", m.curRow())
			}
			return ""
		}},
		{"a package with no registry kho knows still loads its dependencies", func(t *testing.T) model {
			crate := project.Scan{Root: "/work/rs", Projects: []project.Project{{Lockfiles: []project.Lockfile{{Path: "Cargo.lock", Manager: "cargo",
				Packages: []provider.Package{{Source: "cargo", Name: "tinyhash", Version: "1.0.5", Lockfile: "Cargo.lock"}}}}}}}
			return header(withProject(t, crate, false))
		}, func(m model) string {
			if d := m.deps[cacheKey(provider.Package{Source: "cargo", Name: "tinyhash", Version: "1.0.5", Lockfile: "Cargo.lock"})]; d == nil || !d.done {
				return "dependencies never finish loading"
			}
			return ""
		}},
		{"a project folder with only a bare manifest shows its note", func(t *testing.T) model {
			notes := project.Scan{Root: "/work/code", Projects: []project.Project{
				{Dir: "api", Lockfiles: []project.Lockfile{{Path: "api/go.mod", Manager: "go", Packages: []provider.Package{{Source: "go", Name: "example.com/a", Origin: "example.com/a", Version: "v1.0.0", Lockfile: "api/go.mod"}}}}},
				{Dir: "web", Lockfiles: []project.Lockfile{{Path: "web/package.json", Manager: "npm", Missing: "no lockfile, versions unknown. Run npm install to create one"}}},
			}}
			return press(t, header(withProject(t, notes, false)), "enter", "G")
		}, func(m model) string {
			if !strings.Contains(rail(m), "web") || !strings.Contains(rail(m), "◌") || !strings.Contains(screen(m), "web/package.json: no lockfile") {
				return fmt.Sprintf("rail %q", rail(m))
			}
			return ""
		}},
		{"a failed scan names the folder kho was opened on", func(t *testing.T) model {
			m := loaded(t)
			findProject = func(context.Context, string) (project.Scan, error) { return project.Scan{}, errors.New("boom") }
			m.dir, m.projBusy = "/work/app", projReading
			return update(t, m, m.findCmd()())
		}, func(m model) string {
			if !strings.Contains(rail(m), "📁 app · boom") {
				return fmt.Sprintf("rail %q", rail(m))
			}
			return ""
		}},
		{"a project package's Versions footer offers no install", func(t *testing.T) model {
			m := header(withProject(t, one, false))
			m.focus = focusSide
			projectVersions = func(context.Context, provider.Package) ([]provider.Release, error) {
				return []provider.Release{{Version: "9.9.9"}}, nil
			}
			return press(t, m, "v")
		}, func(m model) string {
			if f := ansi.Strip(m.footer()); strings.Contains(f, "install it") || !strings.Contains(f, "kho doesn't change projects") {
				return fmt.Sprintf("footer %q", f)
			}
			return ""
		}},
		{"several projects get a row per folder", func(t *testing.T) model { return press(t, header(withProject(t, several, false)), "enter") },
			func(m model) string {
				if r := rail(m); !strings.Contains(r, "code · 2 projects") || !strings.Contains(r, "api") || !strings.Contains(r, "web") {
					return fmt.Sprintf("rail %q", r)
				}
				return ""
			}},
		{"a folder with no lockfiles says so and has nothing to select", func(t *testing.T) model { return header(withProject(t, project.Scan{Root: "/work/empty"}, false)) },
			func(m model) string {
				if !strings.Contains(rail(m), "empty · no lockfiles") || m.curRow().kind != rowProvider {
					return fmt.Sprintf("rail %q, selected %+v", rail(m), m.curRow())
				}
				return ""
			}},
		{"a changed lockfile is read again, and an answer for the older scan is dropped", func(t *testing.T) model {
			m := withProject(t, one, false)
			m = update(t, m, watchMsg{gen: m.projGen, changed: true})
			tm, _ := m.Update(projectMsg{gen: 0, scan: several})
			return tm.(model)
		}, func(m model) string {
			if m.projGen != 1 || m.proj.Root != "/work/app" {
				return fmt.Sprintf("gen %d, root %q", m.projGen, m.proj.Root)
			}
			return ""
		}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if why := tt.check(tt.model(t)); why != "" {
				t.Error(why)
			}
		})
	}
}

func TestProjectStaysInViewInAShortTerminal(t *testing.T) {
	var ps []provider.Provider
	for i := range 8 {
		ps = append(ps, fake{name: fmt.Sprintf("tool%d", i)})
	}
	m := update(t, newModel(ps, ""), tea.WindowSizeMsg{Width: 100, Height: minHeight})
	findProject = func(context.Context, string) (project.Scan, error) {
		return project.Scan{Root: "/work/app", Projects: []project.Project{{Lockfiles: []project.Lockfile{{Path: "go.mod", Manager: "go"}}}}}, nil
	}
	projectLatest = func(_ context.Context, p []provider.Package) []provider.Package { return p }
	m.dir, m.projBusy = "/work/app", projReading
	m = update(t, m, m.findCmd()())
	rail := ansi.Strip(strings.Join(m.railBody(m.layout().bodyH-2), "\n"))
	if !strings.Contains(rail, "📁 app") || !strings.Contains(rail, "All") {
		t.Errorf("the project or All is off screen:\n%s", rail)
	}
	m.focus = focusRail
	m = press(t, m, "G", "enter")
	rail = ansi.Strip(strings.Join(m.railBody(m.layout().bodyH-2), "\n"))
	if !strings.Contains(rail, "▾ 📁 app") || !strings.Contains(rail, "go") {
		t.Errorf("the open project is off screen:\n%s", rail)
	}
}

// With no homepage or repo, w opens the package's page on its registry,
// whichever tool put a Python package there.
func TestHomeURL(t *testing.T) {
	tests := []struct {
		id   string
		p    provider.Package
		want string
	}{
		{"a poetry package", provider.Package{Source: "poetry", Name: "quill"}, "https://pypi.org/project/quill/"},
		{"a pip package", provider.Package{Source: "pip", Name: "quill"}, "https://pypi.org/project/quill/"},
		{"a pipx tool", provider.Package{Source: "pipx", Name: "quill"}, "https://pypi.org/project/quill/"},
		{"its own homepage first", provider.Package{Source: "npm", Name: "lark", Homepage: "https://lark.example"}, "https://lark.example"},
		{"then its repo", provider.Package{Source: "npm", Name: "lark", Repo: "acme/lark"}, "https://github.com/acme/lark"},
		{"an npm package", provider.Package{Source: "npm", Name: "lark"}, "https://www.npmjs.com/package/lark"},
		{"a go binary", provider.Package{Source: "go", Name: "wren", Origin: "example.com/acme/wren"}, "https://pkg.go.dev/example.com/acme/wren"},
		{"a formula has none", provider.Package{Source: "brew", Name: "anvil"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := homeURL(tt.p); got != tt.want {
				t.Errorf("homeURL = %q, want %q", got, tt.want)
			}
		})
	}
}
