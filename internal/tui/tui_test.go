package tui

import (
	"bytes"
	"context"
	"errors"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/history"
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
func (f fake) Available() bool                                  { return true }
func (f fake) List(context.Context) ([]provider.Package, error) { return f.pkgs, f.err }
func (f fake) Latest(_ context.Context, p []provider.Package) ([]provider.Package, error) {
	return p, nil
}
func (f fake) Deps(_ context.Context, p provider.Package) ([]provider.Dep, error) { return p.Deps, nil }
func (f fake) Versions(_ context.Context, p provider.Package) ([]provider.Release, error) {
	return f.versions[p.Name], nil
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
		case depsMsg, versionsMsg, docMsg, openedMsg, scanMsg, historyMsg, auditMsg, installStartedMsg, outputMsg, installedMsg, linkedMsg:
			tm, cmd = tm.Update(msg)
			drain(cmd)
		}
	}
	drain(cmd)
	return tm.(model)
}

var opened, ran, copied, toggled []string

// installScript stands in for the package manager an install runs.
var installScript string

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
	installScript = "echo fetched"
	installProcess = func(c *exec.Cmd) *exec.Cmd {
		ran = append(ran, strings.Join(c.Args, " "))
		return exec.Command("sh", "-c", installScript)
	}
	runExec = func(c tea.ExecCommand, fn tea.ExecCallback) tea.Cmd {
		return func() tea.Msg {
			ran = append(ran, strings.Join(c.(*terminalRun).cmd.Args, " "))
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
	tests := []struct {
		id      string
		msgs    []tea.Msg
		rows    []string
		current string
		check   func(model) bool
		opened  []string
	}{
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
	m := update(t, loaded(t), tea.WindowSizeMsg{Width: 80, Height: 20})
	if s := screen(m); !strings.Contains(s, "kho needs at least 100x16, this terminal is 80x20.") {
		t.Errorf("small screen:\n%s", s)
	}
	m = update(t, m, tea.WindowSizeMsg{Width: 110, Height: 30})
	if s := screen(m); !strings.Contains(s, "LATEST") || !strings.Contains(s, "STATUS") || !strings.Contains(s, "↑ outdated") {
		t.Errorf("a split-pane width should keep every status visible:\n%s", s)
	}
	for _, size := range [][2]int{{100, 16}, {110, 30}, {220, 50}} {
		m = update(t, m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		lines := strings.Split(screen(m), "\n")
		if len(lines) != size[1] {
			t.Errorf("got %d lines at %v, want %d", len(lines), size, size[1])
		}
		for i, line := range lines {
			if w := ansi.StringWidth(line); w != size[0] && i > 0 && i < size[1]-1 {
				t.Errorf("line %d is %d wide at %v", i, w, size)
			}
		}
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
			Err: "exit status 1", Output: "boom: no matching distribution"})
		m.log.Add(history.Entry{At: clock.Add(2 * time.Minute), Kind: history.Change, Command: []string{"ln", "-s", "/h/.agents/skills/pathmaker", "/h/.cursor/skills/pathmaker"}})
		return m
	}
	tests := []struct {
		id     string
		keys   []string
		want   []string
		lacks  []string
		copied []string
	}{
		{id: "H lists every command, newest first", keys: []string{"H"}, want: []string{"🕘 History · 3", "ln -s /h/.agents", "pipx install --force", "brew info --json=v2 --installed", "1.3s", "⌨ ln", "change: kho changed the machine"}},
		{id: "f keeps the changes", keys: []string{"H", "f"}, want: []string{"🕘 History · 2 · ✎ Changes", "✎ Changes 2"}, lacks: []string{"brew info"}},
		{id: "f again keeps the failures", keys: []string{"H", "f", "f"}, want: []string{"✗ Failed 1", "✗ exit status 1", "boom: no matching distribution"}, lacks: []string{"ln -s"}},
		{id: "/ filters the commands", keys: []string{"H", "/", "b", "r", "e", "w", "enter"}, want: []string{"🕘 History · 1", "brew info"}, lacks: []string{"pipx install"}},
		{id: "c copies the selected command", keys: []string{"H", "j", "c"}, copied: []string{"pipx install --force bramble==26.10.1"}},
		{id: "esc goes back to the packages", keys: []string{"H", "esc"}, want: []string{"✨ Sources"}, lacks: []string{"🕘 History"}},
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
			if !reflect.DeepEqual(copied, tt.copied) {
				t.Errorf("copied %q, want %q", copied, tt.copied)
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
		{"a tall screen shows every key", 50, []tea.Msg{key("?"), key("j")}, 0, first + "|" + last, "", false},
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
	tests := []struct {
		id     string
		script string
		keys   []string
		ran    []string
		shows  []string
		hides  string
		open   bool
	}{
		{"output streams into a popup", "echo fetched anvil; echo poured", upgrade, []string{brew},
			[]string{"⬆ Upgrade anvil", "runs  brew upgrade anvil", "fetched anvil", "poured", "✓ done", "enter close"}, "", true},
		{"a failure says so and offers the terminal", "echo no space left; exit 3", upgrade, []string{brew},
			[]string{"no space left", "✗ exit status 3", "t run it in the terminal"}, "", true},
		{"t runs a failed install in the terminal", "exit 3", append(upgrade, "t"), []string{brew, brew}, nil, "✗ exit status 3", false},
		{"enter closes it once done", "echo fetched", append(upgrade, "enter"), []string{brew}, nil, "fetched", false},
		{"t does nothing after a success", "echo fetched", append(upgrade, "t"), []string{brew}, []string{"✓ done"}, "", true},
		{"a progress line keeps its last state", `printf 'step 1\rstep 2\n'`, upgrade, []string{brew}, []string{"step 2"}, "step 1", true},
		{"colors are dropped", `printf '\033[32mgreen\033[0m\n'`, upgrade, []string{brew}, []string{"green"}, "[32m", true},
		{"the command can't reach the terminal", `(exec 3</dev/tty) 2>/dev/null && echo has-tty || echo no-tty`, upgrade, []string{brew}, []string{"no-tty"}, "has-tty", true},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			installScript = tt.script
			m = press(t, m, tt.keys...)
			s := screen(m)
			if !reflect.DeepEqual(ran, tt.ran) {
				t.Errorf("ran %v, want %v", ran, tt.ran)
			}
			if (m.inst != nil) != tt.open {
				t.Errorf("popup open is %v, want %v", m.inst != nil, tt.open)
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

	m := loaded(t)
	installScript = "echo fetched; exit 3"
	m = press(t, m, upgrade...)
	if es := m.log.Entries(); len(es) != 1 || es[0].Kind != history.Change || strings.Join(es[0].Command, " ") != brew || es[0].Err != "exit status 3" || !strings.Contains(es[0].Output, "fetched") {
		t.Errorf("logged %+v", es)
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
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := loaded(t)
			installScript = tt.script
			m = press(t, m, "l", "v", "enter")
			tm, cmd := m.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
			tm, _ = tm.Update(cmd())
			tm, _ = tm.Update(tm.(model).inst.next()())
			if s := screen(tm.(model)); !strings.Contains(s, "started") || !strings.Contains(s, "ctrl+c stop it") {
				t.Fatalf("running popup:\n%s", s)
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
			if s := screen(m); !strings.Contains(s, "✗ "+tt.err) || strings.Contains(s, "finished") {
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

// withDeps adds a go binary whose second dependency has an advisory.
func withDeps(t *testing.T) model {
	m := loaded(t)
	loop := vuln.Advisory{ID: "GO-TEST-0001", Summary: "Header parsing can loop forever", Severity: "HIGH", Package: "example.org/net",
		Details: "A crafted header makes the parser loop.", Ranges: []vuln.Range{{Introduced: "0"}, {Fixed: "0.52.0"}}}
	scanOSV = func(_ context.Context, qs []vuln.Query, _ map[string]bool) (map[string][]string, map[string]vuln.Advisory, error) {
		hits := map[string][]string{}
		for _, q := range qs {
			hits[q.Key()] = nil
			if q.Name == loop.Package {
				hits[q.Key()] = []string{loop.ID}
			}
		}
		return hits, map[string]vuln.Advisory{loop.ID: loop}, nil
	}
	tidy := fake{name: "go", pkgs: []provider.Package{{Source: "go", Name: "tidyup", Version: "v1.2.0", Latest: "v1.2.0", Origin: "example.com/tidyup",
		Deps: []provider.Dep{{Name: "example.org/text", Version: "v0.30.0"}, {Name: "example.org/net", Version: "v0.50.0"}}}}}
	m.providers = append(m.providers, tidy)
	m = update(t, m, listedMsg{"go", tidy.pkgs, nil})
	m = update(t, m, checkedMsg{"go", tidy.pkgs, nil})
	return press(t, m, "/", "t", "i", "d", "y", "enter", "l")
}

func TestDependencyPopup(t *testing.T) {
	tests := []struct {
		id     string
		keys   []string
		open   bool
		shows  []string
		copied string
	}{
		{"enter opens the selected dependency's advisories", []string{"j", "enter"}, true,
			[]string{"◆ example.org/net v0.50.0", "GO-TEST-0001", "Header parsing can loop forever", "0.52.0", "A crafted header", "c copy all"}, ""},
		{"a clean dependency says so", []string{"enter"}, true, []string{"No known advisories for example.org/text v0.30.0"}, ""},
		{"esc closes it", []string{"j", "enter", "esc"}, false, nil, ""},
		{"c copies all of it", []string{"j", "enter", "c"}, true, nil, "GO-TEST-0001"},
		{"the Info footer says how to open one", nil, false, []string{"↑↓ dependency", "enter its advisories"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			m := press(t, withDeps(t), tt.keys...)
			s := screen(m)
			if (m.depPop != nil) != tt.open {
				t.Errorf("popup open is %v, want %v:\n%s", m.depPop != nil, tt.open, s)
			}
			for _, want := range tt.shows {
				if !strings.Contains(s, want) {
					t.Errorf("screen lacks %q:\n%s", want, s)
				}
			}
			if tt.copied != "" && (len(copied) != 1 || !strings.Contains(copied[0], tt.copied)) {
				t.Errorf("copied %q, want it to hold %q", copied, tt.copied)
			}
		})
	}

	m := press(t, withDeps(t), "j", "enter")
	x, y, _, _ := m.depRect()
	first := strings.TrimRight(ansi.Cut(ansi.Strip(m.depPopView()[0].text), 0, 12), " ")
	m = update(t, m, tea.MouseClickMsg{X: x + 1, Y: y + 2, Button: tea.MouseLeft})
	m = update(t, m, tea.MouseMotionMsg{X: x + 12, Y: y + 2, Button: tea.MouseLeft})
	m = update(t, m, tea.MouseReleaseMsg{X: x + 12, Y: y + 2, Button: tea.MouseLeft})
	if !reflect.DeepEqual(copied, []string{first}) || m.depPop == nil {
		t.Errorf("a drag in the popup copied %q, want %q, and the popup open", copied, first)
	}
	m = update(t, m, tea.MouseClickMsg{X: 1, Y: 1, Button: tea.MouseLeft})
	if m.depPop != nil {
		t.Error("a click outside the popup should close it")
	}
}
