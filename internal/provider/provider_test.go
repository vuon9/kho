package provider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vuon9/kho/internal/vuln"
)

func TestParseBrew(t *testing.T) {
	tests := []struct {
		id   string
		json string
		want []Package
	}{
		{
			id: "outdated formula installed on request",
			json: `{"formulae":[{"name":"anvil","tap":"homebrew/core","desc":"Run your build jobs locally","homepage":"https://anvil.example",
				"pinned":false,"outdated":true,"linked_keg":"0.2.89","revision":0,"versions":{"stable":"0.2.94"},
				"urls":{"stable":{"url":"https://github.com/example/anvil/archive/refs/tags/v0.2.94.tar.gz"}},
				"installed":[{"version":"0.2.89","installed_on_request":true,"runtime_dependencies":[
					{"full_name":"openssl@4","pkg_version":"4.1.0","declared_directly":true},
					{"full_name":"ca-certificates","pkg_version":"2026-10-20","declared_directly":false}]}]}],"casks":[]}`,
			want: []Package{{Source: "brew", Name: "anvil", Version: "0.2.89", Latest: "0.2.94", Outdated: true,
				Origin: "homebrew/core", Desc: "Run your build jobs locally", Homepage: "https://anvil.example", Repo: "example/anvil",
				Deps: []Dep{{Name: "openssl@4", Version: "4.1.0", Direct: true}, {Name: "ca-certificates", Version: "2026-10-20"}}}},
		},
		{
			id: "dependency with three kegs keeps every version",
			json: `{"formulae":[{"name":"libauth","tap":"homebrew/core","outdated":true,"linked_keg":"1.0.2","versions":{"stable":"1.0.3"},
				"installed":[{"version":"1.0.0"},{"version":"1.0.1"},{"version":"1.0.2"}]}],"casks":[]}`,
			want: []Package{{Source: "brew", Name: "libauth", Version: "1.0.2", Latest: "1.0.3", Outdated: true, Dependency: true,
				Versions: []string{"1.0.0", "1.0.1", "1.0.2"}, Origin: "homebrew/core"}},
		},
		{
			id: "revision is part of the latest version",
			json: `{"formulae":[{"name":"autobuild","pinned":true,"linked_keg":"1.18.1_1","revision":1,"versions":{"stable":"1.19"},
				"installed":[{"version":"1.18.1_1","installed_on_request":true}]}],"casks":[]}`,
			want: []Package{{Source: "brew", Name: "autobuild", Version: "1.18.1_1", Latest: "1.19_1", Pinned: true}},
		},
		{
			id: "unlinked keg falls back to newest installed",
			json: `{"formulae":[{"name":"python@3.12","linked_keg":null,"versions":{"stable":"3.12.9"},
				"installed":[{"version":"3.12.9","installed_on_request":true}]}],"casks":[]}`,
			want: []Package{{Source: "brew", Name: "python@3.12", Version: "3.12.9", Latest: "3.12.9"}},
		},
		{
			id: "self-updating cask",
			json: `{"formulae":[],"casks":[{"token":"focusbar","tap":"homebrew/cask","desc":"Tool to manage periodic breaks",
				"homepage":"https://focusbar.example/","version":"2.0.3","installed":"2.0.3","outdated":false,"auto_updates":true}]}`,
			want: []Package{{Source: "cask", Name: "focusbar", Version: "2.0.3", Latest: "2.0.3", Origin: "homebrew/cask",
				Desc: "Tool to manage periodic breaks", Homepage: "https://focusbar.example/", Note: "updates itself"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := parseBrew([]byte(tt.json))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseLists(t *testing.T) {
	tests := []struct {
		id    string
		parse func([]byte) ([]Package, error)
		in    string
		want  []Package
	}{
		{
			id:    "npm globals sorted by name",
			parse: parseNpmList,
			in: `{"name":"lib","dependencies":{"npm":{"version":"11.19.0"},"diffkit":{"version":"0.23.0","overridden":false,
				"dependencies":{"commander":{"version":"14.0.3"},"chokidar":{"version":"4.0.3"}}}}}`,
			want: []Package{
				{Source: "npm", Name: "diffkit", Version: "0.23.0", Origin: "npmjs.com",
					Deps: []Dep{{Name: "chokidar", Version: "4.0.3", Direct: true}, {Name: "commander", Version: "14.0.3", Direct: true}}},
				{Source: "npm", Name: "npm", Version: "11.19.0", Origin: "npmjs.com"},
			},
		},
		{
			id:    "pipx keeps its native pin",
			parse: parsePipx,
			in: `{"pipx_spec_version":"0.1","venvs":{"bramble":{"metadata":{"python_version":"Python 3.12.1",
				"main_package":{"package":"bramble","package_version":"22.12.0","pinned":true,"apps":["bramble","brambled"]}}}}}`,
			want: []Package{{Source: "pipx", Name: "bramble", Version: "22.12.0", Pinned: true, Origin: "pypi.org",
				Desc: "apps: bramble, brambled · Python 3.12.1"}},
		},
		{
			id:    "uv tools skip executable lines",
			parse: func(b []byte) ([]Package, error) { return parseUvList(string(b)), nil },
			in:    "ruff v0.15.2\n- ruff\nbramble v26.10.1\n- bramble\n- brambled\n",
			want: []Package{
				{Source: "uv", Name: "ruff", Version: "0.15.2", Origin: "pypi.org"},
				{Source: "uv", Name: "bramble", Version: "26.10.1", Origin: "pypi.org"},
			},
		},
		{
			id:    "uv with nothing installed",
			parse: func(b []byte) ([]Package, error) { return parseUvList(string(b)), nil },
			in:    "No tools installed\n",
			want:  nil,
		},
		{
			id:    "mise prefers the active version and lists all",
			parse: parseMiseList,
			in: `{"node":[{"version":"22.1.0","install_path":"/m/node/22.1.0","installed":true,"active":false},
				{"version":"24.2.0","install_path":"/m/node/24.2.0","installed":true,"active":true}],
				"java":[{"version":"temurin-21.0.4+7.LTS","install_path":"/m/java/t25","installed":true,"active":false}],
				"go":[{"version":"1.27.0","installed":false,"active":true}]}`,
			want: []Package{
				{Source: "mise", Name: "java", Version: "temurin-21.0.4+7.LTS", Path: "/m/java/t25"},
				{Source: "mise", Name: "node", Version: "24.2.0", Path: "/m/node/24.2.0", Versions: []string{"22.1.0", "24.2.0"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := tt.parse([]byte(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseOutdated(t *testing.T) {
	tests := []struct {
		id    string
		parse func([]byte) (map[string]string, error)
		in    string
		want  map[string]string
	}{
		{"npm outdated", parseNpmOutdated, `{"npm":{"current":"11.19.0","wanted":"12.2.1","latest":"12.2.1","dependent":"global"}}`, map[string]string{"npm": "12.2.1"}},
		{"npm nothing outdated", parseNpmOutdated, ``, nil},
		{"mise outdated", parseMiseOutdated, `{"node":{"requested":"24","current":"24.2.0","latest":"24.3.0"}}`, map[string]string{"node": "24.3.0"}},
		{"mise nothing outdated", parseMiseOutdated, `{}`, map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := tt.parse([]byte(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// clearAgentEnv drops the env settings that move an agent's folders, so a
// test sees only the home it builds.
func clearAgentEnv(t *testing.T) {
	for _, a := range skillAgents {
		for _, p := range slices.Concat(a.Dirs, a.Detect) {
			if m := envDefault.FindStringSubmatch(p); m != nil {
				t.Setenv(m[1], "")
			}
		}
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct{ id, path, env, want string }{
		{"home", "~/.cursor/skills", "", "/h/.cursor/skills"},
		{"env unset falls back to its default", "${XDG_CONFIG_HOME:-~/.config}/goose/skills", "", "/h/.config/goose/skills"},
		{"env set wins", "${XDG_CONFIG_HOME:-~/.config}/goose/skills", "/x", "/x/goose/skills"},
		{"a blank env setting falls back to its default, as in the CLI", "${XDG_CONFIG_HOME:-~/.config}/goose/skills", " ", "/h/.config/goose/skills"},
		{"spaces around an env setting are dropped", "${XDG_CONFIG_HOME:-~/.config}/goose/skills", " /x\n", "/x/goose/skills"},
		{"absolute", "/etc/codex", "", "/etc/codex"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", tt.env)
			if got := expandPath("/h", tt.path); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAgentDir(t *testing.T) {
	tests := []struct {
		id, agent string
		dirs      []string
		want      string
	}{
		{"OpenClaw keeps its skills in ~/.clawdbot when only that exists", "openclaw", []string{".clawdbot"}, ".clawdbot/skills"},
		{"and in ~/.moltbot when only that exists", "openclaw", []string{".moltbot"}, ".moltbot/skills"},
		{"~/.openclaw wins over the old names", "openclaw", []string{".moltbot", ".clawdbot", ".openclaw"}, ".openclaw/skills"},
		{"~/.clawdbot wins over ~/.moltbot", "openclaw", []string{".moltbot", ".clawdbot"}, ".clawdbot/skills"},
		{"with none of them it is ~/.openclaw", "openclaw", nil, ".openclaw/skills"},
		{"an agent whose folder is ~/.agents/skills has none of its own", "codex", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			clearAgentEnv(t)
			home := t.TempDir()
			for _, d := range tt.dirs {
				os.Mkdir(filepath.Join(home, d), 0o755)
			}
			i := slices.IndexFunc(skillAgents, func(a skillAgent) bool { return a.Name == tt.agent })
			want := ""
			if tt.want != "" {
				want = filepath.Join(home, tt.want)
			}
			if got := skillAgents[i].dir(home); got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestScanSkills(t *testing.T) {
	clearAgentEnv(t)
	home := t.TempDir()
	mkdirs := func(paths ...string) {
		for _, p := range paths {
			if err := os.MkdirAll(filepath.Join(home, p), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	skills := func(paths ...string) {
		mkdirs(paths...)
		for _, p := range paths {
			os.WriteFile(filepath.Join(home, p, "SKILL.md"), []byte("---\nname: x\n---\n"), 0o644)
		}
	}
	skills(
		".agents/skills/tracked", ".agents/skills/untracked", ".agents/skills/claude-off",
		".claude/skills/tracked", ".claude/skills/untracked", ".claude/skills/agent-only",
		".cursor/skills/cursor-only", ".cursor/skills/agent-only", ".clawdbot/skills/claw-only",
	)
	mkdirs(".pi/agent", ".config/opencode")
	// Not skills: a link left behind after its skill was removed, and a
	// category folder like the ones Hermes keeps its bundled skills in.
	os.Symlink("../../.agents/skills/removed", filepath.Join(home, ".cursor/skills/removed"))
	skills(".claude/skills/notes/obsidian")
	os.WriteFile(filepath.Join(home, ".claude/skills/notes/DESCRIPTION.md"), nil, 0o644)
	lock := map[string]lockEntry{
		"tracked":    {Source: "someone/skills", SourceType: "github", SkillFolderHash: "cd509ae729c86487d352e17a26651217a4c25711"},
		"claude-off": {Source: "someone/skills", SourceType: "github", Ref: "v1.3.1", SkillFolderHash: "8295b8e10d4cdb6cce772a56dda7b7c37075074d"},
	}
	got, err := scanSkills(home, lock)
	if err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(home, ".agents", "skills")
	want := []Package{
		{Source: "skills", Name: "agent-only", Version: "-", Path: filepath.Join(home, ".claude/skills/agent-only"), Agents: []string{"claude-code", "cursor"},
			Note: "only in claude-code, cursor, not managed by the skills CLI"},
		{Source: "skills", Name: "claude-off", Version: "8295b8e", Pinned: true, Origin: "someone/skills", Path: filepath.Join(shared, "claude-off"),
			Agents: []string{"cursor", "opencode", "pi"}, Note: "pinned to v1.3.1", Repo: "someone/skills"},
		{Source: "skills", Name: "claw-only", Version: "-", Path: filepath.Join(home, ".clawdbot/skills/claw-only"), Agents: []string{"openclaw"},
			Note: "only in openclaw, not managed by the skills CLI"},
		{Source: "skills", Name: "cursor-only", Version: "-", Path: filepath.Join(home, ".cursor/skills/cursor-only"), Agents: []string{"cursor"},
			Note: "only in cursor, not managed by the skills CLI"},
		{Source: "skills", Name: "tracked", Version: "cd509ae", Origin: "someone/skills", Path: filepath.Join(shared, "tracked"), Agents: []string{"claude-code", "cursor", "opencode", "pi"}, Repo: "someone/skills"},
		{Source: "skills", Name: "untracked", Version: "-", Path: filepath.Join(shared, "untracked"), Agents: []string{"claude-code", "cursor", "opencode", "pi"},
			Note: "no lock entry, the skills CLI can't update it"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseVersions(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC) }
	pypi := func(in string) ([]Release, string, error) {
		var r pypiProject
		err := json.Unmarshal([]byte(in), &r)
		rels, repo := r.releases("bramble")
		return rels, repo, err
	}
	tests := []struct {
		id       string
		parse    func(string) ([]Release, string, error)
		in       string
		want     []Release
		wantRepo string
	}{
		{
			id:    "npm versions newest first with repo from url",
			parse: func(in string) ([]Release, string, error) { return parseNpmView("diffkit", []byte(in)) },
			in: `{"time":{"created":"2026-10-01T00:00:00Z","modified":"2026-10-09T00:00:00Z","0.23.0":"2026-10-02T00:00:00Z","0.24.1":"2026-10-08T00:00:00Z"},
				"repository":{"type":"git","url":"git+https://github.com/example/diffkit.git"}}`,
			want: []Release{
				{Version: "0.24.1", Date: day(8), URL: "https://www.npmjs.com/package/diffkit/v/0.24.1"},
				{Version: "0.23.0", Date: day(2), URL: "https://www.npmjs.com/package/diffkit/v/0.23.0"},
			},
			wantRepo: "example/diffkit",
		},
		{
			id:       "npm repository shorthand",
			parse:    func(in string) ([]Release, string, error) { return parseNpmView("x", []byte(in)) },
			in:       `{"time":{},"repository":"github:owner/name"}`,
			wantRepo: "owner/name",
		},
		{
			id:    "pypi skips yanked and empty releases",
			parse: pypi,
			in: `{"info":{"project_urls":{"Changelog":"https://github.com/example/bramble/blob/main/CHANGES.md","Documentation":"https://bramble.example/"}},
				"releases":{"26.10.1":[{"upload_time_iso_8601":"2026-10-10T00:00:00Z"}],"26.10.0":[{"upload_time_iso_8601":"2026-10-04T00:00:00Z","yanked":true}],"26.9.9":[]}}`,
			want:     []Release{{Version: "26.10.1", Date: day(10), URL: "https://pypi.org/project/bramble/26.10.1/"}},
			wantRepo: "example/bramble",
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, repo, err := tt.parse(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) || repo != tt.wantRepo {
				t.Errorf("got %+v %q\nwant %+v %q", got, repo, tt.want, tt.wantRepo)
			}
		})
	}
}

func TestTagVersion(t *testing.T) {
	for tag, want := range map[string]string{"v2.103.3": "2.103.3", "26.10.1": "26.10.1", "@example/cli@2026.9.1": "2026.9.1", "tidyup/v0.24.0": "0.24.0"} {
		if got := TagVersion(tag); got != want {
			t.Errorf("TagVersion(%q) = %q, want %q", tag, got, want)
		}
	}
}

func TestParsePipList(t *testing.T) {
	got, err := parsePipList("bramble", []byte(`[{"name":"bramble","version":"22.12.0"},{"name":"click","version":"8.5.0"},{"name":"pip","version":"26.2.1"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []Dep{{Name: "click", Version: "8.5.0"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestReadSkill(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: pathmaker\ndescription: \"Plan big work\"\nmetadata:\n  nested: x\n---\n\n# Pathmaker\nBody text.\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Readme"), 0o644)
	os.Mkdir(filepath.Join(dir, "scripts"), 0o755)
	got, err := ReadSkill(Package{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	want := SkillDoc{
		Meta:   [][2]string{{"name", "pathmaker"}, {"description", "Plan big work"}, {"metadata", ""}},
		Body:   "# Pathmaker\nBody text.\n",
		Readme: "# Readme",
		Files:  []string{"README.md", "SKILL.md", "scripts/"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestQueries(t *testing.T) {
	tidyup := Package{Source: "go", Name: "tidyup", Version: "v0.23.0", Origin: "example.com/tidyup",
		Deps: []Dep{{Name: "golang.org/x/net", Version: "v0.20.0"}, {Name: "example.com/local", Version: "(devel)"}}}
	if q, ok := Query(tidyup); !ok || q != (vuln.Query{Ecosystem: "Go", Name: "example.com/tidyup", Version: "v0.23.0"}) {
		t.Errorf("Query = %+v %v", q, ok)
	}
	if got := DepQueries(tidyup); !reflect.DeepEqual(got, []vuln.Query{{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.20.0"}}) {
		t.Errorf("DepQueries = %+v", got)
	}
	if _, ok := Query(Package{Source: "brew", Name: "anvil", Version: "0.2.89"}); ok {
		t.Error("brew has no OSV ecosystem")
	}
	if _, ok := Query(Package{Source: "go", Name: "localtool", Version: "(devel)"}); ok {
		t.Error("a local build has no published version to check")
	}
}

func TestEscapeModule(t *testing.T) {
	if got := escapeModule("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Errorf("got %s", got)
	}
}

func TestInstallCmd(t *testing.T) {
	tests := []struct {
		id      string
		pkg     Package
		version string
		want    string
		err     string
	}{
		{"npm installs any version", Package{Source: "npm", Name: "diffkit"}, "0.23.0", "npm install -g diffkit@0.23.0", ""},
		{"pipx forces the version", Package{Source: "pipx", Name: "bramble"}, "24.3.0", "pipx install --force bramble==24.3.0", ""},
		{"uv forces the version", Package{Source: "uv", Name: "ruff"}, "0.15.2", "uv tool install --force ruff==0.15.2", ""},
		{"go installs the main package", Package{Source: "go", Name: "tidyup", Entry: "example.com/tidyup"}, "v0.24.0", "go install example.com/tidyup@v0.24.0", ""},
		{"mise installs a tool version", Package{Source: "mise", Name: "node"}, "24.3.0", "mise install node@24.3.0", ""},
		{"brew upgrades to the newest", Package{Source: "brew", Name: "anvil", Latest: "0.2.94"}, "0.2.94", "brew upgrade anvil", ""},
		{"casks too", Package{Source: "cask", Name: "notchy", Latest: "2.3.0"}, "2.3.0", "brew upgrade --cask notchy", ""},
		{"brew has no older versions", Package{Source: "brew", Name: "anvil", Latest: "0.2.94"}, "0.2.89", "", "Homebrew can only install the newest version, 0.2.94"},
		{"a pinned package stays", Package{Source: "brew", Name: "gust", Pinned: true}, "1.27.3", "", "gust is pinned, so kho leaves it where it is"},
		{"skills update to the newest commit", Package{Source: "skills", Name: "pathmaker", Latest: "25da74e"}, "25da74e", "npx -y skills update -g pathmaker", ""},
		{"skills have no older installs", Package{Source: "skills", Name: "pathmaker", Latest: "25da74e"}, "32b0ce9", "", "the skills CLI installs only the newest commit of a skill"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			cmd, err := InstallCmd(tt.pkg, tt.version)
			got, gotErr := "", ""
			if cmd != nil {
				got = strings.Join(cmd.Args, " ")
			}
			if err != nil {
				gotErr = err.Error()
			}
			if got != tt.want || gotErr != tt.err {
				t.Errorf("got %q %q, want %q %q", got, gotErr, tt.want, tt.err)
			}
		})
	}
}

func TestSkillLinks(t *testing.T) {
	clearAgentEnv(t)
	home := t.TempDir()
	for _, d := range []string{".agents/skills/workflow", ".claude/skills", ".cursor/skills/workflow", ".pi/agent", ".codex", ".config/goose", ".config/opencode"} {
		os.MkdirAll(filepath.Join(home, d), 0o755)
	}
	os.Symlink("../../.agents/skills/workflow", filepath.Join(home, ".claude/skills/workflow"))
	p := Package{Name: "workflow", Path: filepath.Join(home, ".agents/skills/workflow")}
	real := RealPath(p)
	// Agents found through a system path like /Applications vary by machine.
	kinds := func() map[string]string {
		got := map[string]string{}
		for _, l := range skillLinks(home, p, false) {
			if !strings.HasPrefix(l.Path, home) {
				continue
			}
			got[l.Agent] = l.Kind
			if l.Shared && l.Kind != "shared" {
				got[l.Agent] += ", sees shared"
			}
			if l.Kind == "link" && l.Target != real {
				t.Errorf("%s points at %s, want %s", l.Agent, l.Target, real)
			}
		}
		return got
	}
	want := map[string]string{"claude-code": "link", "codex": "shared", "cursor": "copy, sees shared", "goose": "missing", "opencode": "missing, sees shared", "pi": "shared"}
	if got := kinds(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	byAgent := map[string]SkillLink{}
	for _, l := range skillLinks(home, p, true) {
		byAgent[l.Agent] = l
	}
	if len(byAgent) != len(skillAgents) || byAgent["amp"].Installed || !byAgent["goose"].Installed || byAgent["goose"].Display != "Goose" {
		t.Errorf("all agents: %d of %d, amp %+v, goose %+v", len(byAgent), len(skillAgents), byAgent["amp"], byAgent["goose"])
	}
	if !byAgent["pi"].Shared || byAgent["claude-code"].Shared {
		t.Error("pi reads the shared folder, claude-code does not")
	}
	if err := LinkSkill(byAgent["goose"], p); err != nil {
		t.Fatal(err)
	}
	if err := UnlinkSkill(byAgent["claude-code"]); err != nil {
		t.Fatal(err)
	}
	if err := UnlinkSkill(byAgent["cursor"]); err == nil {
		t.Error("a copied folder must not be removed")
	}
	want = map[string]string{"claude-code": "missing", "codex": "shared", "cursor": "copy, sees shared", "goose": "link", "opencode": "missing, sees shared", "pi": "shared"}
	if got := kinds(); !reflect.DeepEqual(got, want) {
		t.Errorf("after toggling got %v, want %v", got, want)
	}
}

func TestRunIsRecorded(t *testing.T) {
	var got []string
	Record = func(command []string, _ time.Duration, err error) { got = append(got, strings.Join(command, " ")) }
	defer func() { Record = func([]string, time.Duration, error) {} }()
	run(context.Background(), "echo", "hi")
	if !reflect.DeepEqual(got, []string{"echo hi"}) {
		t.Errorf("recorded %q", got)
	}
}

// A provider this machine lacks must be named by Missing, never dropped: a
// silent skip reads as "nothing installed" and hides whatever it would hold.
func TestMissingNamesEveryProviderThatIsNotSetUp(t *testing.T) {
	missing := Missing()
	for _, p := range All() {
		reason, named := missing[p.Name()]
		if available := p.Available(); available == named {
			t.Errorf("%s: Available is %v but Missing says %v", p.Name(), available, named)
		}
		if named && reason == "" {
			t.Errorf("%s is named without a reason", p.Name())
		}
	}
}
