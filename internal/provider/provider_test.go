package provider

import (
	"context"
	"encoding/json"
	"io/fs"
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
		{"a blank CLAUDE_CONFIG_DIR falls back to its default, as the CLI trims it", "${CLAUDE_CONFIG_DIR:-~/.claude}/skills", " ", "/h/.claude/skills"},
		{"spaces around it are dropped", "${CLAUDE_CONFIG_DIR:-~/.claude}/skills", " /x\n", "/x/skills"},
		{"absolute", "/etc/codex", "", "/etc/codex"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if m := envDefault.FindStringSubmatch(tt.path); m != nil {
				t.Setenv(m[1], tt.env)
			}
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

// build makes each entry under home: "a/b/" a folder, "a -> b" a symlink,
// anything else an empty file.
func build(t *testing.T, home string, entries ...string) {
	t.Helper()
	for _, e := range entries {
		from, to, link := strings.Cut(e, " -> ")
		p := filepath.Join(home, from)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		var err error
		switch {
		case link:
			err = os.Symlink(to, p)
		case strings.HasSuffix(from, "/"):
			err = os.MkdirAll(p, 0o755)
		default:
			err = os.WriteFile(p, nil, 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// tree lists what is under home, the way build takes it.
func tree(home string) []string {
	var out []string
	filepath.WalkDir(home, func(p string, d fs.DirEntry, _ error) error {
		rel, _ := filepath.Rel(home, p)
		switch {
		case rel == ".":
		case d.Type()&fs.ModeSymlink != 0:
			to, _ := os.Readlink(p)
			out = append(out, rel+" -> "+to)
		case d.IsDir():
			out = append(out, rel+"/")
		default:
			out = append(out, rel)
		}
		return nil
	})
	return out
}

func TestSkillLinks(t *testing.T) {
	agents := []string{".codex/", ".pi/agent/", ".config/goose/", ".config/opencode/", ".cursor/"}
	tests := []struct {
		id    string
		env   map[string]string
		files []string
		skill string
		want  map[string]string
	}{
		{
			id:    "a skill only in ~/.claude/skills is seen by claude-code alone",
			files: []string{".claude/skills/notes/SKILL.md"},
			skill: ".claude/skills/notes",
			want: map[string]string{"claude-code": "copy, sees", "codex": "no folder", "cursor": "missing, can link", "goose": "missing, can link",
				"opencode": "missing, can link", "pi": "no folder"},
		},
		{
			id:    "a skill in ~/.agents/skills is seen by every agent that reads it, and can be linked for the rest",
			files: []string{".agents/skills/workflow/SKILL.md", ".claude/skills/workflow -> ../../.agents/skills/workflow", ".cursor/skills/workflow/SKILL.md"},
			skill: ".agents/skills/workflow",
			want: map[string]string{"claude-code": "link to .agents/skills/workflow, sees", "codex": "no folder, sees", "cursor": "copy, sees",
				"goose": "missing, can link", "opencode": "missing, sees", "pi": "no folder, sees"},
		},
		{
			id: "a broken link or a folder with no SKILL.md in an agent's folder doesn't count as seeing the skill",
			files: []string{".agents/skills/workflow/SKILL.md", ".config/goose/skills/workflow -> ../../../nowhere", ".claude/skills/workflow/",
				".cursor/skills/workflow -> ../../nowhere"},
			skill: ".agents/skills/workflow",
			want: map[string]string{"claude-code": "copy", "codex": "no folder, sees", "cursor": "link, sees", "goose": "link",
				"opencode": "missing, sees", "pi": "no folder, sees"},
		},
		{
			id:    "nor does a folder with no SKILL.md in ~/.agents/skills",
			files: []string{".claude/skills/notes/SKILL.md", ".agents/skills/notes/"},
			skill: ".claude/skills/notes",
			want: map[string]string{"claude-code": "copy, sees", "codex": "no folder", "cursor": "missing, can link", "goose": "missing, can link",
				"opencode": "missing, can link", "pi": "no folder"},
		},
		{
			id:    "an agent whose folder an env setting moves to ~/.agents/skills reads the shared skills",
			env:   map[string]string{"CLAUDE_CONFIG_DIR": "{home}/.agents"},
			files: []string{".agents/skills/workflow/SKILL.md"},
			skill: ".agents/skills/workflow",
			want: map[string]string{"claude-code": "no folder, sees", "codex": "no folder, sees", "cursor": "missing, sees",
				"goose": "missing, can link", "opencode": "missing, sees", "pi": "no folder, sees"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			clearAgentEnv(t)
			home := t.TempDir()
			for k, v := range tt.env {
				t.Setenv(k, strings.ReplaceAll(v, "{home}", home))
			}
			build(t, home, slices.Concat(agents, tt.files)...)
			p := Package{Name: filepath.Base(tt.skill), Path: filepath.Join(home, tt.skill)}
			real, _ := filepath.EvalSymlinks(home)
			got := map[string]string{}
			var seen []string
			for _, l := range skillLinks(home, p, false) {
				// Agents found through a system path like /Applications vary by machine.
				if !strings.HasPrefix(l.Path, home) {
					continue
				}
				s := string(l.Kind)
				if l.Target != "" {
					to, _ := filepath.Rel(real, l.Target)
					s += " to " + to
				}
				if l.Sees() {
					s += ", sees"
					seen = append(seen, l.Agent)
				}
				if l.CanLink() {
					s += ", can link"
				}
				got[l.Agent] = s
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %v\nwant %v", got, tt.want)
			}

			pkgs, _ := scanSkills(home, nil)
			i := slices.IndexFunc(pkgs, func(q Package) bool { return q.Path == p.Path })
			if i < 0 {
				t.Fatalf("scanSkills did not list %s", p.Path)
			}
			scanned := slices.DeleteFunc(pkgs[i].Agents, func(a string) bool { _, ok := got[a]; return !ok })
			slices.Sort(seen)
			slices.Sort(scanned)
			if !slices.Equal(seen, scanned) {
				t.Errorf("seen by %v, but scanSkills says %v", seen, scanned)
			}
		})
	}
}

func TestSkillLinksAll(t *testing.T) {
	// Agents found through a system path like /Applications vary by machine,
	// so both sides leave them out.
	machine := func(name string) bool {
		i := slices.IndexFunc(skillAgents, func(a skillAgent) bool { return a.Name == name })
		return slices.ContainsFunc(skillAgents[i].Detect, func(p string) bool { return strings.HasPrefix(p, "/") })
	}
	var every []string
	for _, a := range skillAgents {
		switch {
		case machine(a.Name):
		case a.Name == "goose":
			every = append(every, "Goose, installed")
		default:
			every = append(every, a.Display)
		}
	}
	tests := []struct {
		id   string
		all  bool
		want []string
	}{
		{"by default only the installed agents come back", false, []string{"Goose, installed"}},
		{"with all set, every agent the skills CLI supports does, in its order", true, every},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			clearAgentEnv(t)
			home := t.TempDir()
			build(t, home, ".agents/skills/workflow/SKILL.md", ".config/goose/")
			var got []string
			for _, l := range skillLinks(home, Package{Name: "workflow"}, tt.all) {
				switch {
				case machine(l.Agent):
				case l.Installed:
					got = append(got, l.Display+", installed")
				default:
					got = append(got, l.Display)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestLinkSkill(t *testing.T) {
	skill := []string{".agents/skills/workflow/SKILL.md", ".config/goose/", ".config/opencode/", ".codex/", ".cursor/skills/workflow/SKILL.md"}
	tests := []struct {
		id, agent string
		files     []string
		added     []string
		err       string
	}{
		{id: "an agent that sees the skill through ~/.agents/skills gets no link of its own", agent: "opencode", files: skill,
			err: "opencode already sees workflow through ~/.agents/skills"},
		{id: "nor does an agent with no folder of its own", agent: "codex", files: skill, err: "codex has no skills folder of its own"},
		{id: "a copied folder stays", agent: "cursor", files: skill, err: "cursor already has ~/.cursor/skills/workflow"},
		{id: "an agent with a folder of its own gets a relative link", agent: "goose", files: skill,
			added: []string{".config/goose/skills/", ".config/goose/skills/workflow -> ../../../.agents/skills/workflow"}},
		{id: "the link goes through the skill's entry in ~/.agents/skills, not to where that leads", agent: "goose",
			files: []string{".agents/skills/workflow -> ../../dev/workflow", "dev/workflow/SKILL.md", ".config/goose/"},
			added: []string{".config/goose/skills/", ".config/goose/skills/workflow -> ../../../.agents/skills/workflow"}},
		{id: "a link from a folder under a symlink still reaches the skill", agent: "goose",
			files: []string{".agents/skills/workflow/SKILL.md", "dotfiles/config/goose/", ".config -> dotfiles/config"},
			added: []string{"dotfiles/config/goose/skills/", "dotfiles/config/goose/skills/workflow -> ../../../../.agents/skills/workflow"}},
		{id: "OpenClaw links into ~/.clawdbot, the folder it has", agent: "openclaw", files: []string{".agents/skills/workflow/SKILL.md", ".clawdbot/"},
			added: []string{".clawdbot/skills/", ".clawdbot/skills/workflow -> ../../.agents/skills/workflow"}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			clearAgentEnv(t)
			home, _ := filepath.EvalSymlinks(t.TempDir())
			build(t, home, tt.files...)
			before := tree(home)
			p := Package{Name: "workflow", Path: filepath.Join(home, ".agents/skills/workflow")}
			links := skillLinks(home, p, true)
			i := slices.IndexFunc(links, func(l SkillLink) bool { return l.Agent == tt.agent })
			gotErr := ""
			if err := LinkSkill(links[i], p); err != nil {
				gotErr = strings.ReplaceAll(err.Error(), home, "~")
			}
			added := slices.DeleteFunc(tree(home), func(e string) bool { return slices.Contains(before, e) })
			if !slices.Equal(added, tt.added) || gotErr != tt.err {
				t.Errorf("added %q %q\nwant  %q %q", added, gotErr, tt.added, tt.err)
			}
		})
	}
}

func TestUnlinkSkill(t *testing.T) {
	tests := []struct {
		id, agent string
		// since replaces what is at a path after kho read the links.
		since   []string
		removed []string
		err     string
	}{
		{id: "a link is removed", agent: "claude-code", removed: []string{".claude/skills/workflow -> ../../.agents/skills/workflow"}},
		{id: "a link replaced by an empty folder since kho read it stays", agent: "claude-code", since: []string{".claude/skills/workflow/"},
			err: "~/.claude/skills/workflow is not a symlink, so kho won't remove it"},
		{id: "and so does one replaced by a file", agent: "claude-code", since: []string{".claude/skills/workflow"},
			err: "~/.claude/skills/workflow is not a symlink, so kho won't remove it"},
		{id: "a copied folder is never removed", agent: "cursor", err: "~/.cursor/skills/workflow is not a symlink, so kho won't remove it"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			clearAgentEnv(t)
			home, _ := filepath.EvalSymlinks(t.TempDir())
			build(t, home, ".agents/skills/workflow/SKILL.md", ".claude/skills/workflow -> ../../.agents/skills/workflow", ".cursor/skills/workflow/SKILL.md")
			p := Package{Name: "workflow", Path: filepath.Join(home, ".agents/skills/workflow")}
			links := skillLinks(home, p, false)
			for _, e := range tt.since {
				os.Remove(filepath.Join(home, e))
				build(t, home, e)
			}
			before := tree(home)
			i := slices.IndexFunc(links, func(l SkillLink) bool { return l.Agent == tt.agent })
			gotErr := ""
			if err := UnlinkSkill(links[i]); err != nil {
				gotErr = strings.ReplaceAll(err.Error(), home, "~")
			}
			after := tree(home)
			removed := slices.DeleteFunc(before, func(e string) bool { return slices.Contains(after, e) })
			if !slices.Equal(removed, tt.removed) || gotErr != tt.err {
				t.Errorf("removed %q %q\nwant    %q %q", removed, gotErr, tt.removed, tt.err)
			}
		})
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
