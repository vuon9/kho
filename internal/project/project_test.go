package project

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vuon9/kho/internal/provider"
)

func lockfile(path, manager string, pkgs ...provider.Package) Lockfile {
	for i := range pkgs {
		pkgs[i].Source = manager
		pkgs[i].Lockfile = path
	}
	return Lockfile{Path: path, Manager: manager, Packages: pkgs}
}

func TestReadLockfile(t *testing.T) {
	tests := []struct {
		id      string
		path    string
		manager string
		want    Lockfile
	}{
		{
			id:      "npm nested copies resolve the Node way and prod chains win",
			path:    "npm/package-lock.json",
			manager: "npm",
			want: lockfile("npm/package-lock.json", "npm",
				provider.Package{Name: "@acme/strutil", Version: "0.9.0", Dependency: true, Via: []string{"left-trim"}},
				provider.Package{Name: "byteview", Version: "0.2.1", Dependency: true, Via: []string{"left-trim", "@acme/strutil"}},
				provider.Package{Name: "byteview", Version: "0.3.0", Dependency: true, Via: []string{"left-trim", "tinyhash"}},
				provider.Package{Name: "inkpot", Version: "3.1.0", Dev: true},
				provider.Package{Name: "left-trim", Version: "1.2.3"},
				provider.Package{Name: "quietlog", Version: "0.2.4"},
				provider.Package{Name: "tinyhash", Version: "0.4.1", Dependency: true, Via: []string{"left-trim"}},
				provider.Package{Name: "tinyhash", Version: "0.5.0", Dependency: true, Dev: true, Via: []string{"inkpot"}},
			),
		},
		{
			id:      "npm workspace members' dependencies are direct and members are left out",
			path:    "npm-workspace/package-lock.json",
			manager: "npm",
			want: lockfile("npm-workspace/package-lock.json", "npm",
				provider.Package{Name: "left-trim", Version: "1.2.3"},
				provider.Package{Name: "left-trim", Version: "2.0.1"},
				provider.Package{Name: "quietlog", Version: "0.2.4", Dev: true},
				provider.Package{Name: "tinyhash", Version: "0.4.1", Dependency: true, Via: []string{"left-trim"}},
				provider.Package{Name: "tinyhash", Version: "0.5.0", Dependency: true, Via: []string{"left-trim"}},
			),
		},
		{
			id:      "composer keeps the v and takes direct from composer.json",
			path:    "composer/composer.lock",
			manager: "composer",
			want: lockfile("composer/composer.lock", "composer",
				provider.Package{Name: "acme/faker-lite", Version: "0.3.7", Dependency: true, Dev: true, Via: []string{"acme/fixture-kit"}},
				provider.Package{Name: "acme/fixture-kit", Version: "1.1.0", Dev: true},
				provider.Package{Name: "acme/ledger", Version: "v2.3.0"},
				provider.Package{Name: "acme/numbers", Version: "1.4.2", Dependency: true, Via: []string{"acme/ledger"}},
				provider.Package{Name: "acme/polyfill-math", Version: "v1.0.5", Dependency: true, Via: []string{"acme/ledger", "acme/numbers"}},
			),
		},
		{
			id:      "uv extras, dependency groups and dev only when no prod path",
			path:    "uv/uv.lock",
			manager: "uv",
			want: lockfile("uv/uv.lock", "uv",
				provider.Package{Name: "assertly", Version: "0.8.0", Dependency: true, Dev: true, Via: []string{"checkmate"}},
				provider.Package{Name: "checkmate", Version: "9.1.0", Dev: true},
				provider.Package{Name: "inkpot", Version: "3.1.0"},
				provider.Package{Name: "palette", Version: "1.2.0", Dependency: true, Via: []string{"inkpot"}},
				provider.Package{Name: "speedups", Version: "2.0.0"},
				provider.Package{Name: "stylo", Version: "0.4.1", Dev: true},
				provider.Package{Name: "termtint", Version: "0.4.6", Dependency: true, Dev: true, Via: []string{"checkmate"}},
				provider.Package{Name: "tinyhash", Version: "0.4.1", Dependency: true, Via: []string{"inkpot"}},
				provider.Package{Name: "urlkit", Version: "2.8.0", Dependency: true, Via: []string{"webkit-lite"}},
				provider.Package{Name: "webkit-lite", Version: "2.31.0"},
			),
		},
		{
			id:      "poetry groups, PEP 621 and 735 tables, and names matched normalized",
			path:    "poetry/poetry.lock",
			manager: "poetry",
			want: lockfile("poetry/poetry.lock", "poetry",
				provider.Package{Name: "checkmate", Version: "9.1.0", Dev: true},
				provider.Package{Name: "inkpot", Version: "3.1.0"},
				provider.Package{Name: "jinja-lite", Version: "3.1.6", Dependency: true, Dev: true, Via: []string{"pagewright"}},
				provider.Package{Name: "pagewright", Version: "1.6.1", Dev: true},
				provider.Package{Name: "palette", Version: "1.2.0", Dependency: true, Via: []string{"inkpot"}},
				provider.Package{Name: "termtint", Version: "0.4.6", Dependency: true, Dev: true, Via: []string{"checkmate"}},
				provider.Package{Name: "tinyhash", Version: "0.4.1", Dependency: true, Via: []string{"inkpot"}},
				provider.Package{Name: "urlkit", Version: "2.8.0", Dependency: true, Via: []string{"webkit-lite"}},
				provider.Package{Name: "webkit-lite", Version: "2.31.0"},
			),
		},
		{
			id:      "cargo skips own and git crates and reads renamed dev dependencies",
			path:    "cargo/Cargo.lock",
			manager: "cargo",
			want: lockfile("cargo/Cargo.lock", "cargo",
				provider.Package{Name: "byteview", Version: "0.2.1"},
				provider.Package{Name: "byteview", Version: "0.3.0", Dependency: true, Via: []string{"inkpot"}},
				provider.Package{Name: "fastrand-lite", Version: "2.5.0", Dependency: true, Dev: true, Via: []string{"tempdir-lite"}},
				provider.Package{Name: "tempdir-lite", Version: "3.2.0", Dev: true},
				provider.Package{Name: "tinyhash", Version: "0.4.1"},
			),
		},
		{
			id:      "cargo workspace reads dev dependencies from member manifests",
			path:    "cargo-workspace/Cargo.lock",
			manager: "cargo",
			want: lockfile("cargo-workspace/Cargo.lock", "cargo",
				provider.Package{Name: "fastrand-lite", Version: "2.5.0", Dependency: true, Dev: true, Via: []string{"tempdir-lite"}},
				provider.Package{Name: "tempdir-lite", Version: "3.2.0", Dev: true},
				provider.Package{Name: "tinyhash", Version: "0.4.1"},
			),
		},
		{
			id:      "go.mod marks indirect, follows version replaces and drops local ones",
			path:    "go/go.mod",
			manager: "go",
			want: lockfile("go/go.mod", "go",
				provider.Package{Name: "example.com/colorize", Origin: "example.com/colorize", Version: "v0.3.1", Dependency: true},
				provider.Package{Name: "example.com/patched", Origin: "example.com/patched", Version: "v1.0.2"},
				provider.Package{Name: "example.com/tidyup", Origin: "example.com/tidyup", Version: "v1.4.0"},
				provider.Package{Name: "example.org/textwrap", Origin: "example.org/textwrap", Version: "v0.9.0", Dependency: true},
			),
		},
		{
			id:      "requirements keep only == pins",
			path:    "pip/requirements.txt",
			manager: "pip",
			want: lockfile("pip/requirements.txt", "pip",
				provider.Package{Name: "Palette", Version: "1.2.0"},
				provider.Package{Name: "inkpot", Version: "3.1.0"},
				provider.Package{Name: "termtint", Version: "0.4.6"},
				provider.Package{Name: "tinyhash", Version: "0.4.1"},
				provider.Package{Name: "urlkit", Version: "2.8.0"},
			),
		},
		{
			id:      "requirements named dev are dev",
			path:    "pip/requirements-dev.txt",
			manager: "pip",
			want: lockfile("pip/requirements-dev.txt", "pip",
				provider.Package{Name: "assertly", Version: "0.8.0", Dev: true},
				provider.Package{Name: "checkmate", Version: "9.1.0", Dev: true},
			),
		},
		{
			id:      "npm lockfile version 1 nests and takes direct from package.json",
			path:    "npm-v1/package-lock.json",
			manager: "npm",
			want: lockfile("npm-v1/package-lock.json", "npm",
				provider.Package{Name: "inkpot", Version: "3.1.0", Dev: true},
				provider.Package{Name: "left-trim", Version: "1.2.3"},
				provider.Package{Name: "tinyhash", Version: "0.4.1", Dependency: true, Via: []string{"left-trim"}},
				provider.Package{Name: "tinyhash", Version: "0.5.0", Dependency: true, Dev: true, Via: []string{"inkpot"}},
			),
		},
		{
			id:      "composer without composer.json counts every package as direct",
			path:    "composer-lock-only/composer.lock",
			manager: "composer",
			want: lockfile("composer-lock-only/composer.lock", "composer",
				provider.Package{Name: "acme/faker-lite", Version: "0.3.7", Dev: true},
				provider.Package{Name: "acme/fixture-kit", Version: "1.1.0", Dev: true},
				provider.Package{Name: "acme/ledger", Version: "v2.3.0"},
				provider.Package{Name: "acme/numbers", Version: "1.4.2"},
				provider.Package{Name: "acme/polyfill-math", Version: "v1.0.5"},
			),
		},
		{
			id:      "older poetry lockfile marks dev with category",
			path:    "poetry-category/poetry.lock",
			manager: "poetry",
			want: lockfile("poetry-category/poetry.lock", "poetry",
				provider.Package{Name: "checkmate", Version: "7.4.0", Dev: true},
				provider.Package{Name: "inkpot", Version: "3.0.2"},
				provider.Package{Name: "pagewright", Version: "1.4.0", Dev: true},
				provider.Package{Name: "tinyhash", Version: "0.4.1", Dependency: true, Via: []string{"inkpot"}},
			),
		},
		{
			id:      "broken lockfile says why",
			path:    "broken/package-lock.json",
			manager: "npm",
			want:    Lockfile{Path: "broken/package-lock.json", Manager: "npm", Err: "unexpected end of JSON input"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := readLockfile("testdata", tt.path, tt.manager)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func set[T any](t *testing.T, p *T, v T) {
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func TestFind(t *testing.T) {
	const (
		goMod        = "module example.com/x\n"
		npmLock      = `{"lockfileVersion":3,"packages":{"":{}}}`
		pkgJSON      = `{"dependencies":{"left-trim":"^1.2.0"}}`
		composerLock = `{"packages":[],"packages-dev":[]}`
		composerJSON = `{"require":{"acme/ledger":"^2.3"}}`
		tomlLock     = "version = 4\n"
		cargoToml    = "[package]\nname = \"x\"\n"
		pyproject    = "[project]\nname = \"x\"\ndependencies = [\"inkpot>=3\"]\n"
		poetryToml   = "[tool.poetry.dependencies]\npython = \"^3.12\"\ninkpot = \"^3.0\"\n"
	)
	note := func(cmd string) string { return "no lockfile, versions unknown. Run " + cmd + " to create one" }
	tests := []struct {
		id           string
		files        map[string]string // relative to home
		start        string            // relative to home
		maxDepth     int
		maxLockfiles int
		noTime       bool
		root         string // relative to home
		projects     []Project
		capped       string
		err          bool
	}{
		{
			id: "every kind of lockfile, one project per folder",
			files: map[string]string{
				"proj/go.mod":                    goMod,
				"proj/web/package-lock.json":     npmLock,
				"proj/web/package.json":          pkgJSON,
				"proj/web/go.mod":                goMod,
				"proj/api/composer.lock":         composerLock,
				"proj/api/composer.json":         composerJSON,
				"proj/py/uv.lock":                tomlLock,
				"proj/py/requirements.txt":       "",
				"proj/py/pyproject.toml":         pyproject,
				"proj/poetry/poetry.lock":        "",
				"proj/tools/requirements.txt":    "",
				"proj/tools/requirements-ci.txt": "",
				"proj/rs/Cargo.lock":             tomlLock,
				"proj/rs/Cargo.toml":             cargoToml,
			},
			start: "proj",
			root:  "proj",
			projects: []Project{
				{Dir: "", Lockfiles: []Lockfile{{Path: "go.mod", Manager: "go"}}},
				{Dir: "api", Lockfiles: []Lockfile{{Path: "api/composer.lock", Manager: "composer"}}},
				{Dir: "poetry", Lockfiles: []Lockfile{{Path: "poetry/poetry.lock", Manager: "poetry"}}},
				{Dir: "py", Lockfiles: []Lockfile{{Path: "py/uv.lock", Manager: "uv"}}},
				{Dir: "rs", Lockfiles: []Lockfile{{Path: "rs/Cargo.lock", Manager: "cargo"}}},
				{Dir: "tools", Lockfiles: []Lockfile{
					{Path: "tools/requirements-ci.txt", Manager: "pip"},
					{Path: "tools/requirements.txt", Manager: "pip"},
				}},
				{Dir: "web", Lockfiles: []Lockfile{
					{Path: "web/go.mod", Manager: "go"},
					{Path: "web/package-lock.json", Manager: "npm"},
				}},
			},
		},
		{
			id: "manifests without a lockfile get a note",
			files: map[string]string{
				"proj/js/package.json":         pkgJSON,
				"proj/pnpm/package.json":       pkgJSON,
				"proj/pnpm/pnpm-lock.yaml":     "",
				"proj/yarn/package.json":       pkgJSON,
				"proj/yarn/yarn.lock":          "",
				"proj/php/composer.json":       composerJSON,
				"proj/py/pyproject.toml":       pyproject,
				"proj/poetry/pyproject.toml":   poetryToml,
				"proj/rs/Cargo.toml":           cargoToml,
				"proj/settings/package.json":   `{"name":"site","scripts":{"build":"make"}}`,
				"proj/settings/pyproject.toml": "[tool.ruff]\nline-length = 100\n",
			},
			start: "proj",
			root:  "proj",
			projects: []Project{
				{Dir: "js", Lockfiles: []Lockfile{{Path: "js/package.json", Manager: "npm", Missing: note("npm install")}}},
				{Dir: "php", Lockfiles: []Lockfile{{Path: "php/composer.json", Manager: "composer", Missing: note("composer install")}}},
				{Dir: "pnpm", Lockfiles: []Lockfile{{Path: "pnpm/package.json", Manager: "npm", Missing: "pnpm-lock.yaml isn't read yet"}}},
				{Dir: "poetry", Lockfiles: []Lockfile{{Path: "poetry/pyproject.toml", Manager: "poetry", Missing: note("poetry lock")}}},
				{Dir: "py", Lockfiles: []Lockfile{{Path: "py/pyproject.toml", Manager: "uv", Missing: note("uv lock")}}},
				{Dir: "rs", Lockfiles: []Lockfile{{Path: "rs/Cargo.toml", Manager: "cargo", Missing: note("cargo generate-lockfile")}}},
				{Dir: "yarn", Lockfiles: []Lockfile{{Path: "yarn/package.json", Manager: "npm", Missing: "yarn.lock isn't read yet"}}},
			},
		},
		{
			id: "a lockfile above covers workspace members",
			files: map[string]string{
				"proj/package-lock.json":             npmLock,
				"proj/package.json":                  pkgJSON,
				"proj/packages/api/package.json":     pkgJSON,
				"proj/Cargo.lock":                    tomlLock,
				"proj/Cargo.toml":                    cargoToml,
				"proj/crates/core/Cargo.toml":        cargoToml,
				"proj/uv.lock":                       tomlLock,
				"proj/libs/shared/pyproject.toml":    pyproject,
				"proj/composer.lock":                 composerLock,
				"proj/modules/billing/composer.json": composerJSON,
			},
			start: "proj",
			root:  "proj",
			projects: []Project{{Dir: "", Lockfiles: []Lockfile{
				{Path: "Cargo.lock", Manager: "cargo"},
				{Path: "composer.lock", Manager: "composer"},
				{Path: "package-lock.json", Manager: "npm"},
				{Path: "uv.lock", Manager: "uv"},
			}}},
		},
		{
			id: "a lockfile in a sibling folder covers nothing",
			files: map[string]string{
				"proj/a/package-lock.json": npmLock,
				"proj/b/package.json":      pkgJSON,
			},
			start: "proj",
			root:  "proj",
			projects: []Project{
				{Dir: "a", Lockfiles: []Lockfile{{Path: "a/package-lock.json", Manager: "npm"}}},
				{Dir: "b", Lockfiles: []Lockfile{{Path: "b/package.json", Manager: "npm", Missing: note("npm install")}}},
			},
		},
		{
			id: "skips vendored, built and hidden folders",
			files: map[string]string{
				"proj/app/go.mod": goMod,
				"proj/node_modules/left-trim/package-lock.json": npmLock,
				"proj/vendor/example.com/x/go.mod":              goMod,
				"proj/.venv/requirements.txt":                   "",
				"proj/venv/requirements.txt":                    "",
				"proj/target/Cargo.lock":                        tomlLock,
				"proj/dist/go.mod":                              goMod,
				"proj/build/go.mod":                             goMod,
				"proj/testdata/go.mod":                          goMod,
				"proj/fixtures/go.mod":                          goMod,
				"proj/.cache/go.mod":                            goMod,
			},
			start:    "proj",
			root:     "proj",
			projects: []Project{{Dir: "app", Lockfiles: []Lockfile{{Path: "app/go.mod", Manager: "go"}}}},
		},
		{
			id: "stops below the depth cap",
			files: map[string]string{
				"proj/a/go.mod":     goMod,
				"proj/a/b/go.mod":   goMod,
				"proj/a/b/c/go.mod": goMod,
			},
			start:    "proj",
			maxDepth: 2,
			root:     "proj",
			projects: []Project{
				{Dir: "a", Lockfiles: []Lockfile{{Path: "a/go.mod", Manager: "go"}}},
				{Dir: "a/b", Lockfiles: []Lockfile{{Path: "a/b/go.mod", Manager: "go"}}},
			},
		},
		{
			id: "stops after the lockfile cap and says so",
			files: map[string]string{
				"proj/a/go.mod": goMod,
				"proj/b/go.mod": goMod,
				"proj/c/go.mod": goMod,
			},
			start:        "proj",
			maxLockfiles: 2,
			root:         "proj",
			projects: []Project{
				{Dir: "a", Lockfiles: []Lockfile{{Path: "a/go.mod", Manager: "go"}}},
				{Dir: "b", Lockfiles: []Lockfile{{Path: "b/go.mod", Manager: "go"}}},
			},
			capped: "stopped after 2 lockfiles",
		},
		{
			id: "reaching the cap exactly is not stopping early",
			files: map[string]string{
				"proj/a/go.mod": goMod,
				"proj/b/go.mod": goMod,
			},
			start:        "proj",
			maxLockfiles: 2,
			root:         "proj",
			projects: []Project{
				{Dir: "a", Lockfiles: []Lockfile{{Path: "a/go.mod", Manager: "go"}}},
				{Dir: "b", Lockfiles: []Lockfile{{Path: "b/go.mod", Manager: "go"}}},
			},
		},
		{
			id:     "stops when the time is up",
			files:  map[string]string{"proj/go.mod": goMod},
			start:  "proj",
			noTime: true,
			root:   "proj",
			capped: "stopped after 0s",
		},
		{
			id: "nothing below start falls back to the git root",
			files: map[string]string{
				"repo/.git/HEAD":            "ref: refs/heads/main\n",
				"repo/go.mod":               goMod,
				"repo/docs/guide/notes.txt": "",
			},
			start:    "repo/docs/guide",
			root:     "repo",
			projects: []Project{{Dir: "", Lockfiles: []Lockfile{{Path: "go.mod", Manager: "go"}}}},
		},
		{
			id: "a .git file marks a worktree root",
			files: map[string]string{
				"wt/.git":           "gitdir: ../repo/.git/worktrees/wt\n",
				"wt/go.mod":         goMod,
				"wt/docs/notes.txt": "",
			},
			start:    "wt/docs",
			root:     "wt",
			projects: []Project{{Dir: "", Lockfiles: []Lockfile{{Path: "go.mod", Manager: "go"}}}},
		},
		{
			id: "never climbs above home for a git root",
			files: map[string]string{
				"../.git/HEAD":    "ref: refs/heads/main\n",
				"../go.mod":       goMod,
				"empty/notes.txt": "",
			},
			start: "empty",
			root:  "empty",
		},
		{
			id: "a find below start keeps start as the root",
			files: map[string]string{
				"repo/.git/HEAD":  "ref: refs/heads/main\n",
				"repo/go.mod":     goMod,
				"repo/sub/go.mod": goMod,
			},
			start:    "repo/sub",
			root:     "repo/sub",
			projects: []Project{{Dir: "", Lockfiles: []Lockfile{{Path: "go.mod", Manager: "go"}}}},
		},
		{
			id: "a home folder kept in git is never the fallback",
			files: map[string]string{
				".git/HEAD":       "ref: refs/heads/main\n",
				"code/app/go.mod": goMod,
				"Downloads/a.txt": "",
			},
			start: "Downloads",
			root:  "Downloads",
		},
		{
			id:    "a start that can't be read is an error",
			start: "missing",
			err:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			t.Setenv("HOME", home)
			if err := os.MkdirAll(home, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range tt.files {
				p := filepath.Join(home, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tt.maxDepth != 0 {
				set(t, &MaxDepth, tt.maxDepth)
			}
			if tt.maxLockfiles != 0 {
				set(t, &MaxLockfiles, tt.maxLockfiles)
			}
			if tt.noTime {
				set(t, &Budget, 0)
			}

			got, err := Find(context.Background(), filepath.Join(home, tt.start))
			if tt.err {
				if err == nil {
					t.Errorf("got %+v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := Scan{Root: filepath.Join(home, tt.root), Projects: tt.projects, Capped: tt.capped}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got  %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestFixCommand(t *testing.T) {
	tests := []struct {
		id      string
		pkg     provider.Package
		version string
		want    string
	}{
		{
			id:      "a locked version that a shell would run gets no command",
			pkg:     provider.Package{Source: "cargo", Name: "smallvec", Version: "0.6.9;echo${IFS}INJECTED;#", Dependency: true},
			version: "0.6.14",
			want:    "",
		},
		{
			id:      "nor does a name with spaces or quotes",
			pkg:     provider.Package{Source: "npm", Name: "left-trim'; rm -rf ~ #"},
			version: "1.0.3",
			want:    "",
		},
		{
			id:      "nor a fix version that isn't a plain version",
			pkg:     provider.Package{Source: "npm", Name: "left-trim"},
			version: "1.0.3 && curl evil.test",
			want:    "",
		},
		{
			id:      "npm transitive updates in place",
			pkg:     provider.Package{Source: "npm", Name: "tinyhash", Dependency: true},
			version: "0.4.2",
			want:    "npm update tinyhash",
		},
		{
			id:      "npm direct",
			pkg:     provider.Package{Source: "npm", Name: "left-trim"},
			version: "1.2.4",
			want:    "npm install left-trim@1.2.4",
		},
		{
			id:      "npm direct dev",
			pkg:     provider.Package{Source: "npm", Name: "inkpot", Dev: true},
			version: "3.1.1",
			want:    "npm install -D inkpot@3.1.1",
		},
		{
			id:      "composer transitive updates in place",
			pkg:     provider.Package{Source: "composer", Name: "acme/numbers", Dependency: true},
			version: "1.4.3",
			want:    "composer update acme/numbers",
		},
		{
			id:      "composer direct",
			pkg:     provider.Package{Source: "composer", Name: "acme/ledger"},
			version: "2.3.1",
			want:    "composer require acme/ledger:^2.3.1",
		},
		{
			id:      "composer direct dev",
			pkg:     provider.Package{Source: "composer", Name: "acme/fixture-kit", Dev: true},
			version: "1.1.1",
			want:    "composer require --dev acme/fixture-kit:^1.1.1",
		},
		{
			id:      "go adds the v that OSV leaves off",
			pkg:     provider.Package{Source: "go", Name: "example.com/tidyup", Origin: "example.com/tidyup", Dependency: true},
			version: "1.4.1",
			want:    "go get example.com/tidyup@v1.4.1",
		},
		{
			id:      "go keeps a v already there",
			pkg:     provider.Package{Source: "go", Name: "example.com/tidyup", Origin: "example.com/tidyup"},
			version: "v1.4.1",
			want:    "go get example.com/tidyup@v1.4.1",
		},
		{
			id:      "uv",
			pkg:     provider.Package{Source: "uv", Name: "tinyhash", Dependency: true},
			version: "0.4.2",
			want:    "uv lock --upgrade-package tinyhash",
		},
		{
			id:      "poetry transitive",
			pkg:     provider.Package{Source: "poetry", Name: "tinyhash", Dependency: true},
			version: "0.4.2",
			want:    "poetry update tinyhash",
		},
		{
			id:      "poetry direct rewrites the requirement, which may pin",
			pkg:     provider.Package{Source: "poetry", Name: "tinyhash"},
			version: "0.4.2",
			want:    "poetry add tinyhash@^0.4.2",
		},
		{
			id:      "uv direct rewrites the requirement",
			pkg:     provider.Package{Source: "uv", Name: "tinyhash"},
			version: "0.4.2",
			want:    `uv add "tinyhash>=0.4.2"`,
		},
		{
			id:      "cargo direct crosses a major with cargo add",
			pkg:     provider.Package{Source: "cargo", Name: "tinyhash", Version: "0.7.3"},
			version: "0.8.6",
			want:    "cargo add tinyhash@0.8.6",
		},
		{
			id:      "pip names the file to edit",
			pkg:     provider.Package{Source: "pip", Name: "checkmate", Lockfile: "tools/requirements-dev.txt"},
			version: "9.1.1",
			want:    "pin checkmate==9.1.1 in requirements-dev.txt",
		},
		{
			id:      "cargo",
			pkg:     provider.Package{Source: "cargo", Name: "tinyhash", Version: "0.4.1", Dependency: true},
			version: "0.4.2",
			want:    "cargo update -p tinyhash@0.4.1 --precise 0.4.2",
		},
		{
			id:      "composer drops the v from a fix version",
			pkg:     provider.Package{Source: "composer", Name: "acme/ledger"},
			version: "v2.3.1",
			want:    "composer require acme/ledger:^2.3.1",
		},
		{
			id:      "a source with no project lockfile",
			pkg:     provider.Package{Source: "brew", Name: "anvil"},
			version: "0.2.94",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := FixCommand(tt.pkg, tt.version); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := Find(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Errorf("got %+v %v, want the cancellation, not a capped scan", got, err)
	}
}
