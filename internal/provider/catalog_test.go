package provider

import (
	"context"
	"reflect"
	"testing"
)

func TestParseBrewSearch(t *testing.T) {
	out := []byte("==> Formulae\nanvil\ncobalt\n\n==> Casks\nfocusbar\n")
	want := []string{"anvil", "cobalt", "focusbar"}
	if got := parseBrewSearch(out); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := parseBrewSearch([]byte("Error: No formulae or casks found for \"zzzz\".\n")); len(got) != 0 {
		t.Errorf("an error line should not be a name: %v", got)
	}
}

func TestBrewCatalog(t *testing.T) {
	data := []byte(`{"formulae":[{"name":"anvil","tap":"homebrew/core","desc":"Run builds locally",
		"homepage":"https://example.com/anvil","versions":{"stable":"1.2.3"},
		"urls":{"stable":{"url":"https://github.com/acme/anvil/archive/v1.2.3.tar.gz"}}}],
		"casks":[{"token":"focusbar","tap":"homebrew/cask","desc":"Focus timer",
		"homepage":"https://example.com/focusbar","version":"4.5.6"}]}`)
	info, err := parseBrewCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Formulae) != 1 || len(info.Casks) != 1 {
		t.Fatalf("got %d formulae, %d casks", len(info.Formulae), len(info.Casks))
	}
	f := brewFormulaPackage(info.Formulae[0])
	if f.Source != "brew" || f.Name != "anvil" || f.Latest != "1.2.3" || f.Desc != "Run builds locally" ||
		f.Origin != "homebrew/core" || f.Repo != "acme/anvil" {
		t.Errorf("formula %+v", f)
	}
	c := brewCaskPackage(info.Casks[0])
	if c.Source != "cask" || c.Name != "focusbar" || c.Latest != "4.5.6" || c.Origin != "homebrew/cask" {
		t.Errorf("cask %+v", c)
	}
}

func TestParseNpmSearch(t *testing.T) {
	data := []byte(`[
		{"name":"yaml","version":"2.8.1","description":"YAML parser and stringifier",
		 "links":{"homepage":"https://example.com/yaml","repository":"git+https://github.com/acme/yaml.git"}},
		{"name":"@scope/tool","version":"1.2.3","description":"A scoped tool","links":{}}]`)
	got, err := parseNpmSearch(data, 20)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Source: "npm", Name: "yaml", Latest: "2.8.1", Desc: "YAML parser and stringifier",
			Homepage: "https://example.com/yaml", Repo: "acme/yaml", Origin: "npmjs.com"},
		{Source: "npm", Name: "@scope/tool", Latest: "1.2.3", Desc: "A scoped tool", Origin: "npmjs.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if got, _ := parseNpmSearch(data, 1); len(got) != 1 || got[0].Name != "yaml" {
		t.Errorf("limit not applied: %+v", got)
	}
	if got, err := parseNpmSearch([]byte("[]"), 20); err != nil || len(got) != 0 {
		t.Errorf("empty answer should be no results: %v %v", got, err)
	}
}

func TestRepositoryURL(t *testing.T) {
	tests := []struct {
		id  string
		in  any
		url string
	}{
		{"a string url", "git+https://github.com/acme/tool.git", "https://github.com/acme/tool.git"},
		{"an object url", map[string]any{"url": "git+https://github.com/acme/tool.git"}, "https://github.com/acme/tool.git"},
		{"a missing field", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := repositoryURL(tt.in); got != tt.url {
				t.Errorf("got %q, want %q", got, tt.url)
			}
		})
	}
}

func TestParsePackagistSearch(t *testing.T) {
	results := []packagistSearchResult{
		{Name: "acme/yaml", Description: "YAML for PHP", URL: "https://packagist.org/packages/acme/yaml",
			Repository: "https://github.com/acme/yaml"},
		{Name: "acme/other", Description: "Another package"},
	}
	got := parsePackagistSearch(results)
	want := []Package{
		{Source: "composer", Name: "acme/yaml", Desc: "YAML for PHP",
			Homepage: "https://packagist.org/packages/acme/yaml", Repo: "acme/yaml", Origin: "packagist.org"},
		{Source: "composer", Name: "acme/other", Desc: "Another package", Origin: "packagist.org"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestPackagistCandidate(t *testing.T) {
	data := []byte(`{"packages":{"acme/widget":[
		{"version":"2.0.0","time":"2026-01-02T03:04:05+00:00","description":"Widgets for PHP",
		 "homepage":"https://example.com/widget","source":{"url":"https://github.com/acme/widget.git"}},
		{"version":"1.9.0"}]}}`)
	meta, err := parsePackagistMeta(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := packagistCandidate("acme/widget", meta)
	if err != nil {
		t.Fatal(err)
	}
	want := Package{Source: "composer", Name: "acme/widget", Latest: "2.0.0", Desc: "Widgets for PHP",
		Homepage: "https://example.com/widget", Repo: "acme/widget", Origin: "packagist.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := packagistCandidate("acme/missing", meta); err == nil {
		t.Errorf("a missing package should be an error")
	}
}

func TestPypiCandidate(t *testing.T) {
	var r pypiProject
	r.Info.Name = "widget"
	r.Info.Version = "3.2.1"
	r.Info.Summary = "Widgets for Python"
	r.Info.HomePage = "https://example.com/widget"
	r.Info.ProjectURLs = map[string]string{"Source": "https://github.com/acme/widget"}
	got := pypiCandidate(r, "uv", "widget")
	want := Package{Source: "uv", Name: "widget", Latest: "3.2.1", Desc: "Widgets for Python",
		Homepage: "https://example.com/widget", Repo: "acme/widget", Origin: "pypi.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestGoBinName(t *testing.T) {
	tests := []struct{ id, path, name string }{
		{"a module root", "example.com/tool", "tool"},
		{"a major version suffix", "example.com/tool/v2", "tool"},
		{"a package inside a module", "example.com/tool/cmd/runner", "runner"},
		{"a command under a major version", "example.com/tool/v2/cmd/runner", "runner"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := goBinName(tt.path); got != tt.name {
				t.Errorf("got %q, want %q", got, tt.name)
			}
		})
	}
}

func TestInstallNewCmd(t *testing.T) {
	tests := []struct {
		id      string
		pkg     Package
		version string
		args    []string
		err     string
	}{
		{id: "a formula", pkg: Package{Source: "brew", Name: "anvil", Latest: "1.2.3"}, version: "1.2.3",
			args: []string{"brew", "install", "--formula", "anvil"}},
		{id: "a cask", pkg: Package{Source: "cask", Name: "focusbar", Latest: "4.5.6"}, version: "4.5.6",
			args: []string{"brew", "install", "--cask", "focusbar"}},
		{id: "an older formula is refused", pkg: Package{Source: "brew", Name: "anvil", Latest: "1.2.3"}, version: "1.2.2",
			err: "Homebrew can only install the newest version, 1.2.3"},
		{id: "a scoped npm package", pkg: Package{Source: "npm", Name: "@scope/tool", Latest: "1.2.3"}, version: "1.2.3",
			args: []string{"npm", "install", "-g", "@scope/tool@1.2.3"}},
		{id: "a pipx tool", pkg: Package{Source: "pipx", Name: "bramble", Latest: "2.0.0"}, version: "2.0.0",
			args: []string{"pipx", "install", "bramble==2.0.0"}},
		{id: "a uv tool", pkg: Package{Source: "uv", Name: "ruff", Latest: "0.5.0"}, version: "0.5.0",
			args: []string{"uv", "tool", "install", "ruff==0.5.0"}},
		{id: "a composer package", pkg: Package{Source: "composer", Name: "acme/widget", Latest: "2.0.0"}, version: "2.0.0",
			args: []string{"composer", "global", "require", "acme/widget:2.0.0"}},
		{id: "a go tool", pkg: Package{Source: "go", Name: "tool", Origin: "example.com/tool", Entry: "example.com/tool", Latest: "v1.2.3"}, version: "v1.2.3",
			args: []string{"go", "install", "example.com/tool@v1.2.3"}},
		{id: "a go package with no entry", pkg: Package{Source: "go", Name: "tool", Latest: "v1.2.3"}, version: "v1.2.3",
			err: "this package has no main package path to install from"},
		{id: "a skill installs its newest commit", pkg: Package{Source: "skills", Name: "yaml", Entry: "yaml", Repo: "acme/skills", Latest: SkillNewest}, version: SkillNewest,
			args: []string{"npx", "-y", "skills", "add", "acme/skills", "--skill", "yaml", "-g", "-y", "--json"}},
		{id: "a skill display name installs by its slug", pkg: Package{Source: "skills", Name: "Command Development", Entry: "command-development", Repo: "acme/skills", Latest: SkillNewest}, version: SkillNewest,
			args: []string{"npx", "-y", "skills", "add", "acme/skills", "--skill", "command-development", "-g", "-y", "--json"}},
		{id: "a skill with no repo cannot install", pkg: Package{Source: "skills", Name: "yaml", Latest: SkillNewest}, version: SkillNewest,
			err: "this skill has no repository to install from"},
		{id: "mise is deferred", pkg: Package{Source: "mise", Name: "node", Latest: "24.0.0"}, version: "24.0.0",
			err: "kho can't install new mise packages yet"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			cmd, err := InstallNewCmd(tt.pkg, tt.version)
			if tt.err != "" {
				if err == nil || err.Error() != tt.err {
					t.Fatalf("got error %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cmd.Args, tt.args) {
				t.Errorf("got %v, want %v", cmd.Args, tt.args)
			}
		})
	}
}

func TestSearchCapabilities(t *testing.T) {
	names := func(ps []Provider) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.Name())
		}
		return out
	}
	if got, want := names(Searchers(All())), []string{"brew", "npm", "composer", "go", "skills"}; !reflect.DeepEqual(got, want) {
		t.Errorf("searchers %v, want %v", got, want)
	}
	if got, want := names(Finders(All())), []string{"brew", "npm", "composer", "pipx", "uv", "go", "skills"}; !reflect.DeepEqual(got, want) {
		t.Errorf("finders %v, want %v", got, want)
	}
	if p := ProviderNamed(All(), "uv"); p == nil || p.Name() != "uv" {
		t.Errorf("ProviderNamed(uv) = %v", p)
	}
	if p := ProviderNamed(All(), "nope"); p != nil {
		t.Errorf("ProviderNamed(nope) = %v", p)
	}
	if _, ok := Finders(All())[1].(Finder); !ok { // a sanity check of the helper's shape
		t.Errorf("Finders returned something that is not a Finder")
	}
}

func TestBrewVersionsForACandidate(t *testing.T) {
	rels, err := Brew{}.Versions(context.Background(), Package{Source: "brew", Name: "neon", Latest: "0.37.1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []Release{{Version: "0.37.1"}}; !reflect.DeepEqual(rels, want) {
		t.Errorf("candidate versions %+v, want %+v (no blank installed version)", rels, want)
	}

	installed, err := Brew{}.Versions(context.Background(), Package{
		Source: "brew", Name: "neon", Version: "0.36.0", Latest: "0.37.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Release{{Version: "0.37.1"}, {Version: "0.36.0"}}
	if !reflect.DeepEqual(installed, want) {
		t.Errorf("installed versions %+v, want %+v", installed, want)
	}
}
