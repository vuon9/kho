package provider

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

func TestGoPathQuery(t *testing.T) {
	tests := []struct {
		id    string
		in    string
		path  string
		isOne bool
	}{
		{id: "a keyword is not a path", in: "staticcheck"},
		{id: "a word with a slash but no host is not a path", in: "net/http"},
		{id: "a module path", in: "example.com/tool", path: "example.com/tool", isOne: true},
		{id: "a package inside a module", in: "example.com/tool/cmd/app", path: "example.com/tool/cmd/app", isOne: true},
		{id: "a pasted pkg.go.dev package page", in: "https://pkg.go.dev/github.com/acme/tool", path: "github.com/acme/tool", isOne: true},
		{id: "a page with a version and a tab", in: "https://pkg.go.dev/github.com/acme/tool@v1.2.3?tab=versions", path: "github.com/acme/tool", isOne: true},
		{id: "a page without the scheme", in: "pkg.go.dev/example.com/tool/", path: "example.com/tool", isOne: true},
		{id: "a traversal is not a path", in: "example.com/../evil"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, ok := goPathQuery(tt.in)
			if got != tt.path || ok != tt.isOne {
				t.Errorf("goPathQuery(%q) = %q %v, want %q %v", tt.in, got, ok, tt.path, tt.isOne)
			}
		})
	}
}

func TestParseGoModModule(t *testing.T) {
	tests := []struct{ id, data, want string }{
		{"a module line", "module example.com/tool\n\ngo 1.22\n", "example.com/tool"},
		{"a quoted module path", "module \"example.com/tool\"\n", "example.com/tool"},
		{"no module line", "go 1.22\n", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := parseGoModModule(tt.data); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGoMainDirs(t *testing.T) {
	tests := []struct {
		id    string
		paths []string
		want  []string
	}{
		{id: "a root main comes first", paths: []string{"main.go", "cmd/app/main.go", "cmd/lib/util.go"}, want: []string{"."}},
		{id: "cmd tools", paths: []string{"go.mod", "cmd/app/main.go", "cmd/other/main.go"}, want: []string{"cmd/app", "cmd/other"}},
		{id: "test and vendor trees do not count",
			paths: []string{"testdata/main.go", "vendor/cmd/main.go", "internal/cmd/main.go", "cmd/app/main.go"}, want: []string{"cmd/app"}},
		{id: "a cmd file named after the tool is a main", paths: []string{"cmd/staticcheck/staticcheck.go", "cmd/structlayout/main.go"},
			want: []string{"cmd/staticcheck", "cmd/structlayout"}},
		{id: "root level tools", paths: []string{"tool/main.go", "docs/main.go"}, want: []string{"docs", "tool"}},
		{id: "nothing installable", paths: []string{"go.mod", "lib.go"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := goMainDirs(tt.paths); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGitHubRepos(t *testing.T) {
	data := []byte(`{"items":[
		{"full_name":"acme/tool","description":"A tool","html_url":"https://github.com/acme/tool","stargazers_count":42},
		{"full_name":"acme/fork","fork":true},
		{"full_name":"acme/old","archived":true}]}`)
	got, err := parseGitHubRepos(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 { // limit 0 keeps everything; forks are filtered by Search
		t.Fatalf("got %d repos", len(got))
	}
	if got[0].FullName != "acme/tool" || got[0].Stars != 42 || got[0].Description != "A tool" {
		t.Errorf("first repo %+v", got[0])
	}
	got, _ = parseGitHubRepos(data, 1)
	if len(got) != 1 || got[0].FullName != "acme/tool" {
		t.Errorf("limit not applied: %v", got)
	}
	if _, err := parseGitHubRepos([]byte("nope"), 3); err == nil {
		t.Error("bad JSON should fail")
	}
}

func TestGoBinFindWalksToTheModule(t *testing.T) {
	old := goModuleLatest
	t.Cleanup(func() { goModuleLatest = old })
	var asked []string
	goModuleLatest = func(_ context.Context, module string) (goModuleInfo, error) {
		asked = append(asked, module)
		if module == "example.com/tool" {
			return goModuleInfo{Version: "v1.2.3", RepoURL: "https://github.com/acme/tool"}, nil
		}
		return goModuleInfo{}, fmt.Errorf("no module")
	}
	p, err := GoBin{}.Find(context.Background(), "go", "example.com/tool/cmd/app")
	if err != nil {
		t.Fatal(err)
	}
	want := Package{Source: "go", Name: "app", Latest: "v1.2.3", Origin: "example.com/tool",
		Entry: "example.com/tool/cmd/app", Repo: "acme/tool"}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("got %+v, want %+v", p, want)
	}
	if len(asked) < 2 || asked[0] != "example.com/tool/cmd/app" || asked[len(asked)-1] != "example.com/tool" {
		t.Errorf("looked up %v, want the full path first and the module last", asked)
	}
	bare := GoBin{}
	if _, err := bare.Find(context.Background(), "go", "fzf"); err == nil {
		t.Error("a bare word is not a Go install path")
	}
}

func TestGoBinSearchByKeyword(t *testing.T) {
	oldRepos, oldMod, oldTree, oldLatest := gitHubRepos, goModFile, gitTreePaths, goModuleLatest
	t.Cleanup(func() { gitHubRepos, goModFile, gitTreePaths, goModuleLatest = oldRepos, oldMod, oldTree, oldLatest })
	gitHubRepos = func(_ context.Context, query string, n int) ([]githubRepository, error) {
		if query != "widget" || n < 1 {
			t.Errorf("asked GitHub for %q %d", query, n)
		}
		return []githubRepository{
			{FullName: "acme/tool", Description: "A tool for widgets", HTMLURL: "https://github.com/acme/tool", Stars: 10},
			{FullName: "acme/fork", Fork: true},
			{FullName: "mallory/tool", Description: "A copy whose go.mod names acme's module", Stars: 1},
		}, nil
	}
	goModFile = func(_ context.Context, repo string) (string, error) {
		if repo != "acme/tool" && repo != "mallory/tool" {
			return "", nil
		}
		return "example.com/tool", nil
	}
	// cmd/unreleased exists only on the default branch, after the tag.
	gitTreePaths = func(_ context.Context, repo, ref string) ([]string, error) {
		if ref == "c0ffee" {
			return []string{"go.mod", "cmd/widget/main.go"}, nil
		}
		return []string{"go.mod", "cmd/widget/main.go", "cmd/unreleased/main.go"}, nil
	}
	goModuleLatest = func(_ context.Context, module string) (goModuleInfo, error) {
		return goModuleInfo{Version: "v1.2.3", RepoURL: "https://github.com/acme/tool", Commit: "c0ffee"}, nil
	}
	got, err := GoBin{}.Search(context.Background(), "widget", 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{Source: "go", Name: "widget", Latest: "v1.2.3", Desc: "A tool for widgets",
		Homepage: "https://github.com/acme/tool", Repo: "acme/tool", Origin: "example.com/tool",
		Entry: "example.com/tool/cmd/widget"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestGoBinSearchAcceptsAPastedPath(t *testing.T) {
	oldRepos, oldLatest := gitHubRepos, goModuleLatest
	t.Cleanup(func() { gitHubRepos, goModuleLatest = oldRepos, oldLatest })
	gitHubRepos = func(context.Context, string, int) ([]githubRepository, error) {
		t.Error("a path query should not ask GitHub for a keyword search")
		return nil, nil
	}
	goModuleLatest = func(_ context.Context, module string) (goModuleInfo, error) {
		if module != "example.com/tool" {
			return goModuleInfo{}, fmt.Errorf("no module")
		}
		return goModuleInfo{Version: "v1.2.3"}, nil
	}
	got, err := GoBin{}.Search(context.Background(), "https://pkg.go.dev/example.com/tool?tab=versions", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Entry != "example.com/tool" || got[0].Name != "tool" {
		t.Errorf("got %+v", got)
	}
}

func TestRankGoMainDirs(t *testing.T) {
	dirs := []string{"cmd/structlayout", "cmd/staticcheck", "cmd/other"}
	rankGoMainDirs(dirs, "staticcheck", "dominikh/go-tools")
	if dirs[0] != "cmd/staticcheck" {
		t.Errorf("ranked %v, want staticcheck first", dirs)
	}
}
