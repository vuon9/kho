package provider

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func pypiFixture(name, version, summary string) pypiProject {
	var p pypiProject
	p.Info.Name, p.Info.Version, p.Info.Summary = name, version, summary
	return p
}

func TestParsePythonProjectNames(t *testing.T) {
	tests := []struct {
		id   string
		got  string
		want string
	}{
		{"pep 621 name", parsePyProjectName("[project]\nname = \"black\"\nversion = \"1\"\n"), "black"},
		{"poetry name", parsePyProjectName("[tool.poetry]\nname = 'black'\n"), "black"},
		{"a name outside the project sections", parsePyProjectName("[build-system]\nname = \"setuptools\"\n"), ""},
		{"setup.cfg metadata", parseSetupCfgName("[metadata]\nname = black\n"), "black"},
		{"setup.py name", parseSetupPyName("setup(name=\"black\", version=\"1\")"), "black"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestPythonSearchByKeyword(t *testing.T) {
	oldRepos, oldFile, oldDoc := gitHubPyRepos, pyRepoFile, pyPIProjectDoc
	t.Cleanup(func() { gitHubPyRepos, pyRepoFile, pyPIProjectDoc = oldRepos, oldFile, oldDoc })
	githubCalls := 0
	gitHubPyRepos = func(_ context.Context, query string, n int) ([]githubRepository, error) {
		githubCalls++
		if query != "formatter" || n < 1 {
			t.Errorf("asked GitHub for %q %d", query, n)
		}
		return []githubRepository{
			{FullName: "psf/black", Description: "A formatter", HTMLURL: "https://github.com/psf/black"},
			{FullName: "acme/fork", Fork: true},
			{FullName: "acme/docs", Description: "Docs only"},
		}, nil
	}
	pyRepoFile = func(_ context.Context, repo, file string) (string, error) {
		if repo == "psf/black" && file == "pyproject.toml" {
			return "[project]\nname = \"black\"\n", nil
		}
		return "", errRepoFileNotFound
	}
	pyPIProjectDoc = func(_ context.Context, name string) (pypiProject, error) {
		if name != "black" && name != "docs" {
			t.Errorf("asked PyPI for %q", name)
		}
		if name == "black" {
			return pypiFixture("black", "24.10.0", "The uncompromising code formatter"), nil
		}
		return pypiProject{}, errors.New("not found")
	}
	got, err := Pipx{}.Search(context.Background(), "formatter", 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{Source: "pipx", Name: "black", Latest: "24.10.0", Desc: "The uncompromising code formatter",
		Repo: "psf/black", Origin: "pypi.org"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	uv, err := Uv{}.Search(context.Background(), "formatter", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(uv) != 1 || uv[0].Source != "uv" || uv[0].Name != "black" {
		t.Errorf("uv search %+v", uv)
	}
	if githubCalls != 1 {
		t.Errorf("pipx and uv asked GitHub %d times, want one shared search", githubCalls)
	}
}

func TestPythonSearchAcceptsAPyPIProjectPage(t *testing.T) {
	oldRepos, oldDoc := gitHubPyRepos, pyPIProjectDoc
	t.Cleanup(func() { gitHubPyRepos, pyPIProjectDoc = oldRepos, oldDoc })
	gitHubPyRepos = func(context.Context, string, int) ([]githubRepository, error) {
		t.Error("a PyPI page should not ask GitHub for a keyword search")
		return nil, nil
	}
	pyPIProjectDoc = func(_ context.Context, name string) (pypiProject, error) {
		if name != "black" {
			t.Errorf("asked PyPI for %q", name)
		}
		return pypiFixture("black", "24.10.0", "A formatter"), nil
	}
	got, err := Pipx{}.Search(context.Background(), "https://pypi.org/project/black/24.10.0/", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "black" || got[0].Latest != "24.10.0" {
		t.Errorf("got %+v", got)
	}
}

func TestRepoPyPINameFallsBackToTheRepoName(t *testing.T) {
	oldFile := pyRepoFile
	t.Cleanup(func() { pyRepoFile = oldFile })
	pyRepoFile = func(context.Context, string, string) (string, error) { return "", errRepoFileNotFound }
	got, err := repoPyPIName(context.Background(), "psf/black")
	if err != nil {
		t.Fatal(err)
	}
	if got != "black" {
		t.Errorf("got %q, want black", got)
	}
}
