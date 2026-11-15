package provider

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseSkillHits(t *testing.T) {
	data := []byte(`{"query":"yaml","skills":[
		{"id":"acme/skills/yaml","source":"acme/skills","skillId":"yaml","name":"yaml","installs":1079},
		{"id":"acme/skills/k8s","source":"acme/skills","skillId":"k8s-yaml","name":"k8s-yaml","installs":738}]}`)
	got, err := parseSkillHits(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Source != "acme/skills" || got[0].SkillID != "yaml" || got[0].Installs != 1079 {
		t.Errorf("hits %+v", got)
	}
	if _, err := parseSkillHits([]byte(`{"error":"Query must be at least 2 characters"}`)); err == nil {
		t.Error("an API error should fail")
	}
	if _, err := parseSkillHits([]byte("nope")); err == nil {
		t.Error("bad JSON should fail")
	}
}

func TestSkillsSearch(t *testing.T) {
	old := skillSearch
	t.Cleanup(func() { skillSearch = old })
	skillSearch = func(_ context.Context, query string) ([]skillHit, error) {
		if query != "yaml" {
			t.Errorf("asked skills.sh for %q", query)
		}
		return []skillHit{
			{ID: "acme/skills/yaml", Source: "acme/skills", SkillID: "yaml", Name: "yaml", Installs: 1079},
			{ID: "acme/skills/k8s", Source: "acme/skills", SkillID: "k8s-yaml", Name: "k8s-yaml", Installs: 738},
		}, nil
	}
	got, err := Skills{}.Search(context.Background(), "yaml", 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{
		Source: "skills", Name: "yaml", Desc: "1079 installs", Latest: SkillNewest,
		Origin: "acme/skills", Homepage: "https://www.skills.sh/acme/skills/yaml",
		Repo: "acme/skills", Entry: "yaml",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := (Skills{}).Search(context.Background(), "y", 5); err == nil {
		t.Error("a one character search should fail")
	}
}

func TestSkillsFind(t *testing.T) {
	old := skillSearch
	t.Cleanup(func() { skillSearch = old })
	asked := 0
	skillSearch = func(_ context.Context, query string) ([]skillHit, error) {
		asked++
		if query != "yaml" {
			t.Errorf("asked for %q", query)
		}
		return []skillHit{{ID: "acme/skills/yaml", Source: "acme/skills", SkillID: "yaml", Name: "yaml", Installs: 2}}, nil
	}
	p, err := Skills{}.Find(context.Background(), "skills", "acme/skills/yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != "skills" || p.Name != "yaml" || p.Repo != "acme/skills" || p.Latest != SkillNewest {
		t.Errorf("path find %+v", p)
	}
	if asked != 0 {
		t.Errorf("a repo path search should not read the registry, asked %d", asked)
	}
	p, err = Skills{}.Find(context.Background(), "skills", "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Entry != "yaml" || asked != 1 {
		t.Errorf("exact find %+v, asked %d", p, asked)
	}
	skillSearch = func(context.Context, string) ([]skillHit, error) { return nil, errors.New("down") }
	if _, err := (Skills{}).Find(context.Background(), "skills", "zzzz"); err == nil {
		t.Error("a failed search should fail the find")
	}
}

func TestSkillDocPath(t *testing.T) {
	tests := []struct {
		id    string
		paths []string
		slug  string
		want  string
	}{
		{"a root SKILL.md wins", []string{"SKILL.md", "skills/pdf/SKILL.md"}, "pdf", "SKILL.md"},
		{"the folder named for the skill", []string{"a/SKILL.md", "pdf/SKILL.md", "b/SKILL.md"}, "pdf", "pdf/SKILL.md"},
		{"the only one when the name differs", []string{"a/SKILL.md"}, "pdf", "a/SKILL.md"},
		{"nothing when several do not match", []string{"a/SKILL.md", "b/SKILL.md"}, "pdf", ""},
		{"no SKILL.md", []string{"README.md"}, "pdf", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := skillDocPath(tt.paths, tt.slug); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadRemoteSkill(t *testing.T) {
	oldTree, oldFile := skillRepoTree, skillRepoFile
	t.Cleanup(func() { skillRepoTree, skillRepoFile = oldTree, oldFile })
	skillRepoTree = func(_ context.Context, repo string) ([]string, error) {
		if repo != "acme/skills" {
			t.Errorf("tree for %q", repo)
		}
		return []string{"README.md", "skills/other/SKILL.md", "skills/pdf/SKILL.md"}, nil
	}
	skillRepoFile = func(_ context.Context, repo, file string) (string, error) {
		if repo != "acme/skills" || file != "skills/pdf/SKILL.md" {
			t.Errorf("read %q %q", repo, file)
		}
		return "---\nname: pdf\n---\n# PDF\nUse it.\n", nil
	}
	doc, err := ReadRemoteSkill(context.Background(), Package{Source: "skills", Name: "pdf", Entry: "pdf", Repo: "acme/skills"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc.Body, "Use it.") {
		t.Errorf("body %q", doc.Body)
	}
}
