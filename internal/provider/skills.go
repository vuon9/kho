package provider

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// Skills reads what the skills CLI (`npx skills`) writes: the shared
// ~/.agents/skills folder and its lock file.
type Skills struct{}

func (Skills) Name() string { return "skills" }

func (Skills) Missing() string {
	if _, err := os.Stat(filepath.Join(homeDir(), ".agents", "skills")); err != nil {
		return "no ~/.agents/skills directory"
	}
	return ""
}

//go:generate go run ./genagents v1.7.6

// skillAgent is one agent the skills CLI supports. Dir is its global skills
// folder, and any Detect path existing means it is installed. Paths start
// with ~/, a ${VAR:-default} the agent's own env setting overrides, or /.
type skillAgent struct {
	Name, Display, Dir string
	Detect             []string
}

// dir is the agent's skills folder, or "" when it reads ~/.agents/skills
// itself and so has no links of its own.
func (a skillAgent) dir(home string) string {
	if d := expandPath(home, a.Dir); d != filepath.Join(home, ".agents", "skills") {
		return d
	}
	return ""
}

func (a skillAgent) installed(home string) bool {
	for _, p := range a.Detect {
		if _, err := os.Stat(expandPath(home, p)); err == nil {
			return true
		}
	}
	return false
}

var envDefault = regexp.MustCompile(`^\$\{(\w+):-([^}]*)\}`)

func expandPath(home, p string) string {
	if m := envDefault.FindStringSubmatch(p); m != nil {
		base := os.Getenv(m[1])
		if base == "" {
			base = expandPath(home, m[2])
		}
		return filepath.Join(base, p[len(m[0]):])
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

type lockEntry struct {
	Source          string `json:"source"`
	SourceType      string `json:"sourceType"`
	Ref             string `json:"ref"`
	SkillPath       string `json:"skillPath"`
	SkillFolderHash string `json:"skillFolderHash"`
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

func skillLockPath(home string) string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "skills", ".skill-lock.json")
	}
	return filepath.Join(home, ".agents", ".skill-lock.json")
}

func readSkillLock(home string) (map[string]lockEntry, error) {
	data, err := os.ReadFile(skillLockPath(home))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lock struct {
		Skills map[string]lockEntry `json:"skills"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("skill lock: %w", err)
	}
	return lock.Skills, nil
}

func (Skills) List(context.Context) ([]Package, error) {
	home := homeDir()
	lock, err := readSkillLock(home)
	if err != nil {
		return nil, err
	}
	return scanSkills(home, lock)
}

// skillNames lists the skills in dir. As in the skills CLI, an entry is a
// skill only when it holds a SKILL.md, so a link whose skill was removed, or a
// category folder of bundled skills, is not one.
func skillNames(dir string) map[string]bool {
	names := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "SKILL.md")); err == nil && !strings.HasPrefix(e.Name(), ".") {
			names[e.Name()] = true
		}
	}
	return names
}

func scanSkills(home string, lock map[string]lockEntry) ([]Package, error) {
	shared := filepath.Join(home, ".agents", "skills")
	canonical := skillNames(shared)
	var agents []skillAgent
	own := map[string]map[string]bool{}
	for _, a := range skillAgents {
		if !a.installed(home) {
			continue
		}
		agents = append(agents, a)
		if d := a.dir(home); d != "" {
			own[a.Name] = skillNames(d)
		}
	}

	var pkgs []Package
	for name := range canonical {
		p := Package{Source: "skills", Name: name, Version: "-", Path: filepath.Join(shared, name)}
		if e, ok := lock[name]; ok {
			p.Origin = e.Source
			p.Version = shortHash(e.SkillFolderHash)
			if e.SourceType == "github" {
				p.Repo = e.Source
			}
			// `skills update` checks a skill against its ref, so a ref holds it in place.
			if e.Ref != "" {
				p.Pinned = true
				p.Note = "pinned to " + shortRef(e.Ref)
			}
		} else {
			p.Note = "no lock entry, the skills CLI can't update it"
		}
		for _, a := range agents {
			if a.dir(home) == "" || own[a.Name][name] {
				p.Agents = append(p.Agents, a.Name)
			}
		}
		pkgs = append(pkgs, p)
	}

	unmanaged := map[string][]string{}
	paths := map[string]string{}
	for _, a := range agents {
		for name := range own[a.Name] {
			if !canonical[name] {
				unmanaged[name] = append(unmanaged[name], a.Name)
				paths[name] = cmp.Or(paths[name], filepath.Join(a.dir(home), name))
			}
		}
	}
	for name, as := range unmanaged {
		sort.Strings(as)
		pkgs = append(pkgs, Package{
			Source:  "skills",
			Name:    name,
			Version: "-",
			Path:    paths[name],
			Agents:  as,
			Note:    "only in " + strings.Join(as, ", ") + ", not managed by the skills CLI",
		})
	}
	sortByName(pkgs)
	return pkgs, nil
}

func shortHash(h string) string {
	if len(h) > 7 {
		return h[:7]
	}
	return h
}

func shortRef(ref string) string {
	if len(ref) == 40 {
		return ref[:7]
	}
	return ref
}

// Latest compares each skill folder's recorded tree hash with the folder's
// hash on the repo's default branch. For a pinned skill that means a newer
// version exists upstream, not that `skills update` will move it.
func (Skills) Latest(ctx context.Context, pkgs []Package) ([]Package, error) {
	lock, err := readSkillLock(homeDir())
	if err != nil {
		return pkgs, err
	}
	var sources []string
	for _, e := range lock {
		if e.SourceType == "github" && !slices.Contains(sources, e.Source) {
			sources = append(sources, e.Source)
		}
	}
	var mu sync.Mutex
	repos := map[string]map[string]string{}
	failed := map[string]error{}
	var g errgroup.Group
	g.SetLimit(8)
	for _, repo := range sources {
		g.Go(func() error {
			hashes, err := folderHashes(ctx, repo)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed[repo] = err
			}
			repos[repo] = hashes
			return nil
		})
	}
	g.Wait()

	for i, p := range pkgs {
		e, ok := lock[p.Name]
		if !ok || e.SourceType != "github" {
			continue
		}
		if err := failed[e.Source]; err != nil {
			pkgs[i].Note = "latest unknown: " + err.Error()
			continue
		}
		folder := skillFolder(e)
		latest, ok := repos[e.Source][folder]
		if !ok {
			pkgs[i].Note = "folder " + folder + " is gone upstream"
			continue
		}
		pkgs[i].Latest = shortHash(latest)
		pkgs[i].Outdated = latest != e.SkillFolderHash
	}
	return pkgs, nil
}

func skillFolder(e lockEntry) string {
	folder := path.Dir(e.SkillPath)
	if folder == "." {
		return ""
	}
	return folder
}

func (Skills) Deps(context.Context, Package) ([]Dep, error) { return nil, nil }

// Versions lists the commits that touched the skill's folder, since skills
// have no published versions of their own.
func (Skills) Versions(ctx context.Context, p Package) ([]Release, error) {
	lock, err := readSkillLock(homeDir())
	if err != nil {
		return nil, err
	}
	e, ok := lock[p.Name]
	if !ok || e.SourceType != "github" {
		return nil, errors.New("only skills installed from GitHub have a history")
	}
	var commits []struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message   string `json:"message"`
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := githubGet(ctx, "repos/"+e.Source+"/commits?per_page=50&path="+url.QueryEscape(skillFolder(e)), &commits); err != nil {
		return nil, err
	}
	var rels []Release
	for _, c := range commits {
		rels = append(rels, Release{Version: shortHash(c.SHA), Date: c.Commit.Committer.Date, Notes: c.Commit.Message, URL: c.HTMLURL})
	}
	return rels, nil
}

// SkillDoc is what a skill folder holds: SKILL.md's front matter and body,
// a README if there is one, and the folder's files.
type SkillDoc struct {
	Meta   [][2]string
	Body   string
	Readme string
	Files  []string
}

func ReadSkill(p Package) (SkillDoc, error) {
	var doc SkillDoc
	if p.Path == "" {
		return doc, errors.New("this skill has no folder on disk")
	}
	data, err := os.ReadFile(filepath.Join(p.Path, "SKILL.md"))
	if err != nil {
		return doc, err
	}
	doc.Meta, doc.Body = frontMatter(string(data))
	if readme, err := os.ReadFile(filepath.Join(p.Path, "README.md")); err == nil {
		doc.Readme = string(readme)
	}
	entries, _ := os.ReadDir(p.Path)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		doc.Files = append(doc.Files, name)
	}
	return doc, nil
}

// frontMatter splits "---\nkey: value\n---\nbody". Values that span lines
// keep only their first line.
func frontMatter(s string) ([][2]string, string) {
	rest, ok := strings.CutPrefix(s, "---\n")
	if !ok {
		return nil, s
	}
	head, body, ok := strings.Cut(rest, "\n---")
	if !ok {
		return nil, s
	}
	var meta [][2]string
	for line := range strings.Lines(head) {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\n"), ":")
		if ok && k != "" && !strings.HasPrefix(k, " ") {
			meta = append(meta, [2]string{k, strings.Trim(strings.TrimSpace(v), `"'`)})
		}
	}
	return meta, strings.TrimLeft(strings.TrimPrefix(body, "\n"), "-\n")
}

// SkillLink is how one agent sees a skill: through a symlink in its own
// skills folder, a copied folder, the shared ~/.agents/skills folder, or not.
type SkillLink struct {
	Agent, Display string
	Path           string
	Kind           string // "link", "copy", "missing", or "shared" for agents that read ~/.agents/skills
	Target         string
	// Shared is true when the agent reads ~/.agents/skills and the skill is
	// there, so it sees the skill without a link of its own.
	Shared    bool
	Installed bool
}

// RealPath follows any symlinks to the folder the skill's files live in.
func RealPath(p Package) string {
	if real, err := filepath.EvalSymlinks(p.Path); err == nil {
		return real
	}
	return p.Path
}

// SkillLinks says how each installed agent sees the skill, or every agent
// the skills CLI supports when all is set.
func SkillLinks(p Package, all bool) []SkillLink {
	return skillLinks(homeDir(), p, all)
}

func skillLinks(home string, p Package, all bool) []SkillLink {
	shared := filepath.Join(home, ".agents", "skills", p.Name)
	_, inShared := os.Stat(shared)
	var links []SkillLink
	for _, a := range skillAgents {
		installed := a.installed(home)
		if !installed && !all {
			continue
		}
		l := SkillLink{Agent: a.Name, Display: a.Display, Installed: installed}
		d := a.dir(home)
		if d == "" {
			l.Path, l.Kind, l.Shared = shared, "shared", inShared == nil
			links = append(links, l)
			continue
		}
		l.Path = filepath.Join(d, p.Name)
		info, err := os.Lstat(l.Path)
		switch {
		case err != nil:
			l.Kind = "missing"
		case info.Mode()&os.ModeSymlink != 0:
			l.Kind = "link"
			l.Target, _ = filepath.EvalSymlinks(l.Path)
		default:
			l.Kind = "copy"
		}
		links = append(links, l)
	}
	return links
}

// LinkSkill gives an agent its own symlink to the skill, relative like the
// ones the skills CLI makes.
func LinkSkill(l SkillLink, p Package) error {
	if l.Kind != "missing" {
		return fmt.Errorf("%s already has %s", l.Agent, l.Path)
	}
	dir := filepath.Dir(l.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Both ends resolved, or a symlinked parent like macOS's /var makes the
	// relative path wrong.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(realDir, RealPath(p))
	if err != nil {
		return err
	}
	return os.Symlink(rel, l.Path)
}

// UnlinkSkill removes an agent's symlink. It never deletes a copied folder.
func UnlinkSkill(l SkillLink) error {
	if l.Kind != "link" {
		return fmt.Errorf("%s is not a symlink, so kho won't remove it", l.Path)
	}
	return os.Remove(l.Path)
}
