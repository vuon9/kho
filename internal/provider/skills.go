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
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// Skills reads what the skills CLI (`npx skills`) writes: the shared
// ~/.agents/skills folder and its lock file.
type Skills struct{}

func (Skills) Name() string { return "skills" }

func (Skills) Available() bool {
	_, err := os.Stat(filepath.Join(homeDir(), ".agents", "skills"))
	return err == nil
}

//go:generate go run ./genagents v1.7.6

// skillAgent is one agent the skills CLI supports. Its global skills folder
// is the first of Dirs whose parent folder exists, or else the first, and any
// Detect path existing means it is installed. A universal agent reads
// ~/.agents/skills as well as its own folder. Paths start with ~/, a
// ${VAR:-default} the agent's own env setting overrides, or /.
type skillAgent struct {
	Name, Display string
	Dirs, Detect  []string
	Universal     bool
}

// dir is the agent's skills folder, or "" when that is ~/.agents/skills
// itself and so it has no links of its own.
func (a skillAgent) dir(home string) string {
	d := expandPath(home, a.Dirs[0])
	for _, p := range a.Dirs {
		if _, err := os.Stat(filepath.Dir(expandPath(home, p))); err == nil {
			d = expandPath(home, p)
			break
		}
	}
	if d == filepath.Join(home, ".agents", "skills") {
		return ""
	}
	return d
}

// link is how the agent sees the skill called name, where inShared says
// whether ~/.agents/skills holds it. Both the Links tab and the agents a
// listed skill names come from here, so they always agree.
func (a skillAgent) link(home, name string, inShared bool) SkillLink {
	d := a.dir(home)
	l := SkillLink{Agent: a.Name, Display: a.Display, Shared: inShared && (a.Universal || d == "")}
	if d == "" {
		l.Path, l.Kind = filepath.Join(home, ".agents", "skills", name), LinkNoFolder
		return l
	}
	l.Path = filepath.Join(d, name)
	info, err := os.Lstat(l.Path)
	switch {
	case err != nil:
		l.Kind = LinkMissing
	case info.Mode()&os.ModeSymlink != 0:
		l.Kind = LinkSymlink
		l.Target, _ = filepath.EvalSymlinks(l.Path)
	default:
		l.Kind = LinkCopy
	}
	l.Own = isSkill(l.Path)
	return l
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
		base := strings.TrimSpace(os.Getenv(m[1]))
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

// isSkill says whether dir holds a skill. As in the skills CLI, it does only
// with a SKILL.md, so a link whose skill was removed, or a category folder of
// bundled skills, is not one.
func isSkill(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "SKILL.md"))
	return err == nil
}

func skillNames(dir string) map[string]bool {
	names := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") && isSkill(filepath.Join(dir, e.Name())) {
			names[e.Name()] = true
		}
	}
	return names
}

func scanSkills(home string, lock map[string]lockEntry) ([]Package, error) {
	shared := filepath.Join(home, ".agents", "skills")
	canonical := skillNames(shared)
	var agents []skillAgent
	unmanaged := map[string]string{}
	for _, a := range skillAgents {
		if !a.installed(home) {
			continue
		}
		agents = append(agents, a)
		if d := a.dir(home); d != "" {
			for name := range skillNames(d) {
				if !canonical[name] {
					unmanaged[name] = cmp.Or(unmanaged[name], filepath.Join(d, name))
				}
			}
		}
	}
	seenBy := func(name string) []string {
		var as []string
		for _, a := range agents {
			if a.link(home, name, canonical[name]).Sees() {
				as = append(as, a.Name)
			}
		}
		return as
	}

	var pkgs []Package
	for name := range canonical {
		p := Package{Source: "skills", Name: name, Version: "-", Path: filepath.Join(shared, name), Agents: seenBy(name)}
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
		pkgs = append(pkgs, p)
	}
	for name, path := range unmanaged {
		as := seenBy(name)
		pkgs = append(pkgs, Package{
			Source:  "skills",
			Name:    name,
			Version: "-",
			Path:    path,
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

// LinkKind is what an agent's own skills folder holds for a skill.
type LinkKind string

const (
	LinkMissing LinkKind = "missing"
	LinkSymlink LinkKind = "link"
	LinkCopy    LinkKind = "copy"
	// LinkNoFolder is an agent whose only skills folder is ~/.agents/skills.
	LinkNoFolder LinkKind = "no folder"
)

// SkillLink is how one agent sees a skill: through what its own skills
// folder holds, through the shared ~/.agents/skills folder, or not at all.
type SkillLink struct {
	Agent, Display string
	Path           string
	Kind           LinkKind
	Target         string
	// Shared is true when the agent reads ~/.agents/skills and the skill is
	// there, so it sees the skill without a link of its own.
	Shared bool
	// Own is true when Path holds the skill, SKILL.md and all. A broken link
	// is still a link to remove, but not a skill the agent loads.
	Own       bool
	Installed bool
}

// Sees says whether the agent loads the skill, from its own folder or from
// ~/.agents/skills.
func (l SkillLink) Sees() bool {
	return l.Shared || l.Own
}

// CanLink says whether a link of the agent's own would add the skill: its
// folder has nothing by that name, and it doesn't see the skill already, so
// the link can't load it twice.
func (l SkillLink) CanLink() bool {
	return l.Kind == LinkMissing && !l.Shared
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
	inShared := isSkill(filepath.Join(home, ".agents", "skills", p.Name))
	var links []SkillLink
	for _, a := range skillAgents {
		installed := a.installed(home)
		if !installed && !all {
			continue
		}
		l := a.link(home, p.Name, inShared)
		l.Installed = installed
		links = append(links, l)
	}
	return links
}

// LinkSkill gives an agent its own symlink to the skill's entry, relative
// like the ones the skills CLI makes, so removing the entry removes the skill
// for every agent.
func LinkSkill(l SkillLink, p Package) error {
	switch {
	case l.CanLink():
	case l.Kind == LinkNoFolder:
		return fmt.Errorf("%s has no skills folder of its own", l.Agent)
	case l.Kind != LinkMissing:
		return fmt.Errorf("%s already has %s", l.Agent, l.Path)
	default:
		return fmt.Errorf("%s already sees %s through ~/.agents/skills", l.Agent, p.Name)
	}
	dir := filepath.Dir(l.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// A link is read from the folder it really sits in, so a symlinked parent
	// would make a path worked out from dir wrong.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(realDir, p.Path)
	if err != nil {
		return err
	}
	return os.Symlink(rel, l.Path)
}

// UnlinkSkill removes an agent's symlink. It never deletes a copied folder.
func UnlinkSkill(l SkillLink) error {
	if l.Kind != LinkSymlink {
		return fmt.Errorf("%s is not a symlink, so kho won't remove it", l.Path)
	}
	return os.Remove(l.Path)
}
