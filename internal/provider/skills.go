package provider

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
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

	"github.com/vuon9/kho/internal/vuln"
)

// Skills reads what the skills CLI (`npx skills`) writes: the shared
// ~/.agents/skills folder and its lock file.
type Skills struct{}

// The skills CLI installs the newest commit, never a chosen version.
const SkillNewest = "newest"

// The skills CLI's own find uses this endpoint.
const skillsSearchURL = "https://www.skills.sh/api/search"

type skillHit struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	SkillID  string `json:"skillId"`
	Name     string `json:"name"`
	Installs int    `json:"installs"`
}

// A var so tests can answer it.
var skillSearch = searchSkillsSh

func (Skills) Name() string { return "skills" }

func (Skills) Missing() string {
	if _, err := os.Stat(filepath.Join(homeDir(), ".agents", "skills")); err != nil {
		return "no ~/.agents/skills directory"
	}
	return ""
}

//go:generate go run ./genagents v1.7.6

// An agent's global skills folder is the first of Dirs whose parent folder exists, or else the first, and one
// of Detect existing is the CLI's idea of an install; installed narrows that
// down. A universal agent reads ~/.agents/skills as well as its own folder.
// Paths start with ~/, a ${VAR:-default} the agent's own env setting
// overrides, or /.
type skillAgent struct {
	Name, Display string
	Dirs, Detect  []string
	Universal     bool
}

// dir is the agent's skills folder, or "" when that is ~/.agents/skills
// itself, or a link to it, and so it has no links of its own.
func (a skillAgent) dir(home string) string {
	d := expandPath(home, a.Dirs[0])
	for _, p := range a.Dirs {
		if _, err := os.Stat(filepath.Dir(expandPath(home, p))); err == nil {
			d = expandPath(home, p)
			break
		}
	}
	if resolved(d) == resolved(filepath.Join(home, ".agents", "skills")) {
		return ""
	}
	return d
}

func resolved(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// Worked out once per scan, not once per skill.
type placed struct {
	skillAgent
	dir       string
	installed bool
}

func place(home string, all bool) []placed {
	var installed, rest []placed
	for _, a := range skillAgents {
		on := a.installed(home)
		if !on && !all {
			continue
		}
		p := placed{a, a.dir(home), on}
		if on {
			installed = append(installed, p)
		} else {
			rest = append(rest, p)
		}
	}
	return append(installed, rest...)
}

func (a placed) shared(inShared bool) bool {
	return inShared && (a.Universal || a.dir == "")
}

func (a placed) link(home, name string, inShared bool) SkillLink {
	l := SkillLink{Agent: a.Name, Display: a.Display, Installed: a.installed, Shared: a.shared(inShared)}
	if a.dir == "" {
		l.Path, l.Kind = filepath.Join(home, ".agents", "skills", name), LinkNoFolder
		return l
	}
	l.Path = filepath.Join(a.dir, name)
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

// `skills add` makes a folder for every agent it links
// into, so an agent nobody installed still gets one, holding nothing but the
// chain of folders down to its skills folder. Anything else in a Detect
// folder, like the config or state the agent wrote, means the agent is
// installed.
func (a skillAgent) installed(home string) bool {
	for _, p := range a.Detect {
		d := expandPath(home, p)
		info, err := os.Stat(d)
		if err != nil {
			continue
		}
		if !info.IsDir() || !linksOnly(d) {
			return true
		}
	}
	return false
}

// linksOnly says whether dir holds only the folders the skills CLI made for
// links: every path down from it is a chain of folders ending in a skills
// folder. Several chains can share a parent, such as ~/.gemini holding the
// skills folders of two other agents. An empty folder is not linksOnly,
// because the CLI never leaves one behind, so a person or the agent made it.
// The depth cap stops links that lead back into themselves.
func linksOnly(dir string) bool { return linksOnlyBelow(dir, 8) }

func linksOnlyBelow(dir string, depth int) bool {
	if filepath.Base(dir) == "skills" {
		return true
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 || depth == 0 {
		return false
	}
	for _, e := range entries {
		sub := filepath.Join(dir, e.Name())
		if info, err := os.Stat(sub); err != nil || !info.IsDir() || !linksOnlyBelow(sub, depth-1) {
			return false
		}
	}
	return true
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

func (Skills) Search(ctx context.Context, query string, limit int) ([]Package, error) {
	query = strings.TrimSpace(query)
	if len([]rune(query)) < 2 {
		return nil, fmt.Errorf("a skill search needs two characters")
	}
	hits, err := skillSearch(ctx, query)
	if err != nil {
		return nil, err
	}
	limit = searchLimit(limit)
	out := make([]Package, 0, min(len(hits), limit))
	for _, h := range hits {
		if len(out) >= limit {
			break
		}
		if h.Source == "" || (h.Name == "" && h.SkillID == "") {
			continue
		}
		out = append(out, skillPackage(h))
	}
	return out, nil
}

func (Skills) Find(ctx context.Context, source, name string) (Package, error) {
	if source != "" && source != "skills" {
		return Package{}, fmt.Errorf("skills doesn't serve the %s source", source)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Package{}, fmt.Errorf("a skill install needs a skill name or an owner/repo/skill path")
	}
	if parts := strings.Split(name, "/"); len(parts) >= 3 {
		repo, skill := strings.Join(parts[:len(parts)-1], "/"), parts[len(parts)-1]
		return skillPackage(skillHit{Source: repo, SkillID: skill, Name: skill}), nil
	}
	hits, err := Skills{}.Search(ctx, name, 20)
	if err != nil {
		return Package{}, err
	}
	for _, p := range hits {
		if strings.EqualFold(p.Name, name) || strings.EqualFold(p.Entry, name) {
			return p, nil
		}
	}
	return Package{}, fmt.Errorf("no skill named %s", name)
}

func skillPackage(h skillHit) Package {
	skill := h.SkillID
	if skill == "" {
		skill = h.Name
	}
	name := h.Name
	if name == "" {
		name = skill
	}
	desc := ""
	if h.Installs > 0 {
		desc = fmt.Sprintf("%d installs", h.Installs)
	}
	// Entry carries the slug the skills CLI installs. Name is what the
	// registry shows, which may be a display name with spaces.
	return Package{
		Source: "skills", Name: name, Desc: desc, Latest: SkillNewest,
		Origin: h.Source, Homepage: vuln.SkillPage(h.Source, skill), Repo: h.Source, Entry: skill,
	}
}

func searchSkillsSh(ctx context.Context, query string) ([]skillHit, error) {
	var raw json.RawMessage
	header := http.Header{"User-Agent": {khoUserAgent}}
	if err := getJSON(ctx, skillsSearchURL+"?q="+url.QueryEscape(query), header, &raw); err != nil {
		return nil, fmt.Errorf("skills.sh: %w", err)
	}
	return parseSkillHits(raw)
}

func parseSkillHits(data []byte) ([]skillHit, error) {
	var resp struct {
		Skills []skillHit `json:"skills"`
		Error  string     `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("skills.sh search: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("skills.sh: %s", resp.Error)
	}
	return resp.Skills, nil
}

// As in the skills CLI, only a folder with a SKILL.md is a skill, so a link whose skill was removed, or a category folder of
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
	agents := place(home, false)
	own := make([]map[string]bool, len(agents))
	unmanaged := map[string]string{}
	for i, a := range agents {
		if a.dir == "" {
			continue
		}
		own[i] = skillNames(a.dir)
		for name := range own[i] {
			if !canonical[name] {
				unmanaged[name] = cmp.Or(unmanaged[name], filepath.Join(a.dir, name))
			}
		}
	}
	// Own, Sees and the order match the Links tab.
	seenBy := func(name string) []string {
		type seen struct {
			agent string
			rank  int
		}
		var as []seen
		for i, a := range agents {
			l := SkillLink{Installed: true, Shared: a.shared(canonical[name]), Own: own[i][name]}
			if l.Sees() {
				as = append(as, seen{a.Name, rank(l)})
			}
		}
		slices.SortStableFunc(as, func(a, b seen) int { return cmp.Compare(a.rank, b.rank) })
		var names []string
		for _, s := range as {
			names = append(names, s.agent)
		}
		return names
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
			p.Note = noteNoLock + " entry, the skills CLI can't update it"
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
			Note:    noteOnlyIn + " " + strings.Join(as, ", ") + ", not managed by the skills CLI",
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

// For a pinned skill a changed tree hash means a newer version exists
// upstream, not that `skills update` will move it.
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
			pkgs[i].Note = noteLatestUnknown + ": " + err.Error()
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

// Skills have no published versions of their own, so commits stand in.
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

type SkillDoc struct {
	Meta   [][2]string
	Body   string
	Readme string
	Files  []string
}

// Tests feed both.
var (
	skillRepoTree = fetchGitTreePaths
	skillRepoFile = fetchRepoFile
)

// The file's folder must be the skill's slug, so a repo with several skills
// loads the one the row names.
func ReadRemoteSkill(ctx context.Context, p Package) (SkillDoc, error) {
	if p.Path != "" {
		return ReadSkill(p)
	}
	if p.Repo == "" {
		return SkillDoc{}, errors.New("this skill has no repository to read from")
	}
	paths, err := skillRepoTree(ctx, p.Repo)
	if err != nil {
		return SkillDoc{}, err
	}
	file := skillDocPath(paths, p.Entry)
	if file == "" {
		return SkillDoc{}, fmt.Errorf("no SKILL.md for %s in %s", p.Name, p.Repo)
	}
	data, err := skillRepoFile(ctx, p.Repo, file)
	if err != nil {
		return SkillDoc{}, err
	}
	var doc SkillDoc
	doc.Meta, doc.Body = frontMatter(data)
	return doc, nil
}

func skillDocPath(paths []string, slug string) string {
	var root, match, only string
	count := 0
	for _, p := range paths {
		if p != "SKILL.md" && !strings.HasSuffix(p, "/SKILL.md") {
			continue
		}
		count++
		if p == "SKILL.md" {
			root = p
			continue
		}
		dir := path.Base(path.Dir(p))
		if slug != "" && strings.EqualFold(dir, slug) {
			match = p
			continue
		}
		only = p
	}
	switch {
	case match != "":
		return match
	case root != "":
		return root
	case count == 1:
		return only
	}
	return ""
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

type LinkKind string

const (
	LinkMissing LinkKind = "missing"
	LinkSymlink LinkKind = "link"
	LinkCopy    LinkKind = "copy"
	// LinkNoFolder is an agent whose only skills folder is ~/.agents/skills.
	LinkNoFolder LinkKind = "no folder"
)

type SkillLink struct {
	Agent, Display string
	Path           string
	Kind           LinkKind
	Target         string
	// Shared is true when the agent reads ~/.agents/skills and the skill is
	// there, so it sees the skill without a link of its own.
	Shared bool
	// A broken link is still a link to remove, but not a skill the agent loads.
	Own       bool
	Installed bool
}

func (l SkillLink) Sees() bool {
	return l.Shared || l.Own
}

func rank(l SkillLink) int {
	switch {
	case l.Installed && l.Own:
		return 0
	case l.Installed && l.Shared:
		return 1
	case l.Installed:
		return 2
	}
	return 3
}

// An agent that already sees the skill would load it twice.
func (l SkillLink) CanLink() bool {
	return l.Kind == LinkMissing && !l.Shared
}

func RealPath(p Package) string {
	if real, err := filepath.EvalSymlinks(p.Path); err == nil {
		return real
	}
	return p.Path
}

func SkillLinks(p Package, all bool) []SkillLink {
	return skillLinks(homeDir(), p, all)
}

func skillLinks(home string, p Package, all bool) []SkillLink {
	inShared := isSkill(filepath.Join(home, ".agents", "skills", p.Name))
	var links []SkillLink
	for _, a := range place(home, all) {
		links = append(links, a.link(home, p.Name, inShared))
	}
	slices.SortStableFunc(links, func(a, b SkillLink) int { return cmp.Compare(rank(a), rank(b)) })
	return links
}

// A skill in
// ~/.agents/skills is linked at its entry there, as the CLI's links are, so
// removing it there removes it for every agent. Any other skill sits in an
// agent's own folder, maybe as that agent's link, so it is linked at its real
// folder and outlives that agent's link.
func LinkTarget(p Package) string {
	return linkTarget(homeDir(), p)
}

func linkTarget(home string, p Package) string {
	if filepath.Dir(p.Path) == filepath.Join(home, ".agents", "skills") {
		return p.Path
	}
	return RealPath(p)
}

// Relative, like the links the skills CLI makes.
func LinkSkill(l SkillLink, p Package) error {
	return linkSkill(homeDir(), l, p)
}

func linkSkill(home string, l SkillLink, p Package) error {
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
	// would make a path worked out from dir wrong. Of the target only home is
	// resolved: a home under a symlink still gives a short path, and the link
	// still goes through ~/.agents/skills when that is a link itself, as the
	// CLI's do and as the dialog and history say.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return err
	}
	target := linkTarget(home, p)
	if under, err := filepath.Rel(home, target); err == nil && filepath.IsLocal(under) {
		target = filepath.Join(realHome, under)
	}
	rel, err := filepath.Rel(realDir, target)
	if err != nil {
		return err
	}
	return os.Symlink(rel, l.Path)
}

// It never deletes a copied folder.
// It looks at the path again rather than trust l.Kind, which kho may have
// read minutes ago.
func UnlinkSkill(l SkillLink) error {
	if l.Kind == LinkNoFolder {
		return fmt.Errorf("%s has no skills folder of its own, so kho won't remove %s", l.Agent, l.Path)
	}
	if info, err := os.Lstat(l.Path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s is not a symlink, so kho won't remove it", l.Path)
	}
	return os.Remove(l.Path)
}
