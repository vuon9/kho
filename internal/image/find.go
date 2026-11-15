package image

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

// Tunables, package vars so tests can shrink them.
var (
	MaxDepth = 4
	MaxFiles = 100
	Budget   = 3 * time.Second
)

// walkWidth is how many folders the walk reads at once. Reading a folder is a
// disk wait, so a level with many siblings would otherwise spend its time
// waiting for each one in turn.
const walkWidth = 16

// folder is what reading one folder found: the folders to read next, and the
// files to read.
type folder struct {
	next  []string
	files []string
}

// Scan is what a folder holds: every image its Dockerfiles and compose files
// name, and the files that were read to find them.
type Scan struct {
	Root string `json:"root"`
	Refs []Ref  `json:"refs,omitempty"`
	// Files are the files read, relative to Root and slash separated.
	Files []string `json:"files,omitempty"`
	// Capped says why the walk stopped early, or is "".
	Capped string `json:"capped,omitempty"`
}

// Find walks down from start for Dockerfiles and compose files. It only reads
// files, and it never asks docker anything.
func Find(ctx context.Context, start string) (Scan, error) {
	root, err := filepath.Abs(start)
	if err != nil {
		return Scan{}, err
	}
	if _, err := os.ReadDir(root); err != nil {
		return Scan{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	s := Scan{Root: root}
	dirs := []string{""}
	for depth := 0; depth <= MaxDepth && len(dirs) > 0; depth++ {
		if ctx.Err() != nil {
			s.Capped = cappedBudget()
			break
		}
		var next []string
		folders, timedOut := readFolders(ctx, root, dirs)
		for _, f := range folders {
			next = append(next, f.next...)
			for _, path := range f.files {
				if ctx.Err() != nil {
					s.Capped = cappedBudget()
					break
				}
				if len(s.Files) >= MaxFiles {
					s.Capped = "stopped after " + itoa(MaxFiles) + " files"
					break
				}
				src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
				if err != nil {
					continue
				}
				s.Files = append(s.Files, path)
				if isCompose(filepath.Base(path)) {
					s.Refs = append(s.Refs, ParseCompose(path, src)...)
				} else {
					s.Refs = append(s.Refs, ParseDockerfile(path, src)...)
				}
			}
			if s.Capped != "" {
				break
			}
		}
		if s.Capped != "" {
			break
		}
		if timedOut {
			s.Capped = cappedBudget()
			break
		}
		dirs = next
	}
	// Stage aliases are kept for the report but are not images.
	kept := s.Refs[:0]
	for _, r := range s.Refs {
		if !r.StageRef {
			kept = append(kept, r)
		}
	}
	s.Refs = dedupe(kept)
	sort.SliceStable(s.Refs, func(i, j int) bool {
		if s.Refs[i].File != s.Refs[j].File {
			return s.Refs[i].File < s.Refs[j].File
		}
		return s.Refs[i].Line < s.Refs[j].Line
	})
	return s, nil
}

// readFolders reads a whole level of the walk at once. Each folder's answer
// lands in its own slot, so merging them back in order keeps the walk reading
// files in the same order as one folder at a time. A folder the walk could not
// read leaves an empty slot, as it would leave nothing behind. timedOut says
// the budget ran out before every folder was read.
func readFolders(ctx context.Context, root string, dirs []string) (folders []folder, timedOut bool) {
	out := make([]folder, len(dirs))
	var skipped atomic.Bool
	var g errgroup.Group
	g.SetLimit(walkWidth)
	for i, rel := range dirs {
		g.Go(func() error {
			if ctx.Err() != nil {
				skipped.Store(true)
				return nil
			}
			entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				return nil
			}
			f := folder{}
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() {
					if !skipDir[name] && !strings.HasPrefix(name, ".") {
						f.next = append(f.next, join(rel, name))
					}
					continue
				}
				if isImageFile(name) {
					f.files = append(f.files, join(rel, name))
				}
			}
			out[i] = f
			return nil
		})
	}
	_ = g.Wait()
	return out, skipped.Load()
}

// cappedBudget names the cap a walk that ran out of time hits.
func cappedBudget() string {
	return "stopped after " + Budget.String()
}

// dedupe drops the second reference to the same image from the same file,
// which a multi stage build often writes twice.
func dedupe(refs []Ref) []Ref {
	seen := map[string]bool{}
	out := refs[:0]
	for _, r := range refs {
		key := r.File + "|" + r.Image + "|" + r.Stage + r.Service
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

var skipDir = map[string]bool{
	"node_modules": true, "vendor": true, ".venv": true, "venv": true, "target": true,
	"dist": true, "build": true, "__pycache__": true, ".terraform": true, ".next": true,
	// The OS keeps its own data here: caches, app support, containers, never a
	// project. Reading it costs more than the rest of a home folder together.
	"Library": true,
}

func isImageFile(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case isCompose(name):
		return true
	case lower == "dockerfile" || lower == "containerfile":
		return true
	case strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile."):
		return true
	case strings.HasSuffix(lower, ".dockerfile"):
		return true
	}
	return false
}

func isCompose(name string) bool {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	base := strings.TrimSuffix(strings.TrimSuffix(lower, ".yml"), ".yaml")
	return base == "compose" || strings.HasPrefix(base, "compose.") || strings.HasPrefix(base, "docker-compose")
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
