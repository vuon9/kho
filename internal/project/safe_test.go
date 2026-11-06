package project

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadingAnUntrustedProject(t *testing.T) {
	escape := "\x1b]52;c;cHduZWQ=\a\x1b[8m"
	tests := []struct {
		id    string
		setup func(t *testing.T, dir string)
		check func(Scan) string
	}{
		{"a lockfile linked to a file outside the folder is refused, and its contents never show", func(t *testing.T, dir string) {
			secret := filepath.Join(filepath.Dir(dir), "secret.txt")
			os.WriteFile(secret, []byte("GITHUB_TOKEN=ghp_notreal\n"), 0o600)
			os.Symlink(secret, filepath.Join(dir, "go.mod"))
		}, func(s Scan) string {
			lf := s.Projects[0].Lockfiles[0]
			if strings.Contains(lf.Err, "ghp_") || !strings.Contains(lf.Err, "is a link") || len(lf.Packages) != 0 {
				return fmt.Sprintf("lockfile %+v", lf)
			}
			return ""
		}},
		{"a FIFO named like a lockfile is refused instead of blocking", func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "package-lock.json"), 0o644); err != nil {
				t.Skip(err)
			}
		}, func(s Scan) string {
			if lf := s.Projects[0].Lockfiles[0]; !strings.Contains(lf.Err, "not a regular file") {
				return fmt.Sprintf("lockfile %+v", lf)
			}
			return ""
		}},
		{"a lockfile over the size cap is refused", func(t *testing.T, dir string) {
			set(t, &maxFileBytes, 16)
			os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\nrequire example.com/y v1.0.0\n"), 0o644)
		}, func(s Scan) string {
			if lf := s.Projects[0].Lockfiles[0]; !strings.Contains(lf.Err, "larger than") {
				return fmt.Sprintf("lockfile %+v", lf)
			}
			return ""
		}},
		{"escape sequences in names, versions and chains are dropped", func(t *testing.T, dir string) {
			lock := `{"packages":[{"name":"acme/ink\u001b]52;c;cHduZWQ=\u0007pot","version":"1.0.0\u202e","require":{"acme/dep\u001b[8m":"*"}},` +
				`{"name":"acme/dep\u001b[8m","version":"2.0.0"}],"packages-dev":[]}`
			os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0o644)
		}, func(s Scan) string {
			for _, p := range s.Projects[0].Lockfiles[0].Packages {
				if strings.ContainsAny(p.Name+p.Version+strings.Join(p.Via, ""), "\x1b\a\u202e") {
					return fmt.Sprintf("package %q %q via %q", p.Name, p.Version, p.Via)
				}
			}
			if n := len(s.Projects[0].Lockfiles[0].Packages); n != 2 {
				return fmt.Sprintf("%d packages", n)
			}
			return ""
		}},
		{"a folder whose name carries an escape is skipped", func(t *testing.T, dir string) {
			sub := filepath.Join(dir, "sub"+escape)
			os.MkdirAll(sub, 0o755)
			os.WriteFile(filepath.Join(sub, "go.mod"), []byte("module example.com/x\n"), 0o644)
			os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/y\n"), 0o644)
		}, func(s Scan) string {
			if len(s.Projects) != 1 || s.Projects[0].Dir != "" {
				return fmt.Sprintf("projects %+v", s.Projects)
			}
			return ""
		}},
		{"a chain of ten thousand packages reads quickly, with each path cut short", func(t *testing.T, dir string) {
			var b strings.Builder
			b.WriteString(`{"packages":[`)
			for i := range 10000 {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"name":"acme/p%d","version":"1.0.0","require":{"acme/p%d":"*"}}`, i, i+1)
			}
			b.WriteString(`],"packages-dev":[]}`)
			os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(b.String()), 0o644)
			os.WriteFile(filepath.Join(dir, "composer.json"), []byte(`{"require":{"acme/p0":"*"}}`), 0o644)
		}, func(s Scan) string {
			pkgs := s.Projects[0].Lockfiles[0].Packages
			for _, p := range pkgs {
				if len(p.Via) > chainHead+chainTail+1 {
					return fmt.Sprintf("%s has a %d long chain", p.Name, len(p.Via))
				}
			}
			if len(pkgs) != 10000 {
				return fmt.Sprintf("%d packages", len(pkgs))
			}
			return ""
		}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			dir := filepath.Join(home, "proj")
			os.MkdirAll(dir, 0o755)
			tt.setup(t, dir)
			start := time.Now()
			s, err := Find(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("took %s", took)
			}
			if why := tt.check(s); why != "" {
				t.Error(why)
			}
		})
	}
}
