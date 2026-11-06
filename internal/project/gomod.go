package project

import (
	"path/filepath"

	"golang.org/x/mod/modfile"

	"github.com/vuon9/kho/internal/provider"
)

// readGoMod reads the require lines of go.mod. A module replaced by another
// version is reported at the version that gets built, since a replace is how
// projects pin a fixed release. One replaced by a local folder is left out.
func readGoMod(dir, name string) ([]provider.Package, error) {
	file := filepath.Join(dir, name)
	data, err := readFile(file)
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse(name, data, nil)
	if err != nil {
		return nil, err
	}
	var pkgs []provider.Package
	for _, r := range f.Require {
		mod := r.Mod
		for _, rep := range f.Replace {
			if rep.Old.Path == r.Mod.Path && (rep.Old.Version == "" || rep.Old.Version == r.Mod.Version) {
				mod = rep.New
			}
		}
		if mod.Version == "" {
			continue
		}
		pkgs = append(pkgs, provider.Package{Name: mod.Path, Origin: mod.Path, Version: mod.Version, Dependency: r.Indirect})
	}
	return pkgs, nil
}
