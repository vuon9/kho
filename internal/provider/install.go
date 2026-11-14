package provider

import (
	"errors"
	"fmt"
	"os/exec"
)

// InstallNewCmd builds the command that installs a package the machine does
// not have yet through its own package manager, or says why kho can't. p comes
// from a Searcher or a Finder, so Version is empty and Latest is the newest
// version the registry gave.
func InstallNewCmd(p Package, version string) (*exec.Cmd, error) {
	if version == "" {
		return nil, fmt.Errorf("no version to install for %s", p.Name)
	}
	switch p.Source {
	case "brew", "cask":
		if TagVersion(version) != TagVersion(p.Latest) {
			return nil, errors.New("Homebrew can only install the newest version, " + p.Latest)
		}
		if p.Source == "cask" {
			return exec.Command("brew", "install", "--cask", p.Name), nil
		}
		return exec.Command("brew", "install", "--formula", p.Name), nil
	case "npm":
		return exec.Command("npm", "install", "-g", p.Name+"@"+version), nil
	case "pipx":
		return exec.Command("pipx", "install", p.Name+"=="+version), nil
	case "uv":
		return exec.Command("uv", "tool", "install", p.Name+"=="+version), nil
	case "composer":
		return exec.Command("composer", "global", "require", p.Name+":"+version), nil
	case "go":
		if p.Entry == "" {
			return nil, errors.New("this package has no main package path to install from")
		}
		return exec.Command("go", "install", p.Entry+"@"+version), nil
	}
	return nil, fmt.Errorf("kho can't install new %s packages yet", p.Source)
}

// InstallCmd builds the command that moves a package to version through its
// own package manager, or says why kho can't.
func InstallCmd(p Package, version string) (*exec.Cmd, error) {
	if p.Lockfile != "" {
		return nil, fmt.Errorf("%s comes from %s, and kho doesn't change project lockfiles", p.Name, p.Lockfile)
	}
	if p.Pinned {
		return nil, fmt.Errorf("%s is pinned, so kho leaves it where it is", p.Name)
	}
	switch p.Source {
	case "brew", "cask":
		if TagVersion(version) != TagVersion(p.Latest) {
			return nil, errors.New("Homebrew can only install the newest version, " + p.Latest)
		}
		if p.Source == "cask" {
			return exec.Command("brew", "upgrade", "--cask", p.Name), nil
		}
		return exec.Command("brew", "upgrade", p.Name), nil
	case "npm":
		return exec.Command("npm", "install", "-g", p.Name+"@"+version), nil
	case "pipx":
		return exec.Command("pipx", "install", "--force", p.Name+"=="+version), nil
	case "uv":
		return exec.Command("uv", "tool", "install", "--force", p.Name+"=="+version), nil
	case "go":
		if p.Entry == "" {
			return nil, errors.New("this binary has no main package recorded to install from")
		}
		return exec.Command("go", "install", p.Entry+"@"+version), nil
	case "composer":
		return exec.Command("composer", "global", "require", p.Name+":"+version), nil
	case "mise":
		return exec.Command("mise", "install", p.Name+"@"+version), nil
	case "skills":
		if version != p.Latest {
			return nil, errors.New("the skills CLI installs only the newest commit of a skill")
		}
		return exec.Command("npx", "-y", "skills", "update", "-g", p.Name), nil
	}
	return nil, fmt.Errorf("kho can't install %s packages yet", p.Source)
}
