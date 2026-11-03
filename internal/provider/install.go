package provider

import (
	"errors"
	"fmt"
	"os/exec"
)

// InstallCmd builds the command that moves a package to version through its
// own package manager, or says why kho can't.
func InstallCmd(p Package, version string) (*exec.Cmd, error) {
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
