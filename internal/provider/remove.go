package provider

import (
	"fmt"
	"os/exec"
)

// RemoveCmd builds the command that uninstalls an installed package through
// its own package manager, or says why kho won't. It never installs, so a pin
// and an old version are not reasons to refuse.
func RemoveCmd(p Package, force bool) (*exec.Cmd, error) {
	if p.Lockfile != "" {
		return nil, fmt.Errorf("%s comes from %s, and kho doesn't change project lockfiles", p.Name, p.Lockfile)
	}
	switch p.Source {
	case "brew":
		if force {
			// Homebrew refuses while another installed formula needs this one,
			// and --ignore-dependencies is the flag that overrides it. brew -f
			// would delete every installed version instead, so it is never used.
			return exec.Command("brew", "uninstall", "--ignore-dependencies", p.Name), nil
		}
		return exec.Command("brew", "uninstall", p.Name), nil
	case "cask":
		if force {
			return exec.Command("brew", "uninstall", "--cask", "--ignore-dependencies", p.Name), nil
		}
		return exec.Command("brew", "uninstall", "--cask", p.Name), nil
	case "npm":
		return exec.Command("npm", "uninstall", "-g", p.Name), nil
	case "pipx":
		return exec.Command("pipx", "uninstall", p.Name), nil
	case "uv":
		return exec.Command("uv", "tool", "uninstall", p.Name), nil
	case "composer":
		// This edits Composer's own global composer.json, which is a fact
		// about the machine, not a project lockfile.
		return exec.Command("composer", "global", "remove", p.Name), nil
	case "mise":
		if p.Version == "" {
			return nil, fmt.Errorf("mise needs the installed version to uninstall %s, and kho was not given one", p.Name)
		}
		return exec.Command("mise", "uninstall", p.Name+"@"+p.Version), nil
	case "go":
		if p.Path == "" {
			return nil, fmt.Errorf("go has no uninstall; remove the %s binary yourself and it stops being listed", p.Name)
		}
		return nil, fmt.Errorf("go has no uninstall; %s is %s, so remove that file yourself and it stops being listed", p.Name, p.Path)
	case "skills":
		return nil, fmt.Errorf("kho doesn't remove skills; run npx skills remove %s, or unlink it from each agent in the TUI", p.Name)
	}
	return nil, fmt.Errorf("kho can't remove %s packages yet", p.Source)
}
