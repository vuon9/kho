package provider

import (
	"reflect"
	"strings"
	"testing"
)

func TestRemoveCmd(t *testing.T) {
	tests := []struct {
		id      string
		pkg     Package
		force   bool
		want    []string
		wantErr string
	}{
		{"a project package is never changed", Package{Source: "npm", Name: "left-trim", Lockfile: "web/package-lock.json"}, false, nil, "left-trim comes from web/package-lock.json, and kho doesn't change project lockfiles"},
		{"brew uninstalls the formula", Package{Source: "brew", Name: "anvil"}, false, []string{"brew", "uninstall", "anvil"}, ""},
		{"brew force ignores the dependency check", Package{Source: "brew", Name: "anvil"}, true, []string{"brew", "uninstall", "--ignore-dependencies", "anvil"}, ""},
		{"a cask goes through brew --cask", Package{Source: "cask", Name: "focusbar"}, false, []string{"brew", "uninstall", "--cask", "focusbar"}, ""},
		{"npm uninstalls globally", Package{Source: "npm", Name: "diffkit"}, false, []string{"npm", "uninstall", "-g", "diffkit"}, ""},
		{"a scoped npm name stays whole", Package{Source: "npm", Name: "@scope/tool"}, false, []string{"npm", "uninstall", "-g", "@scope/tool"}, ""},
		{"pipx uninstalls the app", Package{Source: "pipx", Name: "bramble"}, false, []string{"pipx", "uninstall", "bramble"}, ""},
		{"uv uninstalls the tool", Package{Source: "uv", Name: "ruff"}, false, []string{"uv", "tool", "uninstall", "ruff"}, ""},
		{"composer removes it from the global manifest", Package{Source: "composer", Name: "acme/ledger"}, false, []string{"composer", "global", "remove", "acme/ledger"}, ""},
		{"mise uninstalls the installed version", Package{Source: "mise", Name: "node", Version: "22.1.0"}, false, []string{"mise", "uninstall", "node@22.1.0"}, ""},
		{"a name with a space and a semicolon is one argument", Package{Source: "npm", Name: "evil name; rm"}, false, []string{"npm", "uninstall", "-g", "evil name; rm"}, ""},
		{"go has no uninstall, and names the file", Package{Source: "go", Name: "tidyup", Path: "/home/dev/go/bin/tidyup"}, false, nil, "go has no uninstall; tidyup is /home/dev/go/bin/tidyup, so remove that file yourself and it stops being listed"},
		{"go without a path still refuses", Package{Source: "go", Name: "tidyup"}, false, nil, "go has no uninstall; remove the tidyup binary yourself and it stops being listed"},
		{"skills are never deleted by kho", Package{Source: "skills", Name: "pathmaker"}, false, nil, "kho doesn't remove skills; run npx skills remove pathmaker, or unlink it from each agent in the TUI"},
		{"an unknown source is refused", Package{Source: "frob", Name: "widget"}, false, nil, "kho can't remove frob packages yet"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			cmd, err := RemoveCmd(tt.pkg, tt.force)
			var got []string
			if cmd != nil {
				got = cmd.Args
			}
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if !reflect.DeepEqual(got, tt.want) || gotErr != tt.wantErr {
				t.Errorf("got %v %q, want %v %q", got, gotErr, tt.want, tt.wantErr)
			}
		})
	}
}

// A removal never goes through a shell, so a name carrying shell syntax must
// stay one argv element rather than becoming a second command.
func TestRemoveCmdKeepsOneArgument(t *testing.T) {
	cmd, err := RemoveCmd(Package{Source: "npm", Name: "evil name; rm -rf /"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Args) != 4 || cmd.Args[3] != "evil name; rm -rf /" {
		t.Fatalf("argv %q, want 4 elements ending in the whole name", cmd.Args)
	}
	if strings.Contains(strings.Join(cmd.Args, " "), "sh -c") {
		t.Errorf("argv %q looks like a shell", cmd.Args)
	}
}
