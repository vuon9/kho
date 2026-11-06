package provider

import "testing"

func TestLatestURL(t *testing.T) {
	tests := []struct {
		id   string
		pkg  Package
		want string
	}{
		{"a scoped npm package keeps its slash", Package{Source: "npm", Name: "@acme/left-trim"}, "https://registry.npmjs.org/-/package/@acme/left-trim/dist-tags"},
		{"a Python package is looked up by its standard name", Package{Source: "poetry", Name: "Ink_Pot"}, "https://pypi.org/pypi/ink-pot/json"},
		{"a Go module uses the proxy's case encoding", Package{Source: "go", Name: "github.com/Acme/tidyup", Origin: "github.com/Acme/tidyup"}, "https://proxy.golang.org/github.com/!acme/tidyup/@latest"},
		{"a crate", Package{Source: "cargo", Name: "tinyhash"}, "https://crates.io/api/v1/crates/tinyhash"},
		{"a Composer package", Package{Source: "composer", Name: "acme/ledger"}, "https://repo.packagist.org/p2/acme/ledger.json"},
		{"a name from a lockfile can't climb out of its path", Package{Source: "npm", Name: "../../-/user/x?y#z"}, "https://registry.npmjs.org/-/package/%2E%2E/%2E%2E/-/user/x%3Fy%23z/dist-tags"},
		{"nor can a Packagist one", Package{Source: "composer", Name: "acme/../../evil?x"}, "https://repo.packagist.org/p2/acme/%2E%2E/%2E%2E/evil%3Fx.json"},
		{"a Go module outside the module alphabet is not looked up", Package{Source: "go", Name: "x", Origin: "example.com/../x?y"}, ""},
		{"a source with no registry", Package{Source: "mise", Name: "node"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := latestURL(tt.pkg); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewestStable(t *testing.T) {
	tests := []struct {
		id   string
		rels []Release
		want string
	}{
		{"previews are skipped", []Release{{Version: "v3.0.0-beta1"}, {Version: "v3.0.0-RC2"}, {Version: "v2.4.1"}}, "v2.4.1"},
		{"a backport published last doesn't beat a higher version", []Release{{Version: "v12.71.0"}, {Version: "v13.40.0"}, {Version: "v12.70.2"}}, "v13.40.0"},
		{"the newest stable one wins", []Release{{Version: "2.5.0"}, {Version: "2.4.1"}}, "2.5.0"},
		{"nothing stable", []Release{{Version: "1.0.0-alpha"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := newestStable(tt.rels); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
