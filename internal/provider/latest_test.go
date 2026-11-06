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
