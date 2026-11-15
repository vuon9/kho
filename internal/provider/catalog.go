package provider

import "context"

// Searcher finds packages by keyword in a manager's registry. It is read-only
// and may hit the network. Search returns the manager's own order, at most
// limit rows, and never sets Version: these are packages the machine may not
// have. Latest is set when the registry returned one.
//
// A manager that has no keyword search does not implement Searcher. pipx and
// uv are exact-name only, Go searches keywords through GitHub, and mise and
// skills are deferred.
type Searcher interface {
	Search(ctx context.Context, query string, limit int) ([]Package, error)
}

// Finder looks a package up by its exact name in the provider's registry,
// whether or not the machine has it. source names the label to return, such as
// "brew" or "cask", so one provider can serve more than one source. The result
// has Version empty and Latest set to the newest published version.
type Finder interface {
	Find(ctx context.Context, source, name string) (Package, error)
}

// Searchers returns the providers that can search by keyword, in All order.
func Searchers(ps []Provider) []Provider {
	var out []Provider
	for _, p := range ps {
		if _, ok := p.(Searcher); ok {
			out = append(out, p)
		}
	}
	return out
}

// Finders returns the providers that can resolve an exact name, in All order.
func Finders(ps []Provider) []Provider {
	var out []Provider
	for _, p := range ps {
		if _, ok := p.(Finder); ok {
			out = append(out, p)
		}
	}
	return out
}

// ProviderNamed returns the provider whose Name is name, or nil.
func ProviderNamed(ps []Provider, name string) Provider {
	for _, p := range ps {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// Search limits. A manager's search returns the manager's order, so the cap is
// what keeps one registry from flooding the list.
const (
	DefaultSearchLimit = 20
	MaxSearchLimit     = 100
)

func searchLimit(n int) int {
	if n <= 0 {
		return DefaultSearchLimit
	}
	return min(n, MaxSearchLimit)
}

// The managers that can answer each kind of lookup. A compile-time check keeps
// a new adapter from silently landing in the wrong tier.
var (
	_ Searcher = Brew{}
	_ Searcher = Npm{}
	_ Searcher = Composer{}
	_ Searcher = GoBin{}

	_ Finder = Brew{}
	_ Finder = Npm{}
	_ Finder = Composer{}
	_ Finder = Pipx{}
	_ Finder = Uv{}
	_ Finder = GoBin{}
)

// deferredSources are the managers kho does not search yet. They are a product
// choice, not a capability: the interfaces would allow them, but their install
// shape or registry is not settled.
var deferredSources = map[string]bool{"mise": true, "skills": true}

// DeferredSource says whether a manager's search is deferred. The TUI says so
// on that panel; the CLI treats a search for it as a usage error.
func DeferredSource(name string) bool {
	return deferredSources[name]
}
