package provider

import "context"

// Search returns the manager's own order, at most limit rows, and never sets
// Version: these are packages the machine may not have.
//
// A manager that has no keyword search does not implement Searcher. pipx and
// uv are exact-name only, Go searches keywords through GitHub, and mise is
// deferred.
type Searcher interface {
	Search(ctx context.Context, query string, limit int) ([]Package, error)
}

// source names the label to return, such as
// "brew" or "cask", so one provider can serve more than one source. The result
// has Version empty and Latest set to the newest published version.
type Finder interface {
	Find(ctx context.Context, source, name string) (Package, error)
}

func Searchers(ps []Provider) []Provider {
	var out []Provider
	for _, p := range ps {
		if _, ok := p.(Searcher); ok {
			out = append(out, p)
		}
	}
	return out
}

func Finders(ps []Provider) []Provider {
	var out []Provider
	for _, p := range ps {
		if _, ok := p.(Finder); ok {
			out = append(out, p)
		}
	}
	return out
}

func ProviderNamed(ps []Provider, name string) Provider {
	for _, p := range ps {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// A manager's search returns the manager's order, so the cap is what keeps
// one registry from flooding the list.
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

// A compile-time check keeps a new adapter from silently landing in the wrong tier.
var (
	_ Searcher = Brew{}
	_ Searcher = Npm{}
	_ Searcher = Composer{}
	_ Searcher = GoBin{}
	_ Searcher = Pipx{}
	_ Searcher = Uv{}
	_ Searcher = Skills{}
	_ Finder   = Skills{}

	_ Finder = Brew{}
	_ Finder = Npm{}
	_ Finder = Composer{}
	_ Finder = Pipx{}
	_ Finder = Uv{}
	_ Finder = GoBin{}
)

// A product choice, not a capability: the interfaces would allow these, but
// their install shape or registry is not settled.
var deferredSources = map[string]bool{"mise": true}

func DeferredSource(name string) bool {
	return deferredSources[name]
}
