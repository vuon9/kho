package provider

import "github.com/vuon9/kho/internal/vuln"

// Ecosystem names the OSV database that covers the package, or "" when OSV
// has none, as for Homebrew formulae, mise tools and skills.
func Ecosystem(p Package) string {
	switch p.Source {
	case "npm":
		return "npm"
	case "pipx", "uv":
		return "PyPI"
	case "go":
		return "Go"
	}
	return ""
}

// OSVName is the package's name in its OSV ecosystem. Go binaries are known
// by their module path.
func OSVName(p Package) string {
	if p.Source == "go" {
		return p.Origin
	}
	return p.Name
}

// Released says whether v is a published version OSV can know about. A Go
// module built from a local checkout has "(devel)" or no version at all.
func Released(v string) bool {
	return v != "" && v != "(devel)"
}

// Query is the OSV query for the installed version, if there is one to ask.
func Query(p Package) (vuln.Query, bool) {
	eco := Ecosystem(p)
	if eco == "" || !Released(p.Version) {
		return vuln.Query{}, false
	}
	return vuln.Query{Ecosystem: eco, Name: OSVName(p), Version: p.Version}, true
}

// DepQuery is the OSV query for one of p's dependencies, if kho asks about
// it. kho asks about the ones known without extra work: npm's direct
// dependencies and every module built into a Go binary.
func DepQuery(p Package, d Dep) (vuln.Query, bool) {
	if p.Source != "npm" && p.Source != "go" || !Released(d.Version) {
		return vuln.Query{}, false
	}
	return vuln.Query{Ecosystem: Ecosystem(p), Name: d.Name, Version: d.Version}, true
}

func DepQueries(p Package) []vuln.Query {
	var qs []vuln.Query
	for _, d := range p.Deps {
		if q, ok := DepQuery(p, d); ok {
			qs = append(qs, q)
		}
	}
	return qs
}
