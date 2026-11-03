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

// Query is the OSV query for the installed version, if there is one to ask.
func Query(p Package) (vuln.Query, bool) {
	eco := Ecosystem(p)
	if eco == "" || p.Version == "" || p.Version == "(devel)" {
		return vuln.Query{}, false
	}
	return vuln.Query{Ecosystem: eco, Name: OSVName(p), Version: p.Version}, true
}

// DepQueries asks about the dependencies known without extra work: npm's
// direct dependencies and every module built into a Go binary.
func DepQueries(p Package) []vuln.Query {
	eco := Ecosystem(p)
	if p.Source != "npm" && p.Source != "go" {
		return nil
	}
	var qs []vuln.Query
	for _, d := range p.Deps {
		if d.Version != "" && d.Version != "(devel)" {
			qs = append(qs, vuln.Query{Ecosystem: eco, Name: d.Name, Version: d.Version})
		}
	}
	return qs
}
