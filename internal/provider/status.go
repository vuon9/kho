package provider

import "strings"

// StatusWord is what the package table says about a package, as one word, so
// the JSON speaks the same language as the screen and an image's state does.
// Vulnerable and audit are decided by the caller, which holds the advisories.
func StatusWord(p Package) string {
	switch {
	case p.Pinned:
		return "pinned"
	case p.Outdated:
		return "outdated"
	case strings.HasPrefix(p.Note, "no lock"),
		strings.HasPrefix(p.Note, "only in"),
		strings.HasPrefix(p.Note, "latest unknown"):
		return "unverified"
	}
	return "ok"
}
