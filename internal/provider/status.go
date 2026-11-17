package provider

import "strings"

// A note that starts with one of these is a status, not only a remark. The
// writers and the readers below share them, so the screen and the JSON can't
// read a note one way and write it another.
const (
	noteNoLock        = "no lock"
	noteOnlyIn        = "only in"
	noteLatestUnknown = "latest unknown"
)

func (p Package) NoLock() bool { return strings.HasPrefix(p.Note, noteNoLock) }

func (p Package) Unmanaged() bool { return strings.HasPrefix(p.Note, noteOnlyIn) }

func (p Package) LatestUnknown() bool { return strings.HasPrefix(p.Note, noteLatestUnknown) }

// The JSON speaks the same language as the screen and an image's state does.
// Vulnerable and audit are decided by the caller, which holds the advisories.
func StatusWord(p Package) string {
	switch {
	case p.Pinned:
		return "pinned"
	case p.Outdated:
		return "outdated"
	case p.NoLock(), p.Unmanaged(), p.LatestUnknown():
		return "unverified"
	}
	return "ok"
}
