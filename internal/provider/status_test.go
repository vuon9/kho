package provider

import "testing"

// One word per row, the same one the table shows, so the JSON and the screen
// do not disagree.
func TestStatusWord(t *testing.T) {
	tests := []struct {
		id   string
		p    Package
		want string
	}{
		{"a package with nothing to report", Package{Version: "1.0", Latest: "1.0"}, "ok"},
		{"behind its latest", Package{Version: "1.0", Latest: "2.0", Outdated: true}, "outdated"},
		{"pinned, even when newer exists", Package{Version: "1.0", Latest: "2.0", Outdated: true, Pinned: true}, "pinned"},
		{"a project package with no lock", Package{Note: "no lock"}, "unverified"},
		{"a package only another one needs", Package{Note: "only in npm"}, "unverified"},
		{"a package whose latest kho could not read", Package{Note: "latest unknown"}, "unverified"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := StatusWord(tt.p); got != tt.want {
				t.Errorf("StatusWord(%+v) = %q, want %q", tt.p, got, tt.want)
			}
		})
	}
}
