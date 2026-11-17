package provider

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A search whose query does not follow "--" fails, so a query that looks
// like a flag can never reach brew as one.
func fakeBrew(t *testing.T, formula, cask, info string) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = search ] && [ "$3" != "--" ]; then echo "query passed as a flag" >&2; exit 2; fi
case "$1 $2" in
"search --formula") ` + formula + ` ;;
"search --cask") ` + cask + ` ;;
"info --json=v2") echo '` + info + `' ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "brew"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func TestBrewSearch(t *testing.T) {
	const none = `echo "Error: No formulae or casks found for x." >&2; exit 1`
	tests := []struct {
		id            string
		formula, cask string
		info          string
		want          []Package
		wantErr       bool
	}{
		{id: "a tap's cask keeps the tap/name search printed, filled in by its full token",
			formula: none, cask: `echo acme/tap/widget`,
			info: `{"formulae":[],"casks":[{"token":"widget","full_token":"acme/tap/widget","tap":"acme/tap","version":"1.2.3"}]}`,
			want: []Package{{Source: "cask", Name: "acme/tap/widget", Latest: "1.2.3", Origin: "acme/tap"}}},
		{id: "a failed side with nothing on the other is an error, not no match",
			formula: `echo "Error: Refusing to load formula from untrusted tap" >&2; exit 1`, cask: none,
			wantErr: true},
		{id: "no match on either side is no match",
			formula: none, cask: none},
		{id: "a core formula is found by its plain name",
			formula: `echo anvil`, cask: none,
			info: `{"formulae":[{"name":"anvil","full_name":"anvil","tap":"homebrew/core","versions":{"stable":"2.0"}}],"casks":[]}`,
			want: []Package{{Source: "brew", Name: "anvil", Latest: "2.0", Origin: "homebrew/core"}}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			fakeBrew(t, tt.formula, tt.cask, tt.info)
			got, err := Brew{}.Search(context.Background(), "-x", 10)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err %v, want error %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}
