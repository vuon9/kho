package provider

import "testing"

// FuzzParsers feeds the command and registry output parsers arbitrary bytes.
// They read data from package managers and registries, so a panic here would
// crash a check before it can report the package that caused it.
func FuzzParsers(f *testing.F) {
	f.Add([]byte(`{"dependencies":{"left-pad":{"version":"1.3.0"}}}`))
	f.Add([]byte(`{"formulae":[],"casks":[]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseNpmList(data)
		_, _ = parseBrew(data)
		_, _ = parsePipx(data)
		_, _ = parseMiseList(data)
		_, _ = parseComposerOutdated(data)
		_, _ = parseNpmOutdated(data)
		_, _ = parseNpmSearch(data, 10)
		_, _ = ParseBrewVulns(data)
	})
}
