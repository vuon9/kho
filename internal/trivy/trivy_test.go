package trivy

import "testing"

func TestParse(t *testing.T) {
	report := []byte(`{
	  "Results": [
	    {"Target": "node:22-alpine (alpine 3.21.0)", "Vulnerabilities": [
	      {"VulnerabilityID": "CVE-2025-1234", "PkgName": "openssl", "InstalledVersion": "3.3.2-r0",
	       "FixedVersion": "3.3.3-r0", "Severity": "HIGH", "Title": "openssl: a bug", "PrimaryURL": "https://avd.aquasec.com/CVE-2025-1234"},
	      {"VulnerabilityID": "CVE-2025-9999", "PkgName": "zlib", "InstalledVersion": "1.3.1-r0", "Severity": "LOW"}
	    ]},
	    {"Target": "app/package-lock.json", "Vulnerabilities": [
	      {"VulnerabilityID": "CVE-2025-1234", "PkgName": "openssl", "InstalledVersion": "3.3.2-r0", "Severity": "HIGH"}
	    ]}
	  ]
	}`)
	got, err := Parse(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d findings, want 2 (the same package in two targets counts once): %+v", len(got), got)
	}
	if got[0].ID != "CVE-2025-1234" || got[0].Severity != "HIGH" || got[0].Package != "openssl" || got[0].Fixed != "3.3.3-r0" {
		t.Errorf("first finding %+v", got[0])
	}
	if got[1].ID != "CVE-2025-9999" || got[1].Fixed != "" {
		t.Errorf("a low finding without a fix should come last and keep its empty fix: %+v", got[1])
	}
}

func TestParseEmpty(t *testing.T) {
	got, err := Parse([]byte(`{"Results":[]}`))
	if err != nil || len(got) != 0 {
		t.Errorf("an image with nothing found should parse to nothing, got %v %v", got, err)
	}
}
