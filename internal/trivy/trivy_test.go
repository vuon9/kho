package trivy

import (
	"strings"
	"testing"
)

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

func TestClean(t *testing.T) {
	long := "FATAL Fatal error run error: image scan error: scan error: unable to initialize a scan service: unable to initialize cache: unable to initialize fs cache: cache may be in use by another process: timeout"
	got := clean(long)
	if strings.HasPrefix(got, "FATAL") || strings.Contains(got, "\n") {
		t.Errorf("clean should drop the report prefix: %q", got)
	}
	if got != "trivy is busy with another scan, press x to try again" {
		t.Errorf("a held cache lock should say what to do, got %q", got)
	}
	other := clean("2026-11-07T21:55:35+07:00 FATAL Fatal error run error: image scan error: unable to initialize a scan service: unable to initialize artifact: manifest unknown")
	if strings.Contains(other, "FATAL") || strings.Contains(other, "2026-11") {
		t.Errorf("clean should drop the log prefix, got %q", other)
	}
	if len(other) > 145 {
		t.Errorf("clean should keep it short, got %d chars", len(other))
	}
}
