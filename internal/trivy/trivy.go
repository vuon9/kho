// Package trivy runs the trivy scanner over one image and reads what it
// found. kho never reads inside an image itself, so a package level CVE list
// comes from the scanner that already does it well.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/vuon9/kho/internal/provider"
)

// Vuln is one finding, as the Security tab lists it.
type Vuln struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	Installed string `json:"installed,omitempty"`
	Fixed     string `json:"fixed,omitempty"`
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
}

// Available says whether the scanner is installed.
func Available() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

// Scan reads the image trivy names, which may be a tag or a digest. It is
// slow the first time, when trivy downloads its database.
func Scan(ctx context.Context, ref string) ([]Vuln, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, "trivy", "image", "--quiet", "--format", "json",
		"--scanners", "vuln", "--timeout", "5m", ref)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	provider.Record(append([]string{"trivy"}, cmd.Args[1:]...), time.Since(start), err)
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%s", lastLine(msg))
		}
		return nil, err
	}
	return Parse(stdout.Bytes())
}

// Parse reads trivy's JSON report.
func Parse(data []byte) ([]Vuln, error) {
	var doc struct {
		Results []struct {
			Vulnerabilities []struct {
				ID         string `json:"VulnerabilityID"`
				PkgName    string `json:"PkgName"`
				Installed  string `json:"InstalledVersion"`
				Fixed      string `json:"FixedVersion"`
				Severity   string `json:"Severity"`
				Title      string `json:"Title"`
				PrimaryURL string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Vuln
	seen := map[string]bool{}
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			key := v.ID + "|" + v.PkgName + "|" + v.Installed
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Vuln{ID: v.ID, Severity: strings.ToUpper(v.Severity), Package: v.PkgName,
				Installed: v.Installed, Fixed: v.Fixed, Title: v.Title, URL: v.PrimaryURL})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i].Severity), rank(out[j].Severity); ri != rj {
			return ri < rj
		}
		return out[i].Package < out[j].Package
	})
	return out, nil
}

func rank(sev string) int {
	switch sev {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

// lastLine keeps the last line of a scanner error, which is the one that says
// what went wrong.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
