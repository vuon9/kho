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
	"sync"
	"time"

	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
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

// scanMu runs one scan at a time. trivy keeps a cache behind a lock, so two
// scans started together make each other fail with "cache may be in use".
var scanMu sync.Mutex

// Scan reads the image trivy names, which may be a tag or a digest. It is
// slow the first time, when trivy downloads its database, and scans run one
// after another because they share that database.
func Scan(ctx context.Context, ref string) ([]Vuln, error) {
	scanMu.Lock()
	defer scanMu.Unlock()
	vulns, err := scanOnce(ctx, ref)
	// Another kho, or a trivy someone started, can hold the cache lock. Wait
	// for it rather than reporting a failure the person can do nothing about.
	for try := 0; err != nil && strings.Contains(err.Error(), "cache may be in use") && try < 4; try++ {
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(3 * time.Second):
		}
		vulns, err = scanOnce(ctx, ref)
	}
	return vulns, err
}

func scanOnce(ctx context.Context, ref string) ([]Vuln, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, "trivy", "image", "--quiet", "--format", "json",
		"--scanners", "vuln", "--timeout", "5m", ref)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	provider.Record(append([]string{"trivy"}, cmd.Args[1:]...), time.Since(start), err)
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%s", clean(msg))
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
		if ri, rj := vuln.Rank(out[i].Severity), vuln.Rank(out[j].Severity); ri != rj {
			return ri < rj
		}
		return out[i].Package < out[j].Package
	})
	return out, nil
}

// clean turns the scanner's error report into one readable sentence: the
// log prefix goes, the noise about its own cache becomes something a person
// can act on, and the rest is cut at a word.
func clean(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if strings.Contains(s, "cache may be in use") {
		return "trivy is busy with another scan, open the tab again to retry"
	}
	if strings.Contains(s, "manifest unknown") || strings.Contains(s, "MANIFEST_UNKNOWN") || strings.Contains(s, "not found") {
		return "the registry does not have this image, so there is nothing to scan"
	}
	for _, prefix := range []string{"run error: ", "FATAL ", "Fatal error: "} {
		if i := strings.LastIndex(s, prefix); i >= 0 {
			s = s[i+len(prefix):]
			break
		}
	}
	if len(s) > 140 {
		s = s[:140]
		if i := strings.LastIndex(s, " "); i > 0 {
			s = s[:i]
		}
		s += "..."
	}
	return s
}
