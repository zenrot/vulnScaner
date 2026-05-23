package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanFindsRepresentativeIssues(t *testing.T) {
	dir := t.TempDir()
	source := `package main

import (
	"crypto/md5"
	"crypto/tls"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

const apiToken = "hardcoded-token-value"

func main() {
	_ = md5.New()
	_ = rand.Int()
	_ = http.ListenAndServe(":8080", nil)
	_ = exec.Command("sh", "-c", "echo unsafe")
	_ = os.Chmod("secret.txt", 0777)
	_ = &tls.Config{InsecureSkipVerify: true}
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"GO-HARDCODED-SECRET": false,
		"GO-CRYPTO-WEAK":      false,
		"GO-RAND-INSECURE":    false,
		"GO-HTTP-NO-TLS":      false,
		"GO-CMD-SHELL":        false,
		"GO-FILE-PERMISSIVE":  false,
		"GO-TLS-SKIP-VERIFY":  false,
	}
	for _, finding := range findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for ruleID, found := range want {
		if !found {
			t.Fatalf("expected finding %s; got %#v", ruleID, findings)
		}
	}
}

func TestScanSkipsVendor(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "vendor", "example")
	if err := os.MkdirAll(vendor, 0700); err != nil {
		t.Fatal(err)
	}
	source := `package example
const password = "hardcoded-password"
`
	if err := os.WriteFile(filepath.Join(vendor, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected vendor findings to be skipped; got %#v", findings)
	}
}

func TestIncrementalSkipsUnchangedFiles(t *testing.T) {
	dir := t.TempDir()
	source := `package main
const password = "hardcoded-password"
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}

	first, err := ScanWithOptions(dir, Options{Incremental: true, CacheFile: filepath.Join(dir, ".sastcache.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) == 0 {
		t.Fatal("expected finding in first run")
	}
	second, err := ScanWithOptions(dir, Options{Incremental: true, CacheFile: filepath.Join(dir, ".sastcache.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Findings) != 0 {
		t.Fatalf("expected unchanged file to be skipped, got findings: %#v", second.Findings)
	}
	if second.Metrics.FilesSkipped == 0 {
		t.Fatal("expected skipped files in second run")
	}
}

func TestTaintLiteFindsCommandInjection(t *testing.T) {
	dir := t.TempDir()
	source := `package main

import (
	"os"
	"os/exec"
)

func main() {
	input := os.Getenv("USER_INPUT")
	_ = exec.Command("bash", "-lc", input)
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range findings {
		if finding.RuleID == "GO-CMD-INJECTION-TAINT" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected GO-CMD-INJECTION-TAINT, got %#v", findings)
	}
}

func TestParseGosecFindingsKeepsExternalRuleIDs(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{
  "Issues": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "cwe": {"id": "78"},
      "rule_id": "G204",
      "details": "Subprocess launched with variable",
      "file": "cmd/app/main.go",
      "code": "exec.Command(name)",
      "line": "17",
      "column": "9"
    }
  ]
}`)

	findings, err := parseGosecFindings(data, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	got := findings[0]
	if got.RuleID != "GOSEC-G204" {
		t.Fatalf("expected external gosec rule id, got %q", got.RuleID)
	}
	if got.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", got.Severity)
	}
	if got.Line != 17 || got.Column != 9 {
		t.Fatalf("unexpected location: %d:%d", got.Line, got.Column)
	}
	if got.File != filepath.Join(dir, "cmd/app/main.go") {
		t.Fatalf("unexpected file path: %q", got.File)
	}
}

func TestParseGovulncheckFindingsKeepsDependencyVulnerabilities(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"osv":{"id":"GO-2023-2041","summary":"Example vulnerable module","details":"Reachable vulnerable function.","aliases":["CVE-2023-1234"]}}
{"finding":{"osv":"GO-2023-2041","fixed_version":"v1.2.3","trace":[{"module":"example.com/vuln","package":"example.com/vuln/pkg","function":"Danger","position":{"filename":"main.go","line":12,"column":3}}]}}
`)

	findings, err := parseGovulncheckFindings(data, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	got := findings[0]
	if got.RuleID != "GOVULN-GO-2023-2041" {
		t.Fatalf("expected govuln rule id, got %q", got.RuleID)
	}
	if got.Title != "Example vulnerable module" {
		t.Fatalf("unexpected title: %q", got.Title)
	}
	if got.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", got.Severity)
	}
	if got.Remediation != "Upgrade the affected Go module to v1.2.3 or later." {
		t.Fatalf("unexpected remediation: %q", got.Remediation)
	}
}
