package validate

import (
	"fmt"
	"strings"
	"testing"
)

func TestIsNoTemplatesError(t *testing.T) {
	err := fmt.Errorf("nuclei failed: [\x1b[1;31mFTL\x1b[0m] Could not run nuclei: no templates provided for scan")
	if !isNoTemplatesError(err) {
		t.Fatal("isNoTemplatesError returned false for Nuclei no-template failure")
	}
}

func TestParseNucleiLineExtractsResult(t *testing.T) {
	line := `{"timestamp":"2026-06-01T20:00:00Z","template-id":"CVE-2024-0001","template-path":"/templates/http/cves/2024/CVE-2024-0001.yaml","matched-at":"https://app.example.com/login","type":"http","extractor-name":"body","info":{"severity":"high","tags":"cve,apache","classification":{"cve-id":["CVE-2024-0001"]},"metadata":{"product":"apache"}}}`

	result, err := parseNucleiLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if result.TemplateID != "CVE-2024-0001" {
		t.Fatalf("TemplateID = %q", result.TemplateID)
	}
	if result.MatchedAt != "https://app.example.com/login" {
		t.Fatalf("MatchedAt = %q", result.MatchedAt)
	}
	if result.Severity != "high" {
		t.Fatalf("Severity = %q", result.Severity)
	}
	if len(result.CVEs) != 1 || result.CVEs[0] != "cve-2024-0001" {
		t.Fatalf("CVEs = %#v", result.CVEs)
	}
	if len(result.Tags) != 2 || result.Tags[0] != "cve" || result.Tags[1] != "apache" {
		t.Fatalf("Tags = %#v", result.Tags)
	}
	if len(result.Raw) == 0 {
		t.Fatal("Raw is empty")
	}
}

func TestParseNucleiLineEvidenceHashIgnoresVolatileTimestamp(t *testing.T) {
	first := `{"timestamp":"2026-06-01T20:00:00Z","template-id":"CVE-2024-0001","matched-at":"https://app.example.com","type":"http","info":{"severity":"high","classification":{"cve-id":"CVE-2024-0001"}}}`
	second := strings.Replace(first, "2026-06-01T20:00:00Z", "2026-06-01T20:05:00Z", 1)

	left, err := parseNucleiLine(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := parseNucleiLine(second)
	if err != nil {
		t.Fatal(err)
	}
	if left.EvidenceHash != right.EvidenceHash {
		t.Fatalf("EvidenceHash changed across timestamp-only output: %s != %s", left.EvidenceHash, right.EvidenceHash)
	}
}

func TestParseNucleiLineGenericTemplateUsesEmptyCVEs(t *testing.T) {
	line := `{"timestamp":"2026-06-02T11:27:00Z","template-id":"http-missing-security-headers","template-path":"/templates/http/misconfiguration/http-missing-security-headers.yaml","matched-at":"https://app.example.com","type":"http","info":{"severity":"info","tags":"headers,misconfig"}}`

	result, err := parseNucleiLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if result.CVEs == nil {
		t.Fatal("CVEs is nil")
	}
	if len(result.CVEs) != 0 {
		t.Fatalf("CVEs = %#v", result.CVEs)
	}
	if len(result.Tags) != 2 || result.Tags[0] != "headers" || result.Tags[1] != "misconfig" {
		t.Fatalf("Tags = %#v", result.Tags)
	}
}
