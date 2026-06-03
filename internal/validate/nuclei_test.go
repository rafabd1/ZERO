package validate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rafabd1/ZERO/internal/db"
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

func TestSplitHeaderConfigPreservesCommaValues(t *testing.T) {
	headers := SplitHeaderConfig("User-Agent: zero|Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8|Accept-Language: en-US,en;q=0.9")
	if len(headers) != 3 {
		t.Fatalf("headers = %#v", headers)
	}
	if headers[1] != "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" {
		t.Fatalf("Accept header = %q", headers[1])
	}
}

func TestBuildArgsIncludesRequestProfile(t *testing.T) {
	runner := NewNucleiRunner(nil, "nuclei").WithRequestProfile(
		[]string{"User-Agent: zero", "Accept: text/html"},
		"http://127.0.0.1:8080",
		"host-spray",
		42,
	)
	args := strings.Join(runner.buildArgs(), "\n")
	for _, want := range []string{
		"-H\nUser-Agent: zero",
		"-H\nAccept: text/html",
		"-p\nhttp://127.0.0.1:8080",
		"-ss\nhost-spray",
		"-mhe\n42",
		"-pt\nhttp",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("args missing %q in:\n%s", want, args)
		}
	}
}

func TestBuildArgsCanOmitProtocolForAutoTemplates(t *testing.T) {
	runner := NewNucleiRunner(nil, "nuclei").WithTargeting("subdomains", "auto")
	args := strings.Join(runner.buildArgs(), "\n")
	if strings.Contains(args, "-pt\n") {
		t.Fatalf("auto protocol should omit -pt in:\n%s", args)
	}
}

func TestTargetIndexMatchesRawSubdomainInput(t *testing.T) {
	targets := []db.NucleiTarget{{
		ProgramID:    "program-1",
		TargetID:     "00000000-0000-0000-0000-000000000001",
		TargetSource: "subdomains",
		Input:        "dangling.example.com",
	}}
	target, ok := newTargetIndex(targets).match("dangling.example.com")
	if !ok {
		t.Fatal("raw hostname did not match target")
	}
	if target.TargetSource != "subdomains" {
		t.Fatalf("TargetSource = %q", target.TargetSource)
	}
}

func TestNormalizeNucleiListSplitsAndDeduplicates(t *testing.T) {
	got := normalizeNucleiList([]string{"/tmp/a.yaml,/tmp/b.yaml", "/tmp/a.yaml", " /tmp/c.yaml "})
	want := []string{"/tmp/a.yaml", "/tmp/b.yaml", "/tmp/c.yaml"}
	if len(got) != len(want) {
		t.Fatalf("list = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("list = %#v; want %#v", got, want)
		}
	}
}

func TestClassifyWAFResponseDetectsBlockedCloudflarePage(t *testing.T) {
	headers := http.Header{}
	headers.Set("cf-ray", "example")
	blocked, wafLike, indicators := classifyWAFResponse(403, headers, "Attention Required - checking your browser")
	if !blocked || !wafLike {
		t.Fatalf("blocked=%t wafLike=%t; want both true", blocked, wafLike)
	}
	joined := strings.Join(indicators, ",")
	for _, want := range []string{"status_403", "cloudflare_header", "attention_required_body"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("indicators = %#v; missing %s", indicators, want)
		}
	}
}

func TestWAFDiagnosticDetectsPostScanBlockingIncrease(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<title>ok</title>"))
			return
		}
		w.Header().Set("cf-ray", "example")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Attention Required"))
	}))
	defer server.Close()

	targets := []db.NucleiTarget{{Input: server.URL}}
	baseline := startWAFDiagnostic(context.Background(), targets, []string{"User-Agent: zero"}, 1, 2)
	diag := finishWAFDiagnostic(context.Background(), baseline, nil, 0)

	if !diag.Suspected {
		t.Fatalf("diag = %#v; want suspected", diag)
	}
	if diag.Confidence < 80 {
		t.Fatalf("confidence = %d; want >= 80", diag.Confidence)
	}
	if diag.Reason != "post_scan_blocking_increased" {
		t.Fatalf("reason = %q", diag.Reason)
	}
}
