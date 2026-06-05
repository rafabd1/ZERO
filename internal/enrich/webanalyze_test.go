package enrich

import (
	"os"
	"strings"
	"testing"

	"github.com/rafabd1/ZERO/internal/db"
)

func TestParseWebanalyzeLine(t *testing.T) {
	parsed, err := parseWebanalyzeLine(`{"hostname":"https://app.example.com","matches":[{"app_name":"Hugo","version":"0.42.1","cat_names":["Static Site Generator"]}]}`)
	if err != nil {
		t.Fatalf("parseWebanalyzeLine returned error: %v", err)
	}
	if parsed.Hostname != "https://app.example.com" {
		t.Fatalf("Hostname = %q", parsed.Hostname)
	}
	if len(parsed.Matches) != 1 {
		t.Fatalf("matches = %d; want 1", len(parsed.Matches))
	}
	if parsed.Matches[0].AppName != "Hugo" || parsed.Matches[0].Version != "0.42.1" {
		t.Fatalf("match = %#v", parsed.Matches[0])
	}
}

func TestPrepareWebanalyzeAppsMergesMultipleFiles(t *testing.T) {
	first := writeTempWebanalyzeApps(t, `{"technologies":{"Product A":{"html":["A"]}},"categories":{"19":{"name":"Enterprise"}}}`)
	second := writeTempWebanalyzeApps(t, `{"technologies":{"Product B":{"html":["B"]}}}`)
	path, cleanup, err := prepareWebanalyzeApps([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Product A", "Product B", "Enterprise"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("merged apps missing %q: %s", want, data)
		}
	}
}

func writeTempWebanalyzeApps(t *testing.T, body string) string {
	t.Helper()
	file, err := os.CreateTemp("", "zero-webanalyze-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	return file.Name()
}

func TestNormalizeURLKeyDropsQueryAndTrailingSlash(t *testing.T) {
	got := normalizeURLKey("https://APP.example.com/path/?x=1#frag")
	want := "https://app.example.com/path"
	if got != want {
		t.Fatalf("normalizeURLKey = %q; want %q", got, want)
	}
}

func TestNormalizeProbePaths(t *testing.T) {
	got := normalizeProbePaths([]string{
		"admin/",
		"/admin/",
		"/api/jolokia/version?x=1#ignored",
		"https://ignored.example.com/console/",
		"://bad",
		"",
	})
	want := []string{"/admin/", "/api/jolokia/version?x=1", "/console/"}
	if len(got) != len(want) {
		t.Fatalf("normalizeProbePaths length = %d; want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizeProbePaths[%d] = %q; want %q; full=%#v", i, got[i], want[i], got)
		}
	}
}

func TestExpandWebTechTargetsWithProbePaths(t *testing.T) {
	targets := []db.WebTechTarget{{
		ProgramID:     "program-1",
		HTTPServiceID: "service-1",
		LastScanRunID: "scan-1",
		URL:           "https://app.example.com/base?old=1",
	}}
	expanded := expandWebTechTargets(targets, []string{"/admin/", "/api/jolokia/version"})
	if len(expanded) != 3 {
		t.Fatalf("expanded target count = %d; want 3: %#v", len(expanded), expanded)
	}
	wantURLs := []string{
		"https://app.example.com/base?old=1",
		"https://app.example.com/admin/",
		"https://app.example.com/api/jolokia/version",
	}
	for i, want := range wantURLs {
		if expanded[i].URL != want {
			t.Fatalf("expanded[%d].URL = %q; want %q", i, expanded[i].URL, want)
		}
		if expanded[i].HTTPServiceID != "service-1" {
			t.Fatalf("expanded[%d].HTTPServiceID = %q; want service-1", i, expanded[i].HTTPServiceID)
		}
	}
}

func TestFilterWebTechTargetsByHTTPXFingerprintCapsDuplicates(t *testing.T) {
	targets := []db.WebTechTarget{}
	for i := 0; i < 12; i++ {
		targets = append(targets, db.WebTechTarget{
			ProgramID:     "p1",
			HTTPServiceID: "svc",
			URL:           "https://tenant.example.com/" + string(rune('a'+i)),
			Host:          "tenant.example.com",
			StatusCode:    200,
			Title:         "Welcome",
			Webserver:     "cloudfront",
			Technologies:  []string{"HSTS"},
			FaviconHash:   "123",
		})
	}

	filtered, skipped, groups := filterWebTechTargetsByHTTPXFingerprint(targets, 3)
	if len(filtered) != 3 {
		t.Fatalf("filtered targets = %d; want 3", len(filtered))
	}
	if skipped != 9 || groups != 1 {
		t.Fatalf("skipped=%d groups=%d; want 9/1", skipped, groups)
	}
}

func TestWebTechHTTPXFingerprintKeyIncludesRedirectHost(t *testing.T) {
	a := db.WebTechTarget{
		ProgramID:        "p1",
		URL:              "https://a.example.com",
		Host:             "a.example.com",
		StatusCode:       301,
		Webserver:        "akamai",
		RedirectLocation: "https://www.example.com/login",
	}
	b := a
	b.URL = "https://b.example.com"
	b.Host = "b.example.com"
	b.RedirectLocation = "https://www.example.com/account"

	if webTechHTTPXFingerprintKey(a) != webTechHTTPXFingerprintKey(b) {
		t.Fatal("redirects to the same final host should share a fingerprint key")
	}
}

func TestWebTechCanonicalRedirectHostFallsBackToCNAME(t *testing.T) {
	target := db.WebTechTarget{
		CNAME: `["edge.example.cdn.net."]`,
	}

	if got := webTechCanonicalRedirectHost(target); got != "edge.example.cdn.net" {
		t.Fatalf("canonical CNAME host = %q; want edge.example.cdn.net", got)
	}
}
