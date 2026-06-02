package cli

import "testing"

func TestNormalizeManualRunOptionsReuseActiveServicesSkipsActiveProbes(t *testing.T) {
	opts := normalizeManualRunOptions(manualRunOptions{
		ReuseActiveServices: true,
	})
	if !opts.SkipDNS {
		t.Fatal("ReuseActiveServices should skip dnsx")
	}
	if !opts.SkipProbe {
		t.Fatal("ReuseActiveServices should skip httpx probing")
	}
}

func TestShouldIncludePassiveFingerprintReports(t *testing.T) {
	if !shouldIncludePassiveFingerprintReports(manualRunOptions{WebanalyzeApps: "/tmp/custom.json"}) {
		t.Fatal("custom Webanalyze apps should enable passive fingerprint reports")
	}
	if !shouldIncludePassiveFingerprintReports(manualRunOptions{WebanalyzeProbePaths: []string{"/admin/"}}) {
		t.Fatal("custom Webanalyze probe paths should enable passive fingerprint reports")
	}
	if shouldIncludePassiveFingerprintReports(manualRunOptions{WebanalyzeApps: "/tmp/custom.json", DisablePassiveFingerprintReports: true}) {
		t.Fatal("disable flag should suppress passive fingerprint reports")
	}
	if shouldIncludePassiveFingerprintReports(manualRunOptions{WebanalyzeApps: "/tmp/custom.json", SkipEnrich: true}) {
		t.Fatal("skip enrich should suppress passive fingerprint reports")
	}
}
