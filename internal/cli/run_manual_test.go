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

func TestScanRequestEffectiveLimitCapsCampaignCapacity(t *testing.T) {
	if got := scanRequestEffectiveLimit(14, 10); got != 10 {
		t.Fatalf("scanRequestEffectiveLimit(14, 10) = %d; want 10", got)
	}
	if got := scanRequestEffectiveLimit(4, 10); got != 4 {
		t.Fatalf("scanRequestEffectiveLimit(4, 10) = %d; want 4", got)
	}
	if got := scanRequestEffectiveLimit(0, 10); got != 1 {
		t.Fatalf("scanRequestEffectiveLimit(0, 10) = %d; want 1", got)
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

func TestManualWebanalyzeAppsCombinesLegacyAndRepeatedValues(t *testing.T) {
	got := manualWebanalyzeApps(manualRunOptions{
		WebanalyzeApps:     "/tmp/a.json",
		WebanalyzeAppFiles: []string{"/tmp/b.json", "/tmp/a.json", " "},
	})
	want := []string{"/tmp/a.json", "/tmp/b.json"}
	if len(got) != len(want) {
		t.Fatalf("apps = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("apps = %#v; want %#v", got, want)
		}
	}
}

func TestManualNucleiTemplatesCombinesLegacyAndRepeatedValues(t *testing.T) {
	got := manualNucleiTemplates(manualRunOptions{
		NucleiTemplate:  "/tmp/a.yaml",
		NucleiTemplates: []string{"/tmp/b.yaml", "/tmp/a.yaml", ""},
	})
	want := []string{"/tmp/a.yaml", "/tmp/b.yaml"}
	if len(got) != len(want) {
		t.Fatalf("templates = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("templates = %#v; want %#v", got, want)
		}
	}
}
