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
