package cli

import "testing"

func TestEffectiveNucleiFilterClearsDefaultForExplicitTemplates(t *testing.T) {
	got := effectiveNucleiFilter("", "medium,high,critical", true, false)
	if got != "" {
		t.Fatalf("filter = %q; want empty for explicit templates without explicit flag", got)
	}
}

func TestEffectiveNucleiFilterKeepsExplicitFlagForExplicitTemplates(t *testing.T) {
	got := effectiveNucleiFilter("info", "medium,high,critical", true, true)
	if got != "info" {
		t.Fatalf("filter = %q; want explicit flag value", got)
	}
}

func TestEffectiveNucleiFilterUsesDefaultWithoutExplicitTemplates(t *testing.T) {
	got := effectiveNucleiFilter("", "medium,high,critical", false, false)
	if got != "medium,high,critical" {
		t.Fatalf("filter = %q; want configured default", got)
	}
}
