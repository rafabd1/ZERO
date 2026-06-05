package cli

import (
	"testing"
	"time"
)

func TestWebanalyzeEffectiveBatchSizeUsesConfiguredDefault(t *testing.T) {
	if got := webanalyzeEffectiveBatchSize(0, 50); got != 50 {
		t.Fatalf("probe-path batch size = %d; want 50", got)
	}
}

func TestWebanalyzeEffectiveBatchSizeKeepsExplicitValue(t *testing.T) {
	if got := webanalyzeEffectiveBatchSize(350, 500); got != 350 {
		t.Fatalf("explicit batch size = %d; want 350", got)
	}
}

func TestWebanalyzeEffectiveBatchSizeFallsBackToSafeDefault(t *testing.T) {
	if got := webanalyzeEffectiveBatchSize(0, 0); got != 50 {
		t.Fatalf("normal batch size = %d; want 50", got)
	}
}

func TestWebanalyzeEffectiveBatchTimeoutKeepsExplicitValue(t *testing.T) {
	if got := webanalyzeEffectiveBatchTimeout(2*time.Minute, 10*time.Minute); got != 2*time.Minute {
		t.Fatalf("explicit batch timeout = %s; want 2m", got)
	}
}

func TestWebanalyzeEffectiveBatchTimeoutUsesConfiguredDefault(t *testing.T) {
	if got := webanalyzeEffectiveBatchTimeout(0, 10*time.Minute); got != 10*time.Minute {
		t.Fatalf("configured batch timeout = %s; want 10m", got)
	}
}

func TestWebanalyzeEffectiveBatchTimeoutFallsBackToDedicatedDefault(t *testing.T) {
	if got := webanalyzeEffectiveBatchTimeout(0, 0); got != 10*time.Minute {
		t.Fatalf("fallback batch timeout = %s; want 10m", got)
	}
}
