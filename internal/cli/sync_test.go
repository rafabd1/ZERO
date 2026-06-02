package cli

import (
	"testing"
	"time"
)

func TestNormalizeScopeProvidersAliasesAndDedupes(t *testing.T) {
	got := normalizeScopeProviders([]string{"hackerone", "bc", "bugcrowd", "IT", "intigriti", "", "none"})
	want := []string{"h1", "bugcrowd", "intigriti"}
	if len(got) != len(want) {
		t.Fatalf("providers = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("providers = %#v; want %#v", got, want)
		}
	}
}

func TestScopeSyncDueFromLast(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if !scopeSyncDueFromLast(nil, 24*time.Hour, now) {
		t.Fatal("missing previous sync should be due")
	}
	fresh := now.Add(-23 * time.Hour)
	if scopeSyncDueFromLast(&fresh, 24*time.Hour, now) {
		t.Fatal("fresh previous sync should not be due")
	}
	old := now.Add(-25 * time.Hour)
	if !scopeSyncDueFromLast(&old, 24*time.Hour, now) {
		t.Fatal("old previous sync should be due")
	}
}
