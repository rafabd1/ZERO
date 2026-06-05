package db

import "testing"

func TestDefaultChangeEventPolicyKeepsOnlySecurityEvidence(t *testing.T) {
	repo := &Repository{}
	if !repo.ChangeEventAllowed("candidate_finding") {
		t.Fatal("candidate_finding should be allowed by default")
	}
	if !repo.ChangeEventAllowed("nuclei_result") {
		t.Fatal("nuclei_result should be allowed by default")
	}
	for _, entityType := range []string{"scope_asset", "subdomain", "http_service", "technology"} {
		if repo.ChangeEventAllowed(entityType) {
			t.Fatalf("%s should not be allowed by default", entityType)
		}
	}
}

func TestChangeEventPolicyAllAndNone(t *testing.T) {
	repo := &Repository{}
	repo.SetChangeEventEntities("all")
	if !repo.ChangeEventAllowed("technology") {
		t.Fatal("all policy should allow technology events")
	}
	repo.SetChangeEventEntities("none")
	if repo.ChangeEventAllowed("candidate_finding") {
		t.Fatal("none policy should disable candidate_finding events")
	}
}

func TestCleanupBatchSizeBounds(t *testing.T) {
	tests := map[int]int{
		0:      5000,
		1:      100,
		100:    100,
		5000:   5000,
		100000: 50000,
	}
	for input, want := range tests {
		if got := cleanupBatchSize(input); got != want {
			t.Fatalf("cleanupBatchSize(%d) = %d; want %d", input, got, want)
		}
	}
}
