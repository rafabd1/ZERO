package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rafabd1/ZERO/internal/db"
)

func TestBuildDraftGroupsFindingsIntoStableNewOnlyReport(t *testing.T) {
	findings := []db.ReportFinding{
		{
			ID:            "22222222-2222-2222-2222-222222222222",
			ProgramID:     "11111111-1111-1111-1111-111111111111",
			ProgramHandle: "example",
			ProgramURL:    "https://hackerone.com/example",
			ServiceURL:    "https://app.example.com",
			Severity:      "high",
			Confidence:    88,
			Evidence:      json.RawMessage(`{"template_id":"cve-test","matched_at":"https://app.example.com","cves":["cve-2099-0001"],"tags":["cve"]}`),
			FirstSeenAt:   "2026-06-01 00:00:00+00",
		},
	}

	draft := buildDraft(findings)
	if draft.ProgramID != findings[0].ProgramID {
		t.Fatalf("ProgramID = %q; want %q", draft.ProgramID, findings[0].ProgramID)
	}
	if draft.Severity != "high" || draft.Confidence != 88 {
		t.Fatalf("severity/confidence = %s/%d; want high/88", draft.Severity, draft.Confidence)
	}
	if len(draft.FindingIDs) != 1 || draft.FindingIDs[0] != findings[0].ID {
		t.Fatalf("FindingIDs = %#v; want only %s", draft.FindingIDs, findings[0].ID)
	}
	if !strings.HasPrefix(draft.ReportKey, "zero-report:") {
		t.Fatalf("ReportKey = %q; want zero-report prefix", draft.ReportKey)
	}
	for _, want := range []string{"# example", "## High", "https://app.example.com", "`cve-test`", "cve-2099-0001"} {
		if !strings.Contains(draft.Body, want) {
			t.Fatalf("report body missing %q:\n%s", want, draft.Body)
		}
	}
}
