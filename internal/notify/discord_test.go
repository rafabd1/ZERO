package notify

import (
	"strings"
	"testing"

	"github.com/rafabd1/ZERO/internal/db"
)

func TestBuildDiscordPayload(t *testing.T) {
	report := db.DiscordReport{
		ProgramID:     "program-id",
		ProgramHandle: "example",
		ProgramURL:    "https://hackerone.com/example",
		Title:         "Zero findings for example",
		Severity:      "high",
		Confidence:    88,
		BodyMarkdown:  strings.Repeat("validated finding\n", 400),
		FindingIDs:    []string{"finding-1", "finding-2"},
	}

	payload := buildDiscordPayload(report)
	if !strings.Contains(payload.Content, "2 novo") {
		t.Fatalf("content = %q; want finding count", payload.Content)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("embeds = %d; want 1", len(payload.Embeds))
	}
	embed := payload.Embeds[0]
	if embed.Color != 0xE74C3C {
		t.Fatalf("color = %#x; want high severity color", embed.Color)
	}
	if len(embed.Description) > 3900 {
		t.Fatalf("description length = %d; want <= 3900", len(embed.Description))
	}
}

func TestBuildOperationalAlertPayload(t *testing.T) {
	payload := buildOperationalAlertPayload(OperationalAlert{
		Kind:          "tool_timeout",
		Title:         "Zero tool timeout",
		ProgramID:     "program-id",
		ProgramHandle: "example",
		Step:          []string{"enum", "subfinder", "--program-id", "program-id"},
		Error:         "subfinder timed out after 20m0s",
		Timeout:       "20m0s",
	})

	if !strings.Contains(payload.Content, "tool_timeout") {
		t.Fatalf("content = %q; want alert kind", payload.Content)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("embeds = %d; want 1", len(payload.Embeds))
	}
	embed := payload.Embeds[0]
	if embed.Color != 0xE67E22 {
		t.Fatalf("color = %#x; want operational alert color", embed.Color)
	}
	if len(embed.Fields) < 5 {
		t.Fatalf("fields = %d; want kind, program, step, timeout, error", len(embed.Fields))
	}
	if !strings.Contains(embed.Fields[2].Value, "enum subfinder") {
		t.Fatalf("step field = %q; want command step", embed.Fields[2].Value)
	}
}
