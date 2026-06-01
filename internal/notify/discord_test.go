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
	if strings.Contains(payload.Content, "validado") {
		t.Fatalf("content = %q; should not claim validation", payload.Content)
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

func TestBuildDiscordPayloadsSplitsLongReport(t *testing.T) {
	report := db.DiscordReport{
		ProgramID:     "program-id",
		ProgramHandle: "example",
		ProgramURL:    "https://hackerone.com/example",
		Title:         "Zero findings for example",
		Severity:      "critical",
		Confidence:    65,
		BodyMarkdown:  strings.Repeat("### https://app.example.com\n\nValidation: potential/unconfirmed passive CVE match.\n\n", 90),
		FindingIDs:    []string{"finding-1", "finding-2", "finding-3"},
	}

	payloads := buildDiscordPayloads(report)
	if len(payloads) < 2 {
		t.Fatalf("payloads = %d; want split payloads", len(payloads))
	}
	for i, payload := range payloads {
		if len(payload.Embeds) != 1 {
			t.Fatalf("payload %d embeds = %d; want 1", i, len(payload.Embeds))
		}
		if len(payload.Embeds[0].Description) > 3900 {
			t.Fatalf("payload %d description length = %d; want <= 3900", i, len(payload.Embeds[0].Description))
		}
	}
	if !strings.Contains(payloads[0].Content, "potencial(is)/passivo(s)") {
		t.Fatalf("content = %q; want passive warning", payloads[0].Content)
	}
	if !strings.Contains(payloads[1].Embeds[0].Title, "parte 2/") {
		t.Fatalf("title = %q; want part marker", payloads[1].Embeds[0].Title)
	}
}

func TestBuildDiscordPayloadLabelsNucleiConfirmedFindings(t *testing.T) {
	report := db.DiscordReport{
		ProgramID:     "program-id",
		ProgramHandle: "example",
		ProgramURL:    "https://hackerone.com/example",
		Title:         "Zero findings for example",
		Severity:      "critical",
		Confidence:    95,
		BodyMarkdown:  "### https://app.example.com\n\nValidation: Nuclei-backed finding.",
		FindingIDs:    []string{"finding-1", "finding-2"},
		Confirmed:     2,
	}

	payload := buildDiscordPayload(report)
	if !strings.Contains(payload.Content, "confirmou 2 novo(s) finding(s) com Nuclei") {
		t.Fatalf("content = %q; want explicit Nuclei confirmation", payload.Content)
	}
	foundValidation := false
	for _, field := range payload.Embeds[0].Fields {
		if field.Name == "Validacao" && strings.Contains(field.Value, "Confirmado por Nuclei: 2") {
			foundValidation = true
		}
	}
	if !foundValidation {
		t.Fatalf("fields = %#v; want Nuclei validation field", payload.Embeds[0].Fields)
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

func TestDiscordNotifierRoutesReportsByValidation(t *testing.T) {
	notifier := NewDiscordNotifier(nil, "https://discord.test/passive", "https://discord.test/validated")

	passive := notifier.webhookURLForReport(db.DiscordReport{Potential: 2})
	if passive != "https://discord.test/passive" {
		t.Fatalf("passive webhook = %q", passive)
	}
	validated := notifier.webhookURLForReport(db.DiscordReport{Confirmed: 1, Potential: 1})
	if validated != "https://discord.test/validated" {
		t.Fatalf("validated webhook = %q", validated)
	}
}
