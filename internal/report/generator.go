package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/rafabd1/ZERO/internal/db"
)

type Generator struct {
	repo  *db.Repository
	limit int
}

type Result struct {
	Findings int
	Reports  int
	Inserted int
}

func NewGenerator(repo *db.Repository) *Generator {
	return &Generator{repo: repo, limit: 500}
}

func (g *Generator) WithLimit(limit int) *Generator {
	if limit > 0 {
		g.limit = limit
	}
	return g
}

func (g *Generator) Run(ctx context.Context) (Result, error) {
	findings, err := g.repo.ListUnreportedFindings(ctx, g.limit)
	if err != nil {
		return Result{}, err
	}
	result := Result{Findings: len(findings)}
	if len(findings) == 0 {
		return result, nil
	}

	for _, group := range groupByProgram(findings) {
		draft := buildDraft(group)
		_, inserted, err := g.repo.CreateReport(ctx, draft)
		if err != nil {
			return result, err
		}
		result.Reports++
		if inserted {
			result.Inserted++
		}
	}
	return result, nil
}

func groupByProgram(findings []db.ReportFinding) [][]db.ReportFinding {
	byProgram := map[string][]db.ReportFinding{}
	order := []string{}
	for _, finding := range findings {
		if _, ok := byProgram[finding.ProgramID]; !ok {
			order = append(order, finding.ProgramID)
		}
		byProgram[finding.ProgramID] = append(byProgram[finding.ProgramID], finding)
	}
	sort.Strings(order)
	groups := make([][]db.ReportFinding, 0, len(order))
	for _, programID := range order {
		group := byProgram[programID]
		sort.SliceStable(group, func(i, j int) bool {
			if severityRank(group[i].Severity) != severityRank(group[j].Severity) {
				return severityRank(group[i].Severity) < severityRank(group[j].Severity)
			}
			if group[i].Confidence != group[j].Confidence {
				return group[i].Confidence > group[j].Confidence
			}
			return group[i].ID < group[j].ID
		})
		groups = append(groups, group)
	}
	return groups
}

func buildDraft(findings []db.ReportFinding) db.ReportDraft {
	first := findings[0]
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	sort.Strings(ids)

	maxSeverity := "unknown"
	maxConfidence := 0
	for _, finding := range findings {
		if severityRank(finding.Severity) < severityRank(maxSeverity) {
			maxSeverity = finding.Severity
		}
		if finding.Confidence > maxConfidence {
			maxConfidence = finding.Confidence
		}
	}

	title := fmt.Sprintf("Zero findings for %s: %d new candidate(s)", first.ProgramHandle, len(findings))
	return db.ReportDraft{
		ProgramID:  first.ProgramID,
		ReportKey:  reportKey(first.ProgramID, ids),
		Title:      title,
		Severity:   maxSeverity,
		Confidence: maxConfidence,
		Body:       renderMarkdown(first, findings),
		FindingIDs: ids,
		Metadata: map[string]any{
			"source":        "zero",
			"finding_count": len(findings),
			"new_only":      true,
		},
	}
}

func renderMarkdown(program db.ReportFinding, findings []db.ReportFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", program.ProgramHandle)
	fmt.Fprintf(&b, "- Program: %s\n", program.ProgramURL)
	fmt.Fprintf(&b, "- New findings: %d\n\n", len(findings))

	currentSeverity := ""
	for _, finding := range findings {
		if finding.Severity != currentSeverity {
			currentSeverity = finding.Severity
			fmt.Fprintf(&b, "## %s\n\n", severityTitle(currentSeverity))
		}
		target := firstNonEmpty(finding.ServiceURL, finding.ServiceHost, "unknown target")
		fmt.Fprintf(&b, "### %s\n\n", target)
		fmt.Fprintf(&b, "- Confidence: %d\n", finding.Confidence)
		fmt.Fprintf(&b, "- First seen: %s\n", finding.FirstSeenAt)
		writeEvidence(&b, finding.Evidence)
		b.WriteString("\n")
	}
	return b.String()
}

func writeEvidence(b *strings.Builder, raw json.RawMessage) {
	var evidence map[string]any
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return
	}
	if templateID, ok := evidence["template_id"].(string); ok && templateID != "" {
		fmt.Fprintf(b, "- Nuclei template: `%s`\n", templateID)
	}
	if matchedAt, ok := evidence["matched_at"].(string); ok && matchedAt != "" {
		fmt.Fprintf(b, "- Matched at: %s\n", matchedAt)
	}
	if cves := stringList(evidence["cves"]); len(cves) > 0 {
		fmt.Fprintf(b, "- CVEs: %s\n", strings.Join(cves, ", "))
	}
	if tags := stringList(evidence["tags"]); len(tags) > 0 {
		fmt.Fprintf(b, "- Tags: %s\n", strings.Join(tags, ", "))
	}
}

func stringList(value any) []string {
	switch v := value.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

func reportKey(programID string, findingIDs []string) string {
	h := sha256.New()
	h.Write([]byte(programID))
	for _, id := range findingIDs {
		h.Write([]byte{0})
		h.Write([]byte(id))
	}
	return "zero-report:" + hex.EncodeToString(h.Sum(nil))
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 5
	}
}

func severityTitle(severity string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	if severity == "" {
		return "Unknown"
	}
	return strings.ToUpper(severity[:1]) + severity[1:]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
