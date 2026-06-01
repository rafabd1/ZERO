package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
)

type DiscordNotifier struct {
	repo       *db.Repository
	webhookURL string
	client     *http.Client
	programID  string
	limit      int
	dryRun     bool
}

type DiscordResult struct {
	Reports  int
	Sent     int
	Skipped  int
	Failed   int
	Disabled bool
}

type OperationalAlert struct {
	Kind          string
	Title         string
	ProgramID     string
	ProgramHandle string
	Step          []string
	Error         string
	Timeout       string
}

func NewDiscordNotifier(repo *db.Repository, webhookURL string) *DiscordNotifier {
	return &DiscordNotifier{
		repo:       repo,
		webhookURL: strings.TrimSpace(webhookURL),
		client:     &http.Client{Timeout: 15 * time.Second},
		limit:      25,
	}
}

func (n *DiscordNotifier) WithLimit(limit int) *DiscordNotifier {
	if limit > 0 {
		n.limit = limit
	}
	return n
}

func (n *DiscordNotifier) WithProgramID(programID string) *DiscordNotifier {
	n.programID = strings.TrimSpace(programID)
	return n
}

func (n *DiscordNotifier) WithDryRun(dryRun bool) *DiscordNotifier {
	n.dryRun = dryRun
	return n
}

func (n *DiscordNotifier) Run(ctx context.Context) (DiscordResult, error) {
	reports, err := n.repo.ListDiscordReports(ctx, n.programID, n.limit)
	if err != nil {
		return DiscordResult{}, err
	}
	result := DiscordResult{Reports: len(reports)}
	if len(reports) == 0 {
		return result, nil
	}
	if n.webhookURL == "" && !n.dryRun {
		result.Disabled = true
		result.Skipped = len(reports)
		return result, nil
	}

	for _, report := range reports {
		if n.dryRun {
			result.Skipped++
			continue
		}
		notificationID, ok, err := n.repo.UpsertPendingDiscordNotification(ctx, report)
		if err != nil {
			return result, err
		}
		if !ok {
			result.Skipped++
			continue
		}
		if err := n.send(ctx, report); err != nil {
			result.Failed++
			_ = n.repo.FinishDiscordNotification(ctx, notificationID, "failed", err.Error())
			return result, err
		}
		if err := n.repo.FinishDiscordNotification(ctx, notificationID, "sent", ""); err != nil {
			return result, err
		}
		result.Sent++
	}
	return result, nil
}

func SendOperationalAlert(ctx context.Context, webhookURL string, alert OperationalAlert) error {
	webhookURL = strings.TrimSpace(webhookURL)
	if webhookURL == "" {
		return nil
	}
	payload := buildOperationalAlertPayload(alert)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (n *DiscordNotifier) send(ctx context.Context, report db.DiscordReport) error {
	payload := buildDiscordPayload(report)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func buildOperationalAlertPayload(alert OperationalAlert) discordPayload {
	kind := firstNonEmpty(alert.Kind, "operational")
	title := firstNonEmpty(alert.Title, "Zero operational alert")
	step := strings.Join(alert.Step, " ")
	if step == "" {
		step = "unknown"
	}
	program := firstNonEmpty(alert.ProgramHandle, alert.ProgramID, "global")
	content := fmt.Sprintf("Zero alert: `%s` em `%s`.", kind, program)
	fields := []discordField{
		{Name: "Kind", Value: truncate(kind, 1000), Inline: true},
		{Name: "Program", Value: truncate(program, 1000), Inline: true},
		{Name: "Step", Value: truncate("`"+step+"`", 1000), Inline: false},
	}
	if alert.Timeout != "" {
		fields = append(fields, discordField{Name: "Timeout", Value: truncate(alert.Timeout, 1000), Inline: true})
	}
	if alert.Error != "" {
		fields = append(fields, discordField{Name: "Error", Value: truncate(alert.Error, 1000), Inline: false})
	}
	return discordPayload{
		Content: truncate(content, 1900),
		Embeds: []discordEmbed{{
			Title:       truncate(title, 250),
			Description: "Operational alert emitted by Zero. Inspect scan_runs and container logs before retrying broad execution.",
			Color:       0xE67E22,
			Fields:      fields,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		}},
	}
}

type discordPayload struct {
	Content string         `json:"content"`
	Embeds  []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

func buildDiscordPayload(report db.DiscordReport) discordPayload {
	count := len(report.FindingIDs)
	if count == 0 {
		count = 1
	}
	content := fmt.Sprintf("Zero encontrou %d novo(s) finding(s) validado(s) por Nuclei em `%s`.", count, firstNonEmpty(report.ProgramHandle, report.ProgramID, "programa"))
	return discordPayload{
		Content: truncate(content, 1900),
		Embeds: []discordEmbed{{
			Title:       truncate(report.Title, 250),
			Description: truncate(report.BodyMarkdown, 3900),
			Color:       severityColor(report.Severity),
			Fields: []discordField{
				{Name: "Severity", Value: firstNonEmpty(report.Severity, "unknown"), Inline: true},
				{Name: "Confidence", Value: fmt.Sprintf("%d", report.Confidence), Inline: true},
				{Name: "Findings", Value: fmt.Sprintf("%d", count), Inline: true},
				{Name: "Program", Value: truncate(firstNonEmpty(report.ProgramURL, report.ProgramHandle, report.ProgramID, "unknown"), 1000), Inline: false},
			},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}},
	}
}

func severityColor(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0x992D22
	case "high":
		return 0xE74C3C
	case "medium":
		return 0xF1C40F
	case "low":
		return 0x3498DB
	default:
		return 0x95A5A6
	}
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
