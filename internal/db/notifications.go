package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (r *Repository) ListDiscordReports(ctx context.Context, programID string, limit int) ([]DiscordReport, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := r.pool.Query(ctx, `
		SELECT
			r.id::text,
			COALESCE(r.program_id::text, ''),
			COALESCE(p.handle, ''),
			COALESCE(p.program_url, ''),
			r.report_key,
			r.title,
			r.severity,
			r.confidence,
			r.body_markdown,
			r.finding_ids::text[],
			(
				SELECT count(*)
				FROM zero_candidate_findings f
				WHERE f.id = ANY(r.finding_ids)
				  AND f.nuclei_result_id IS NOT NULL
			)::int,
			(
				SELECT count(*)
				FROM zero_candidate_findings f
				WHERE f.id = ANY(r.finding_ids)
				  AND f.nuclei_result_id IS NULL
			)::int,
			r.created_at::text
		FROM zero_reports r
		LEFT JOIN zero_programs p ON p.id = r.program_id
		WHERE NOT EXISTS (
			SELECT 1
			FROM zero_discord_notifications n
			WHERE n.dedupe_key = 'discord:report:' || r.report_key
			  AND n.status = 'sent'
		)
		  AND ($1 = '' OR r.program_id::text = $1)
		ORDER BY r.created_at ASC
		LIMIT $2
	`, programID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	reports := []DiscordReport{}
	for rows.Next() {
		var report DiscordReport
		if err := rows.Scan(
			&report.ReportID,
			&report.ProgramID,
			&report.ProgramHandle,
			&report.ProgramURL,
			&report.ReportKey,
			&report.Title,
			&report.Severity,
			&report.Confidence,
			&report.BodyMarkdown,
			&report.FindingIDs,
			&report.Confirmed,
			&report.Potential,
			&report.CreatedAt,
		); err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (r *Repository) UpsertPendingDiscordNotification(ctx context.Context, report DiscordReport) (string, bool, error) {
	dedupeKey := "discord:report:" + report.ReportKey
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_discord_notifications(program_id, report_id, dedupe_key, status)
		VALUES (NULLIF($1, '')::uuid, $2::uuid, $3, 'pending')
		ON CONFLICT(dedupe_key) DO UPDATE SET
			status = 'pending',
			error = '',
			report_id = excluded.report_id,
			program_id = excluded.program_id,
			created_at = now()
		WHERE zero_discord_notifications.status <> 'sent'
		RETURNING id::text
	`, report.ProgramID, report.ReportID, dedupeKey).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("upsert pending discord notification: %w", err)
	}
	return id, true, nil
}

func (r *Repository) FinishDiscordNotification(ctx context.Context, notificationID, status, errorText string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE zero_discord_notifications
		SET status = $2,
			error = $3,
			sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END
		WHERE id = $1::uuid
	`, notificationID, status, errorText)
	if err != nil {
		return fmt.Errorf("finish discord notification: %w", err)
	}
	return nil
}
