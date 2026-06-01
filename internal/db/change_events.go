package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type ChangeEvent struct {
	ProgramID  string
	ScanRunID  string
	EntityType string
	EntityID   string
	EntityKey  string
	ChangeType string
	OldValue   map[string]any
	NewValue   map[string]any
}

func (r *Repository) RecordChangeEvent(ctx context.Context, event ChangeEvent) error {
	if event.ProgramID == "" || event.EntityType == "" || event.EntityKey == "" || event.ChangeType == "" {
		return nil
	}
	args := changeEventArgs(event)
	_, err := r.pool.Exec(ctx, changeEventInsertSQL, args...)
	if err != nil {
		return fmt.Errorf("record change event: %w", err)
	}
	return nil
}

func (r *Repository) RecordChangeEvents(ctx context.Context, events []ChangeEvent) error {
	batch := &pgx.Batch{}
	queued := 0
	for _, event := range events {
		if event.ProgramID == "" || event.EntityType == "" || event.EntityKey == "" || event.ChangeType == "" {
			continue
		}
		batch.Queue(changeEventInsertSQL, changeEventArgs(event)...)
		queued++
	}
	if queued == 0 {
		return nil
	}
	results := r.pool.SendBatch(ctx, batch)
	defer results.Close()
	for i := 0; i < queued; i++ {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("record change events: %w", err)
		}
	}
	return nil
}

const changeEventInsertSQL = `
	INSERT INTO zero_change_events(
		program_id, scan_run_id, entity_type, entity_id, entity_key,
		change_type, old_value, new_value, evidence_hash
	)
	VALUES ($1::uuid,NULLIF($2, '')::uuid,$3,NULLIF($4, '')::uuid,$5,$6,$7::jsonb,$8::jsonb,$9)
	ON CONFLICT(evidence_hash) DO NOTHING
`

func changeEventArgs(event ChangeEvent) []any {
	oldValue, _ := json.Marshal(emptyMap(event.OldValue))
	newValue, _ := json.Marshal(emptyMap(event.NewValue))
	evidenceHash := changeEventHash(event, newValue)
	return []any{
		event.ProgramID,
		event.ScanRunID,
		event.EntityType,
		event.EntityID,
		event.EntityKey,
		event.ChangeType,
		string(oldValue),
		string(newValue),
		evidenceHash,
	}
}

func emptyMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func changeEventHash(event ChangeEvent, newValue []byte) string {
	h := sha256.New()
	for _, part := range []string{
		event.ProgramID,
		event.EntityType,
		event.EntityKey,
		event.ChangeType,
		string(newValue),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "change:" + hex.EncodeToString(h.Sum(nil))
}
