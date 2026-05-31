package db

import (
	"context"
	"encoding/json"
	"fmt"
)

func (r *Repository) QueryJSONRows(ctx context.Context, query string, args ...any) ([]json.RawMessage, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []json.RawMessage
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, append(json.RawMessage(nil), raw...))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query json rows: %w", err)
	}
	return out, nil
}
