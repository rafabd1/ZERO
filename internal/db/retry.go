package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func withRetryableDB(ctx context.Context, attempts int, baseDelay time.Duration, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	if baseDelay <= 0 {
		baseDelay = 150 * time.Millisecond
	}
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		err = fn()
		if err == nil || !retryableDBError(err) || attempt == attempts {
			return err
		}
		delay := baseDelay * time.Duration(attempt*attempt)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func retryableDBError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40P01", "40001", "55P03":
			return true
		}
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "deadlock detected") ||
		strings.Contains(text, "could not serialize access") ||
		strings.Contains(text, "lock_not_available")
}
