package db

import (
	"context"
	"embed"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Repository struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, databaseURL string) (*Repository, error) {
	return OpenWithMaxConns(ctx, databaseURL, 1)
}

func OpenWithMaxConns(ctx context.Context, databaseURL string, maxConns int) (*Repository, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = int32(maxConns)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Repository{pool: pool}, nil
}

func (r *Repository) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}

func Migrate(ctx context.Context, databaseURL string) error {
	repo, err := OpenWithMaxConns(ctx, databaseURL, 1)
	if err != nil {
		return err
	}
	defer repo.Close()

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	tx, err := repo.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zero_migrations', 0))`); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}

	for _, name := range names {
		sqlBytes, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return tx.Commit(ctx)
}
