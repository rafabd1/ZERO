package cli

import (
	"context"

	"github.com/rafabd1/ZERO/internal/db"
)

func startScanRun(ctx context.Context, repo *db.Repository, runType, programID string) (string, error) {
	return repo.StartScanRun(ctx, runType, "cli", programID)
}

func finishScanRun(ctx context.Context, repo *db.Repository, id string, runErr error, inputCount, insertedCount int, stats map[string]any) error {
	status := "succeeded"
	if runErr != nil {
		status = "failed"
	}
	if err := repo.FinishScanRun(ctx, id, status, inputCount, insertedCount, stats, runErr); err != nil {
		return err
	}
	return runErr
}
