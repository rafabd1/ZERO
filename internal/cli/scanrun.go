package cli

import (
	"context"
	"strings"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/spf13/cobra"
)

const (
	internalDefaultScanCycleFlag = "zero-default-scan-cycle-id"
	internalParentScanRunFlag    = "zero-parent-scan-run-id"
	internalScanRequestFlag      = "zero-scan-request-id"
	internalScanCampaignFlag     = "zero-scan-campaign-id"
)

type scanRunCorrelation struct {
	DefaultScanCycleID string
	ParentScanRunID    string
	ScanRequestID      string
	ScanCampaignID     string
}

func startScanRun(ctx context.Context, cmd *cobra.Command, repo *db.Repository, runType, programID string) (string, error) {
	return repo.StartScanRunWithOptions(ctx, runType, "cli", programID, scanRunOptionsFromCommand(cmd))
}

func startScanRunWithCorrelation(ctx context.Context, repo *db.Repository, runType, programID string, correlation scanRunCorrelation) (string, error) {
	return repo.StartScanRunWithOptions(ctx, runType, "cli", programID, db.ScanRunOptions{
		DefaultScanCycleID: correlation.DefaultScanCycleID,
		ParentScanRunID:    correlation.ParentScanRunID,
		ScanRequestID:      correlation.ScanRequestID,
		ScanCampaignID:     correlation.ScanCampaignID,
	})
}

func scanRunOptionsFromCommand(cmd *cobra.Command) db.ScanRunOptions {
	correlation := scanRunCorrelationFromCommand(cmd)
	return db.ScanRunOptions{
		DefaultScanCycleID: correlation.DefaultScanCycleID,
		ParentScanRunID:    correlation.ParentScanRunID,
		ScanRequestID:      correlation.ScanRequestID,
		ScanCampaignID:     correlation.ScanCampaignID,
	}
}

func scanRunCorrelationFromCommand(cmd *cobra.Command) scanRunCorrelation {
	if cmd == nil {
		return scanRunCorrelation{}
	}
	root := cmd.Root()
	if root == nil {
		root = cmd
	}
	return scanRunCorrelation{
		DefaultScanCycleID: internalFlagValue(root, internalDefaultScanCycleFlag),
		ParentScanRunID:    internalFlagValue(root, internalParentScanRunFlag),
		ScanRequestID:      internalFlagValue(root, internalScanRequestFlag),
		ScanCampaignID:     internalFlagValue(root, internalScanCampaignFlag),
	}
}

func internalFlagValue(cmd *cobra.Command, name string) string {
	flag := cmd.PersistentFlags().Lookup(name)
	if flag == nil {
		return ""
	}
	return strings.TrimSpace(flag.Value.String())
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
