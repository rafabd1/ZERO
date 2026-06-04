package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/rafabd1/ZERO/internal/config"
	"github.com/rafabd1/ZERO/internal/db"
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the main Zero pipeline.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "once",
		Short: "Run sync, scan, validation, and reporting once.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPipeline(cmd)
		},
	})
	var dueLimit int
	var dueParallelism int
	var dueDryRun bool
	var skipSync bool
	due := &cobra.Command{
		Use:   "due",
		Short: "Run the main pipeline for due programs with bounded parallelism.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDuePrograms(cmd, dueLimit, dueParallelism, dueDryRun, skipSync)
		},
	}
	due.Flags().IntVar(&dueLimit, "limit", 0, "maximum due programs to run; 0 means no explicit cap")
	due.Flags().IntVar(&dueParallelism, "parallelism", 0, "maximum programs to scan concurrently; defaults to ZERO_TARGET_PARALLELISM")
	due.Flags().BoolVar(&dueDryRun, "dry-run", false, "list due programs without syncing or scanning")
	due.Flags().BoolVar(&skipSync, "skip-sync", false, "skip the daily scope-sync guard before selecting due programs")
	cmd.AddCommand(due)
	addManualRunCommand(cmd)
	addScheduledRunCommand(cmd)
	addCancelRunCommand(cmd)
	addCleanupRunCommand(cmd)
	return cmd
}

func addCancelRunCommand(parent *cobra.Command) {
	var campaignID string
	var requestID string
	cmd := &cobra.Command{
		Use:   "cancel",
		Short: "Cancel a queued or running scan request/campaign.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if campaignID == "" && requestID == "" {
				return fmt.Errorf("set --campaign-id or --request-id")
			}
			if campaignID != "" && requestID != "" {
				return fmt.Errorf("set only one of --campaign-id or --request-id")
			}
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()
			var result db.CancelScanResult
			if campaignID != "" {
				result, err = repo.CancelScanCampaign(ctx, campaignID)
			} else {
				result, err = repo.CancelScanRequest(ctx, requestID)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "canceled %s %s: requests=%d queued=%d running=%d status=%s\n", result.Type, result.ID, result.RequestsCanceled, result.QueuedCanceled, result.RunningCanceled, result.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&campaignID, "campaign-id", "", "scan campaign id to cancel")
	cmd.Flags().StringVar(&requestID, "request-id", "", "scan request id to cancel")
	parent.AddCommand(cmd)
}

func addCleanupRunCommand(parent *cobra.Command) {
	var retentionHours int
	var retentionScans int
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete inactive inventory rows outside the configured retention window.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			if retentionHours <= 0 {
				retentionHours = cfg.Data.InactiveRetentionHours
			}
			if retentionScans < 0 {
				retentionScans = cfg.Data.InactiveRetentionScans
			}
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()
			result, err := repo.CleanupInactiveEntities(ctx, retentionHours, retentionScans)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "cleanup deleted inactive rows: scope_assets=%d subdomains=%d http_services=%d technologies=%d technology_vulnerability_matches=%d retention_hours=%d retention_scans=%d\n",
				result.ScopeAssets,
				result.Subdomains,
				result.HTTPServices,
				result.TechnologyObservations,
				result.TechnologyVulnerabilityRows,
				retentionHours,
				retentionScans,
			)
			return nil
		},
	}
	cmd.Flags().IntVar(&retentionHours, "retention-hours", 0, "delete inactive rows older than this many hours; defaults to ZERO_INACTIVE_RETENTION_HOURS")
	cmd.Flags().IntVar(&retentionScans, "retention-scans", -1, "delete inactive rows not seen in the latest N successful full scans; defaults to ZERO_INACTIVE_RETENTION_SCANS")
	parent.AddCommand(cmd)
}

func runPipeline(parent *cobra.Command) error {
	ctx := commandContext()
	cfg := loadConfig()
	steps := [][]string{
		{"sync", "all"},
		{"enum", "subfinder"},
		{"probe", "dnsx"},
		{"probe", "httpx"},
		{"enrich", "webanalyze"},
		{"analyze", "cves"},
		{"analyze", "nuclei"},
		{"report", "generate"},
		{"notify", "discord"},
	}
	for _, step := range steps {
		fmt.Fprintf(parent.OutOrStdout(), "zero pipeline step: %v\n", step)
		if err := runChildE(parent, step...); err != nil {
			alertOnTimeout(ctx, parent, cfg, "", "", step, err)
			return err
		}
	}
	return nil
}

func runDuePrograms(parent *cobra.Command, limit, parallelism int, dryRun, skipSync bool) error {
	ctx := commandContext()
	cfg := loadConfig()
	if parallelism <= 0 {
		parallelism = cfg.TargetParallelism
	}
	if parallelism < 1 {
		parallelism = 1
	}

	if !dryRun && !skipSync {
		fmt.Fprintln(parent.OutOrStdout(), "zero due step: [scope sync if due]")
		if err := runScopeSyncIfDue(parent, cfg); err != nil {
			alertOnTimeout(ctx, parent, cfg, "", "", []string{"sync", "all"}, err)
			return err
		}
	}

	repo, err := openRepositoryE(ctx, cfg)
	if err != nil {
		return err
	}
	defer repo.Close()

	queryLimit := limit
	if queryLimit <= 0 {
		queryLimit = 1000
	}
	programs, err := repo.ListDuePrograms(ctx, queryLimit)
	if err != nil {
		return err
	}
	if limit > 0 && len(programs) > limit {
		programs = programs[:limit]
	}
	if dryRun {
		fmt.Fprintf(parent.OutOrStdout(), "due programs: %d\n", len(programs))
		for _, program := range programs {
			fmt.Fprintf(parent.OutOrStdout(), "- %s/%s %s interval=%dh\n", program.Platform, program.Handle, program.ID, program.ScanIntervalHours)
		}
		return nil
	}
	if len(programs) == 0 {
		fmt.Fprintln(parent.OutOrStdout(), "no due programs")
		return nil
	}
	cycleID, err := repo.StartDefaultScanCycle(ctx, parallelism, len(programs))
	if err != nil {
		return err
	}

	jobs := make(chan db.Program)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for worker := 0; worker < parallelism; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for program := range jobs {
				if err := runProgramPipeline(ctx, parent, repo, program, cfg, cycleID); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
				if err := repo.RefreshDefaultScanCycle(ctx, cycleID); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}
		}()
	}
	for _, program := range programs {
		jobs <- program
	}
	close(jobs)
	wg.Wait()
	if err := repo.RefreshDefaultScanCycle(ctx, cycleID); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func runProgramPipeline(ctx context.Context, parent *cobra.Command, repo *db.Repository, program db.Program, cfg config.Config, cycleID string) error {
	fmt.Fprintf(parent.OutOrStdout(), "zero program pipeline starting: %s/%s %s\n", program.Platform, program.Handle, program.ID)
	if err := repo.MarkProgramScanStarted(ctx, program.ID); err != nil {
		return err
	}
	correlation := scanRunCorrelation{DefaultScanCycleID: cycleID}
	scanID, err := startScanRunWithCorrelation(ctx, repo, "full", program.ID, correlation)
	if err != nil {
		return err
	}
	correlation.ParentScanRunID = scanID
	steps := [][]string{
		{"enum", "subfinder", "--program-id", program.ID},
		{"probe", "dnsx", "--program-id", program.ID},
		{"probe", "httpx", "--program-id", program.ID},
		{"enrich", "webanalyze", "--program-id", program.ID},
		{"analyze", "cves", "--program-id", program.ID},
		{"analyze", "nuclei", "--program-id", program.ID},
		{"report", "generate", "--program-id", program.ID},
		{"notify", "discord", "--program-id", program.ID},
	}
	for _, step := range steps {
		fmt.Fprintf(parent.OutOrStdout(), "zero program step %s/%s: %v\n", program.Platform, program.Handle, step)
		if err := runChildEWithCorrelation(parent, correlation, step...); err != nil {
			alertOnTimeout(ctx, parent, cfg, program.ID, program.Handle, step, err)
			return finishScanRun(ctx, repo, scanID, err, 0, 0, map[string]any{
				"program_id": program.ID,
				"handle":     program.Handle,
				"step":       step,
			})
		}
	}
	stale, err := repo.MarkStaleEntities(ctx, program.ID, cfg.Data.StaleAfterHours)
	if err != nil {
		return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
	}
	if err := repo.MarkProgramScanFinished(ctx, program.ID); err != nil {
		return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
	}
	if err := finishScanRun(ctx, repo, scanID, nil, len(steps), 0, map[string]any{
		"program_id":          program.ID,
		"handle":              program.Handle,
		"steps":               len(steps),
		"stale_after_hours":   cfg.Data.StaleAfterHours,
		"stale_subdomains":    stale.Subdomains,
		"stale_http_services": stale.HTTPServices,
		"stale_technologies":  stale.Technologies,
	}); err != nil {
		return err
	}
	fmt.Fprintf(parent.OutOrStdout(), "zero program pipeline finished: %s/%s %s\n", program.Platform, program.Handle, program.ID)
	return nil
}
