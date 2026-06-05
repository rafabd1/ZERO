package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rafabd1/ZERO/internal/config"
	"github.com/rafabd1/ZERO/internal/db"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
)

func newWorkerCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Run scheduled monitoring tasks.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			ctx := commandContext()
			if cfg.AutoMigrate {
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting startup migration\n", time.Now().UTC().Format(time.RFC3339))
				migrateCtx, cancel := workerStartupContext(ctx)
				err := db.Migrate(migrateCtx, cfg.DatabaseURL)
				cancel()
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "startup migration failed: %v\n", err)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] finished startup migration\n", time.Now().UTC().Format(time.RFC3339))
				}
				// The worker performs the startup migration once. Child commands run in
				// the same process and should not try to acquire the migration lock for
				// every scan step.
				_ = os.Setenv("ZERO_AUTO_MIGRATE", "false")
				cfg.AutoMigrate = false
			}
			c := cron.New(cron.WithSeconds())
			if cfg.Worker.RecoverRunningScans {
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting startup recovery\n", time.Now().UTC().Format(time.RFC3339))
				recoveryCtx, cancel := workerRecoveryContext(ctx)
				if err := recoverWorkerState(recoveryCtx, cmd, cfg); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "startup recovery failed: %v\n", err)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] finished startup recovery\n", time.Now().UTC().Format(time.RFC3339))
				}
				cancel()
			}

			addJob := func(name, spec string, fn func()) error {
				_, err := c.AddFunc(spec, func() {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting %s\n", time.Now().UTC().Format(time.RFC3339), name)
					fn()
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] finished %s\n", time.Now().UTC().Format(time.RFC3339), name)
				})
				return err
			}

			var scanRequestsRunning atomic.Bool
			var duePipelineRunning atomic.Bool
			var cleanupRunning atomic.Bool
			runDueJob := func(name string, limit int) {
				if cleanupRunning.Load() {
					fmt.Fprintf(cmd.OutOrStdout(), "%s skipped: cleanup is running\n", name)
					return
				}
				if !duePipelineRunning.CompareAndSwap(false, true) {
					fmt.Fprintf(cmd.OutOrStdout(), "%s skipped: previous due pipeline still running\n", name)
					return
				}
				defer duePipelineRunning.Store(false)
				if err := runDuePrograms(cmd, limit, cfg.TargetParallelism, false, true); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s failed: %v\n", name, err)
				}
			}
			if err := addJob("scope-sync", cfg.Schedule.ScopeSync, func() {
				if err := runScopeSync(cmd, cfg, scopeProviders(cfg.Scope.Providers)); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "scope sync failed: %v\n", err)
				}
			}); err != nil {
				return err
			}
			if err := addJob("due-pipeline", cfg.Schedule.Full, func() {
				runDueJob("full pipeline", 0)
			}); err != nil {
				return err
			}
			if err := addJob("scan-requests", "*/30 * * * * *", func() {
				if cleanupRunning.Load() {
					fmt.Fprintln(cmd.OutOrStdout(), "scan request processing skipped: cleanup is running")
					return
				}
				if !scanRequestsRunning.CompareAndSwap(false, true) {
					fmt.Fprintln(cmd.OutOrStdout(), "scan request processing skipped: previous tick still running")
					return
				}
				defer scanRequestsRunning.Store(false)
				if err := runQueuedScanRequests(cmd, cfg); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "scan request processing failed: %v\n", err)
				}
			}); err != nil {
				return err
			}
			if cfg.Tools.NucleiUpdateTemplates {
				if err := addJob("nuclei-template-update", cfg.Schedule.NucleiTemplates, func() {
					if err := updateNucleiTemplates(commandContext(), cmd, cfg); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "nuclei template update failed: %v\n", err)
					}
				}); err != nil {
					return err
				}
			}
			if err := addJob("cleanup-inactive", cfg.Schedule.Cleanup, func() {
				if duePipelineRunning.Load() || scanRequestsRunning.Load() {
					fmt.Fprintln(cmd.OutOrStdout(), "cleanup inactive skipped: scans are running")
					return
				}
				if !cleanupRunning.CompareAndSwap(false, true) {
					fmt.Fprintln(cmd.OutOrStdout(), "cleanup inactive skipped: previous cleanup still running")
					return
				}
				defer cleanupRunning.Store(false)
				if err := runChildE(cmd, "run", "cleanup"); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "cleanup inactive failed: %v\n", err)
				}
			}); err != nil {
				return err
			}

			c.Start()
			if cfg.Worker.RunOnStartup {
				go func() {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting startup scope-sync-if-due\n", time.Now().UTC().Format(time.RFC3339))
					if err := runScopeSyncIfDue(cmd, cfg); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "startup scope sync failed: %v\n", err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] finished startup scope-sync-if-due\n", time.Now().UTC().Format(time.RFC3339))
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting startup due-pipeline\n", time.Now().UTC().Format(time.RFC3339))
					runDueJob("startup full pipeline", 0)
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] finished startup due-pipeline\n", time.Now().UTC().Format(time.RFC3339))
				}()
			}
			<-ctx.Done()
			stopCtx := c.Stop()
			<-stopCtx.Done()
			return nil
		},
	}
}

func workerStartupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 2*time.Minute)
}

func workerRecoveryContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 30*time.Second)
}

func runQueuedScanRequests(cmd *cobra.Command, cfg config.Config) error {
	ctx := commandContext()
	repo, err := openRepositoryE(ctx, cfg)
	if err != nil {
		return err
	}
	defer repo.Close()
	stale, err := repo.RecoverStaleScanRequests(ctx, cfg.Worker.ScanRequestStaleAfter)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "scan request stale recovery failed: %v\n", err)
	} else if stale > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "requeued %d stale scan request(s)\n", stale)
	}
	retryPolicy := scanRequestRetryPolicy(cfg)
	recovered, err := repo.RecoverRetryableFailedScanRequests(ctx, retryPolicy)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "scan request retry recovery failed: %v\n", err)
	} else if recovered > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "requeued %d transiently failed scan request(s)\n", recovered)
	}

	type scanRequestResult struct {
		id  string
		err error
	}
	done := make(chan scanRequestResult)
	var firstErr error
	active := 0
	totalStarted := 0

	startRequest := func(request db.ScanRequest) {
		active++
		totalStarted++
		go func() {
			done <- scanRequestResult{
				id:  request.ID,
				err: runQueuedScanRequest(cmd, repo, request, cfg),
			}
		}()
	}

	for {
		limit, err := repo.ScanRequestWorkerCapacity(ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if active == 0 {
				return firstErr
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "scan request capacity lookup failed with %d active worker(s): %v\n", active, err)
			limit = active
		}
		limit = scanRequestEffectiveLimit(limit, cfg.Worker.ScanRequestMaxActive)
		for active < limit {
			requests, err := repo.ClaimDueScanRequests(ctx, limit-active)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				if active == 0 {
					return firstErr
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "scan request claim failed with %d active worker(s): %v\n", active, err)
				break
			}
			if len(requests) == 0 {
				break
			}
			for _, request := range requests {
				startRequest(request)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "scan request pool claimed %d request(s), active=%d/%d\n", len(requests), active, limit)
		}

		if active == 0 {
			if totalStarted > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "scan request pool drained after %d request(s)\n", totalStarted)
			}
			return firstErr
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-done:
			active--
			if result.err != nil && firstErr == nil {
				firstErr = result.err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "scan request pool slot released: %s active=%d/%d\n", result.id, active, limit)
		}
	}
}

func runQueuedScanRequest(cmd *cobra.Command, repo *db.Repository, request db.ScanRequest, cfg config.Config) error {
	ctx := commandContext()
	opts, err := manualRunOptionsFromJSON(request.Params)
	if err == nil && opts.ProgramID == "" {
		opts.ProgramID = request.ProgramID
	}
	if err == nil {
		opts.ScanRequestID = request.ID
		opts.ScanCampaignID = request.CampaignID
	}
	stopHeartbeat := startScanRequestHeartbeat(ctx, cmd, repo, request.ID, cfg.Worker.ScanRequestHeartbeat)
	defer stopHeartbeat()
	if err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "zero scan request starting: %s %s\n", request.ID, request.Name)
		err = runManualPipelineWithProgress(cmd, opts, repo)
	}
	if finishErr := repo.FinishScanRequest(ctx, request.ID, err, scanRequestRetryPolicy(cfg)); finishErr != nil {
		if err != nil {
			err = fmt.Errorf("%w; finish scan request: %v", err, finishErr)
		} else {
			err = finishErr
		}
	}
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "zero scan request failed %s: %v\n", request.ID, err)
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "zero scan request finished: %s\n", request.ID)
	return nil
}

func startScanRequestHeartbeat(ctx context.Context, cmd *cobra.Command, repo *db.Repository, requestID string, interval time.Duration) func() {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	heartbeatCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				if err := repo.TouchScanRequest(heartbeatCtx, requestID); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "scan request heartbeat failed %s: %v\n", requestID, err)
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func scanRequestRetryPolicy(cfg config.Config) db.ScanRequestRetryPolicy {
	return db.ScanRequestRetryPolicy{
		MaxAttempts: cfg.Worker.ScanRequestRetryAttempts,
		BaseDelay:   cfg.Worker.ScanRequestRetryBaseDelay,
	}
}

func scanRequestEffectiveLimit(capacity, maxActive int) int {
	if capacity < 1 {
		capacity = 1
	}
	if maxActive > 0 && capacity > maxActive {
		return maxActive
	}
	return capacity
}

func recoverWorkerState(ctx context.Context, cmd *cobra.Command, cfg config.Config) error {
	repo, err := openRepositoryE(ctx, cfg)
	if err != nil {
		return err
	}
	defer repo.Close()
	fmt.Fprintln(cmd.OutOrStdout(), "startup recovery: scan runs")
	recovered, err := repo.RecoverRunningScanRuns(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "startup recovery: scan requests")
	requeued, err := repo.RecoverRunningScanRequests(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "startup recovery: stale scan requests")
	stale, err := repo.RecoverStaleScanRequests(ctx, cfg.Worker.ScanRequestStaleAfter)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "startup recovery: retryable failed scan requests")
	retried, err := repo.RecoverRetryableFailedScanRequests(ctx, scanRequestRetryPolicy(cfg))
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "startup recovery: scan campaigns")
	recoveredCampaigns, err := repo.RecoverRunningScanCampaigns(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "startup recovery: default scan cycles")
	refreshedDefaultCycles, err := repo.RefreshRunningDefaultScanCycles(ctx)
	if err != nil {
		return err
	}
	if recovered > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "recovered %d interrupted scan run(s)\n", recovered)
	}
	if requeued > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "requeued %d interrupted scan request(s)\n", requeued)
	}
	if stale > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "requeued %d stale scan request(s)\n", stale)
	}
	if retried > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "requeued %d transiently failed scan request(s)\n", retried)
	}
	if recoveredCampaigns > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "refreshed %d interrupted scan campaign(s)\n", recoveredCampaigns)
	}
	if refreshedDefaultCycles > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "refreshed %d running default scan cycle(s)\n", refreshedDefaultCycles)
	}
	return nil
}

func runChild(parent *cobra.Command, args ...string) {
	if err := runChildE(parent, args...); err != nil {
		fmt.Fprintf(parent.ErrOrStderr(), "task %v failed: %v\n", args, err)
	}
}

func runChildE(parent *cobra.Command, args ...string) error {
	return runChildEWithCorrelation(parent, scanRunCorrelation{}, args...)
}

func runChildEWithCorrelation(parent *cobra.Command, correlation scanRunCorrelation, args ...string) error {
	child := newRootCommand()
	child.SetArgs(appendInternalScanRunCorrelation(args, correlation))
	child.SetOut(parent.OutOrStdout())
	child.SetErr(parent.ErrOrStderr())
	if err := child.Execute(); err != nil {
		return fmt.Errorf("task %v failed: %w", args, err)
	}
	return nil
}

func appendInternalScanRunCorrelation(args []string, correlation scanRunCorrelation) []string {
	out := append([]string{}, args...)
	if strings.TrimSpace(correlation.DefaultScanCycleID) != "" {
		out = append(out, "--"+internalDefaultScanCycleFlag, strings.TrimSpace(correlation.DefaultScanCycleID))
	}
	if strings.TrimSpace(correlation.ParentScanRunID) != "" {
		out = append(out, "--"+internalParentScanRunFlag, strings.TrimSpace(correlation.ParentScanRunID))
	}
	if strings.TrimSpace(correlation.ScanRequestID) != "" {
		out = append(out, "--"+internalScanRequestFlag, strings.TrimSpace(correlation.ScanRequestID))
	}
	if strings.TrimSpace(correlation.ScanCampaignID) != "" {
		out = append(out, "--"+internalScanCampaignFlag, strings.TrimSpace(correlation.ScanCampaignID))
	}
	return out
}
