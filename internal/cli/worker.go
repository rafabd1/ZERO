package cli

import (
	"fmt"
	"sync"
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
			if cfg.AutoMigrate {
				if err := db.Migrate(commandContext(), cfg.DatabaseURL); err != nil {
					return err
				}
			}
			c := cron.New(cron.WithSeconds())
			if cfg.Worker.RecoverRunningScans {
				if err := recoverWorkerState(cmd, cfg); err != nil {
					return err
				}
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
			if err := addJob("due-pipeline", cfg.Schedule.Full, func() {
				if err := runDuePrograms(cmd, 0, cfg.TargetParallelism, false, false); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "full pipeline failed: %v\n", err)
				}
			}); err != nil {
				return err
			}
			if err := addJob("scan-requests", "*/30 * * * * *", func() {
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

			c.Start()
			if cfg.Worker.RunOnStartup {
				go func() {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting startup due-pipeline\n", time.Now().UTC().Format(time.RFC3339))
					if err := runDuePrograms(cmd, 0, cfg.TargetParallelism, false, false); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "startup full pipeline failed: %v\n", err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] finished startup due-pipeline\n", time.Now().UTC().Format(time.RFC3339))
				}()
			}
			<-commandContext().Done()
			ctx := c.Stop()
			<-ctx.Done()
			return nil
		},
	}
}

func runQueuedScanRequests(cmd *cobra.Command, cfg config.Config) error {
	ctx := commandContext()
	repo, err := openRepositoryE(ctx, cfg)
	if err != nil {
		return err
	}
	defer repo.Close()
	requests, err := repo.ClaimDueScanRequests(ctx, cfg.TargetParallelism)
	if err != nil {
		return err
	}
	var firstErr error
	var firstErrMu sync.Mutex
	var wg sync.WaitGroup
	for _, request := range requests {
		request := request
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := runQueuedScanRequest(cmd, repo, request)
			if err != nil {
				firstErrMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				firstErrMu.Unlock()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func runQueuedScanRequest(cmd *cobra.Command, repo *db.Repository, request db.ScanRequest) error {
	ctx := commandContext()
	opts, err := manualRunOptionsFromJSON(request.Params)
	if err == nil && opts.ProgramID == "" {
		opts.ProgramID = request.ProgramID
	}
	if err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "zero scan request starting: %s %s\n", request.ID, request.Name)
		err = runManualPipeline(cmd, opts)
	}
	if finishErr := repo.FinishScanRequest(ctx, request.ID, err); finishErr != nil && err == nil {
		err = finishErr
	}
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "zero scan request failed %s: %v\n", request.ID, err)
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "zero scan request finished: %s\n", request.ID)
	return nil
}

func recoverWorkerState(cmd *cobra.Command, cfg config.Config) error {
	ctx := commandContext()
	repo, err := openRepositoryE(ctx, cfg)
	if err != nil {
		return err
	}
	defer repo.Close()
	recovered, err := repo.RecoverRunningScanRuns(ctx)
	if err != nil {
		return err
	}
	requeued, err := repo.RecoverRunningScanRequests(ctx)
	if err != nil {
		return err
	}
	recoveredCampaigns, err := repo.RecoverRunningScanCampaigns(ctx)
	if err != nil {
		return err
	}
	if recovered > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "recovered %d interrupted scan run(s)\n", recovered)
	}
	if requeued > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "requeued %d interrupted scan request(s)\n", requeued)
	}
	if recoveredCampaigns > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "refreshed %d interrupted scan campaign(s)\n", recoveredCampaigns)
	}
	return nil
}

func runChild(parent *cobra.Command, args ...string) {
	if err := runChildE(parent, args...); err != nil {
		fmt.Fprintf(parent.ErrOrStderr(), "task %v failed: %v\n", args, err)
	}
}

func runChildE(parent *cobra.Command, args ...string) error {
	child := newRootCommand()
	child.SetArgs(args)
	child.SetOut(parent.OutOrStdout())
	child.SetErr(parent.ErrOrStderr())
	if err := child.Execute(); err != nil {
		return fmt.Errorf("task %v failed: %w", args, err)
	}
	return nil
}
