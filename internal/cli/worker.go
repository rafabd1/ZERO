package cli

import (
	"fmt"
	"time"

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
			c := cron.New(cron.WithSeconds())
			if cfg.Worker.RecoverRunningScans {
				if err := recoverWorkerState(cmd, cfg.DatabaseURL); err != nil {
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

			if err := addJob("due-pipeline", cfg.Schedule.Full, func() {
				if err := runDuePrograms(cmd, 0, cfg.TargetParallelism, false, false); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "full pipeline failed: %v\n", err)
				}
			}); err != nil {
				return err
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

func recoverWorkerState(cmd *cobra.Command, databaseURL string) error {
	if databaseURL == "" {
		return fmt.Errorf("ZERO_DATABASE_URL is required")
	}
	ctx := commandContext()
	repo, err := db.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer repo.Close()
	recovered, err := repo.RecoverRunningScanRuns(ctx)
	if err != nil {
		return err
	}
	if recovered > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "recovered %d interrupted scan run(s)\n", recovered)
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
