package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rafabd1/ZERO/internal/config"
	"github.com/rafabd1/ZERO/internal/db"
	"github.com/spf13/cobra"
)

func Execute() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "zero",
		Short: "Zero monitors bug bounty scopes and vulnerable exposed technologies.",
	}

	root.AddCommand(newMigrateCommand())
	root.AddCommand(newSyncCommand())
	root.AddCommand(newEnumCommand())
	root.AddCommand(newProbeCommand())
	root.AddCommand(newEnrichCommand())
	root.AddCommand(newAnalyzeCommand())
	root.AddCommand(newReportCommand())
	root.AddCommand(newNotifyCommand())
	root.AddCommand(newRunCommand())
	root.AddCommand(newWorkerCommand())
	root.AddCommand(newAPICommand())
	root.AddCommand(newToolsCommand())
	root.AddCommand(newDevCommand())

	return root
}

func commandContext() context.Context {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ctx
}

func loadConfig() config.Config {
	cfg, err := config.Load()
	cobra.CheckErr(err)
	return cfg
}

func openRepository(ctx context.Context, cfg config.Config) *db.Repository {
	repo, err := openRepositoryE(ctx, cfg)
	cobra.CheckErr(err)
	return repo
}

func openRepositoryE(ctx context.Context, cfg config.Config) (*db.Repository, error) {
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("ZERO_DATABASE_URL is required")
	}
	attempts := cfg.DatabaseRetries
	if attempts < 1 {
		attempts = 1
	}
	wait := cfg.DatabaseRetryWait
	if wait <= 0 {
		wait = 3 * time.Second
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		repo, err := openRepositoryOnce(ctx, cfg)
		if err == nil {
			return repo, nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("open repository after %d attempt(s): %w", attempts, lastErr)
}

func openRepositoryOnce(ctx context.Context, cfg config.Config) (*db.Repository, error) {
	if cfg.AutoMigrate {
		if err := db.Migrate(ctx, cfg.DatabaseURL); err != nil {
			return nil, err
		}
	}
	repo, err := db.OpenWithMaxConns(ctx, cfg.DatabaseURL, cfg.DatabaseMaxConns)
	if err != nil {
		return nil, err
	}
	return repo, nil
}
