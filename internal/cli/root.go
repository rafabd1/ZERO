package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
		Short: "Zero runs durable recon, fingerprinting, and validation campaigns at scale.",
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
		sleep := repositoryRetryDelay(wait, attempt, err)
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("open repository after %d attempt(s): %w", attempts, lastErr)
}

func repositoryRetryDelay(base time.Duration, attempt int, err error) time.Duration {
	if base <= 0 {
		base = 3 * time.Second
	}
	if attempt < 1 {
		attempt = 1
	}
	delay := base * time.Duration(attempt)
	if retryableRepositoryOpenError(err) {
		delay = base * time.Duration(1<<minInt(attempt-1, 4))
		if delay < 10*time.Second {
			delay = 10 * time.Second
		}
	}
	if delay > time.Minute {
		delay = time.Minute
	}
	return delay
}

func retryableRepositoryOpenError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"emaxconnsession",
		"max clients reached",
		"failed to connect",
		"connection refused",
		"connection reset",
		"connection timed out",
		"server closed",
		"temporary failure",
		"timeout",
		"deadline exceeded",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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
