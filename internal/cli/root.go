package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
	root.AddCommand(newAnalyzeCommand())
	root.AddCommand(newWorkerCommand())
	root.AddCommand(newAPICommand())

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
	if cfg.DatabaseURL == "" {
		cobra.CheckErr("ZERO_DATABASE_URL is required")
	}
	repo, err := db.Open(ctx, cfg.DatabaseURL)
	cobra.CheckErr(err)
	return repo
}
