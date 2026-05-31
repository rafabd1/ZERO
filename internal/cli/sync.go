package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/scope"
	"github.com/spf13/cobra"
)

func newSyncCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize scope sources.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "h1",
		Short: "Synchronize HackerOne scopes through the bbscope poller.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			if cfg.HackerOne.Username == "" || cfg.HackerOne.Token == "" {
				return fmt.Errorf("ZERO_H1_USERNAME and ZERO_H1_TOKEN are required")
			}

			svc := scope.NewService(repo)
			result, err := svc.SyncHackerOne(ctx, scope.HackerOneOptions{
				Username:    cfg.HackerOne.Username,
				Token:       cfg.HackerOne.Token,
				BountyOnly:  cfg.Scope.BountyOnly,
				PrivateOnly: cfg.Scope.PrivateOnly,
				Categories:  cfg.Scope.Categories,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "synced %d HackerOne programs and %d scope assets\n", result.Programs, result.Assets)
			return nil
		},
	})
	return cmd
}
