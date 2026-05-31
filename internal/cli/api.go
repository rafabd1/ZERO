package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/api"
	"github.com/spf13/cobra"
)

func newAPICommand() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "Run the authenticated read API.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			srv := api.NewServer(repo, cfg.API.Token)
			fmt.Fprintf(cmd.OutOrStdout(), "zero api listening on %s\n", cfg.API.Addr)
			return srv.ListenAndServe(cfg.API.Addr)
		},
	}
}
