package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/enumeration"
	"github.com/spf13/cobra"
)

func newEnumCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enum",
		Short: "Run asset enumeration tasks.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "subfinder",
		Short: "Enumerate subdomains from in-scope wildcard/domain assets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			runner := enumeration.NewSubfinderRunner(repo, cfg.Tools.SubfinderBin).
				WithProviderConfig(cfg.Tools.SubfinderProviderConfig).
				WithSources(cfg.Tools.SubfinderSources).
				WithRateLimits(cfg.Tools.SubfinderRateLimits)
			result, err := runner.Run(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed %d roots and upserted %d subdomains\n", result.Roots, result.Subdomains)
			return nil
		},
	})
	return cmd
}
