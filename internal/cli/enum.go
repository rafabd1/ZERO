package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/enumeration"
	"github.com/spf13/cobra"
)

func newEnumCommand() *cobra.Command {
	var subfinderLimit int
	var programID string
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

			scanID, err := startScanRun(ctx, repo, "enum", programID)
			if err != nil {
				return err
			}
			runner := enumeration.NewSubfinderRunner(repo, cfg.Tools.SubfinderBin).
				WithProviderConfig(cfg.Tools.SubfinderProviderConfig).
				WithSources(cfg.Tools.SubfinderSources).
				WithRateLimits(cfg.Tools.SubfinderRateLimits).
				WithProgramID(programID).
				WithLimit(subfinderLimit)
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Roots, result.Subdomains, map[string]any{
				"roots":      result.Roots,
				"subdomains": result.Subdomains,
				"tool":       "subfinder",
				"program_id": programID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed %d roots and upserted %d subdomains\n", result.Roots, result.Subdomains)
			return nil
		},
	})
	cmd.Commands()[0].Flags().IntVar(&subfinderLimit, "limit", 0, "limit number of roots to enumerate")
	cmd.Commands()[0].Flags().StringVar(&programID, "program-id", "", "limit enumeration to one program id")
	return cmd
}
