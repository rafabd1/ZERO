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
	subfinder := &cobra.Command{
		Use:   "subfinder",
		Short: "Enumerate subdomains from in-scope wildcard/domain assets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo, err := openRepositoryE(ctx, cfg)
			if err != nil {
				return err
			}
			defer repo.Close()

			scanID, err := startScanRun(ctx, repo, "enum", programID)
			if err != nil {
				return err
			}
			runner := enumeration.NewSubfinderRunner(repo, cfg.Tools.SubfinderBin).
				WithProviderConfig(cfg.Tools.SubfinderProviderConfig).
				WithSources(cfg.Tools.SubfinderSources).
				WithRateLimits(cfg.Tools.SubfinderRateLimits).
				WithScanRunID(scanID).
				WithProgramID(programID).
				WithLimit(subfinderLimit).
				WithTimeout(cfg.Tools.ToolTimeout)
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Roots, result.Subdomains, map[string]any{
				"roots":      result.Roots,
				"scoped":     result.Scoped,
				"subdomains": result.Subdomains,
				"tool":       "subfinder",
				"program_id": programID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed %d roots, added %d scoped subdomains and upserted %d total subdomains\n", result.Roots, result.Scoped, result.Subdomains)
			return nil
		},
	}
	subfinder.Flags().IntVar(&subfinderLimit, "limit", 0, "limit number of roots to enumerate")
	subfinder.Flags().StringVar(&programID, "program-id", "", "limit enumeration to one program id")
	cmd.AddCommand(subfinder)
	return cmd
}
