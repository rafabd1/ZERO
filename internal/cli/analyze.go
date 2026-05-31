package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/validate"
	"github.com/spf13/cobra"
)

func newAnalyzeCommand() *cobra.Command {
	var nucleiLimit int
	var nucleiTemplateID string
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Run vulnerability intelligence matching tasks.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "cves",
		Short: "Placeholder for CVE matching pipeline.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "CVE matching schema is ready; matcher implementation is tracked in docs/ROADMAP.md")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "nuclei",
		Short: "Run optimized Nuclei validation against alive HTTP services.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			templateIDs := cfg.Tools.NucleiTemplateIDs
			if nucleiTemplateID != "" {
				templateIDs = nucleiTemplateID
			}
			runner := validate.NewNucleiRunner(repo, cfg.Tools.NucleiBin).
				WithPolicy(cfg.Tools.NucleiTags, cfg.Tools.NucleiSeverities, templateIDs, cfg.Tools.NucleiRate, cfg.Tools.NucleiC, cfg.Tools.NucleiBulkSize).
				WithLimit(nucleiLimit)
			result, err := runner.Run(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "nuclei scanned %d URLs, observed %d results, inserted %d new results and %d new findings\n", result.Targets, result.Results, result.Inserted, result.FindingsInserted)
			return nil
		},
	})
	cmd.Commands()[1].Flags().IntVar(&nucleiLimit, "limit", 0, "limit number of URLs to validate")
	cmd.Commands()[1].Flags().StringVar(&nucleiTemplateID, "template-id", "", "run only matching Nuclei template id(s)")
	return cmd
}
