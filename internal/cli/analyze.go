package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAnalyzeCommand() *cobra.Command {
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
		Short: "Placeholder for optimized Nuclei validation.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			fmt.Fprintf(cmd.OutOrStdout(), "Nuclei validation will use %s with rate=%d concurrency=%d; implementation is tracked in docs/NUCLEI.md\n", cfg.Tools.NucleiBin, cfg.Tools.NucleiRate, cfg.Tools.NucleiC)
			return nil
		},
	})
	return cmd
}
