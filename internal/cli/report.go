package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/report"
	"github.com/spf13/cobra"
)

func newReportCommand() *cobra.Command {
	var limit int
	var programID string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate and inspect deduplicated reports.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "generate",
		Short: "Generate reports from new unreported findings.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			result, err := report.NewGenerator(repo).WithProgramID(programID).WithLimit(limit).Run(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed %d new findings, generated %d reports and inserted %d new reports\n", result.Findings, result.Reports, result.Inserted)
			return nil
		},
	})
	cmd.Commands()[0].Flags().IntVar(&limit, "limit", 500, "maximum new findings to report")
	cmd.Commands()[0].Flags().StringVar(&programID, "program-id", "", "limit reporting to one program id")
	return cmd
}
