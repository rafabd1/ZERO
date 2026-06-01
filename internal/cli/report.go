package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rafabd1/ZERO/internal/report"
	"github.com/spf13/cobra"
)

func newReportCommand() *cobra.Command {
	var limit int
	var programID string
	var exportLimit int
	var exportProgramID string
	var exportStatus string
	var exportOutput string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate and inspect deduplicated reports.",
	}
	generate := &cobra.Command{
		Use:   "generate",
		Short: "Generate reports from new unreported findings.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			scanID, err := startScanRun(ctx, repo, "intel", programID)
			if err != nil {
				return err
			}
			result, err := report.NewGenerator(repo).WithScanRunID(scanID).WithProgramID(programID).WithLimit(limit).Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Findings, result.Inserted, map[string]any{
				"findings":         result.Findings,
				"passive_findings": result.PassiveFindings,
				"reports":          result.Reports,
				"inserted":         result.Inserted,
				"program_id":       programID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed %d new findings (%d passive potential), generated %d reports and inserted %d new reports\n", result.Findings, result.PassiveFindings, result.Reports, result.Inserted)
			return nil
		},
	}
	exportTriage := &cobra.Command{
		Use:   "export-triage",
		Short: "Export structured finding bundles for Proteus/Codex triage.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			bundles, err := repo.ListTriageBundles(ctx, exportProgramID, exportStatus, exportLimit)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			var file *os.File
			if exportOutput != "" {
				file, err = os.Create(exportOutput)
				if err != nil {
					return err
				}
				defer file.Close()
				out = file
			}
			enc := json.NewEncoder(out)
			for _, bundle := range bundles {
				var value any
				if err := json.Unmarshal(bundle, &value); err != nil {
					return err
				}
				if err := enc.Encode(value); err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "exported %d triage bundle(s)\n", len(bundles))
			return nil
		},
	}
	generate.Flags().IntVar(&limit, "limit", 500, "maximum new findings to report")
	generate.Flags().StringVar(&programID, "program-id", "", "limit reporting to one program id")
	exportTriage.Flags().IntVar(&exportLimit, "limit", 100, "maximum findings to export")
	exportTriage.Flags().StringVar(&exportProgramID, "program-id", "", "limit export to one program id")
	exportTriage.Flags().StringVar(&exportStatus, "status", "new", "finding status to export; empty exports all statuses")
	exportTriage.Flags().StringVar(&exportOutput, "output", "", "write JSONL bundles to this file instead of stdout")
	cmd.AddCommand(generate, exportTriage)
	return cmd
}
