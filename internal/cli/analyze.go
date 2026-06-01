package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/validate"
	"github.com/spf13/cobra"
)

func newAnalyzeCommand() *cobra.Command {
	var nucleiLimit int
	var nucleiTemplateID string
	var cvesProgramID string
	var nucleiProgramID string
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Run vulnerability intelligence matching tasks.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "cves",
		Short: "Record passive intel policy for CVE matching.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			scanID, err := startScanRun(ctx, repo, "intel", cvesProgramID)
			if err != nil {
				return err
			}
			if err := finishScanRun(ctx, repo, scanID, nil, 0, 0, map[string]any{
				"passive_cve_matching": "disabled",
				"httpx_role":           "target-intel",
				"program_id":           cvesProgramID,
				"validator":            "nuclei",
			}); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "passive CVE matching is disabled; httpx fingerprints are stored as intel and Nuclei is the CVE validation/reporting source")
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
			scanID, err := startScanRun(ctx, repo, "nuclei", nucleiProgramID)
			if err != nil {
				return err
			}
			runner := validate.NewNucleiRunner(repo, cfg.Tools.NucleiBin).
				WithPolicy(cfg.Tools.NucleiTags, cfg.Tools.NucleiSeverities, templateIDs, cfg.Tools.NucleiRate, cfg.Tools.NucleiC, cfg.Tools.NucleiBulkSize).
				WithScanRunID(scanID).
				WithProgramID(nucleiProgramID).
				WithLimit(nucleiLimit)
			result, err := runner.Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Targets, result.FindingsInserted, map[string]any{
				"targets":           result.Targets,
				"results":           result.Results,
				"inserted_results":  result.Inserted,
				"inserted_findings": result.FindingsInserted,
				"program_id":        nucleiProgramID,
				"tool":              "nuclei",
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "nuclei scanned %d URLs, observed %d results, inserted %d new results and %d new findings\n", result.Targets, result.Results, result.Inserted, result.FindingsInserted)
			return nil
		},
	})
	cmd.Commands()[0].Flags().StringVar(&cvesProgramID, "program-id", "", "record intel policy for one program id")
	cmd.Commands()[1].Flags().IntVar(&nucleiLimit, "limit", 0, "limit number of URLs to validate")
	cmd.Commands()[1].Flags().StringVar(&nucleiTemplateID, "template-id", "", "run only matching Nuclei template id(s)")
	cmd.Commands()[1].Flags().StringVar(&nucleiProgramID, "program-id", "", "limit Nuclei validation to one program id")
	return cmd
}
