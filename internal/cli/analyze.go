package cli

import (
	"fmt"
	"strings"

	"github.com/rafabd1/ZERO/internal/intel"
	"github.com/rafabd1/ZERO/internal/validate"
	"github.com/spf13/cobra"
)

func newAnalyzeCommand() *cobra.Command {
	var nucleiLimit int
	var nucleiTemplateID string
	var nucleiTemplatePath string
	var nucleiTags string
	var nucleiSeverities string
	var nucleiRate int
	var nucleiConcurrency int
	var nucleiBulkSize int
	var nucleiRetries int
	var nucleiTimeout int
	var nucleiFromCVEs bool
	var nucleiAllCVETemplates bool
	var nucleiCVELimit int
	var cvesProgramID string
	var cvesLimit int
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
			result, err := intel.NewNVDRunner(repo, cfg.Intel.NVDAPIKey).
				WithProgramID(cvesProgramID).
				WithScanRunID(scanID).
				WithLimit(cvesLimit).
				Run(ctx)
			if err != nil {
				return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
			}
			if err := finishScanRun(ctx, repo, scanID, nil, result.Technologies, result.Inserted, map[string]any{
				"passive_cve_matching": "intel-only",
				"technologies":         result.Technologies,
				"cves":                 result.CVEs,
				"inserted":             result.Inserted,
				"matches":              result.Matches,
				"inserted_matches":     result.InsertedMatches,
				"template_eligible":    result.TemplateEligible,
				"program_id":           cvesProgramID,
				"source":               "nvd",
				"validator":            "nuclei",
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "queried %d versioned technologies against NVD, observed %d CVE records, inserted %d records, linked %d tech/CVE matches and marked %d as Nuclei-template eligible; no findings are generated without active validation\n", result.Technologies, result.CVEs, result.Inserted, result.Matches, result.TemplateEligible)
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
			tags := firstNonEmpty(nucleiTags, cfg.Tools.NucleiTags)
			severities := firstNonEmpty(nucleiSeverities, cfg.Tools.NucleiSeverities)
			rate := firstPositive(nucleiRate, cfg.Tools.NucleiRate)
			concurrency := firstPositive(nucleiConcurrency, cfg.Tools.NucleiC)
			bulkSize := firstPositive(nucleiBulkSize, cfg.Tools.NucleiBulkSize)
			retries := nucleiRetries
			if retries < 0 {
				retries = 1
			}
			timeout := firstPositive(nucleiTimeout, 8)
			scanID, err := startScanRun(ctx, repo, "nuclei", nucleiProgramID)
			if err != nil {
				return err
			}
			fromCVEs := (cfg.Tools.NucleiFromCVEs || nucleiFromCVEs) && !nucleiAllCVETemplates && templateIDs == "" && nucleiTemplatePath == ""
			if fromCVEs {
				cveLimit := nucleiCVELimit
				if cveLimit <= 0 {
					cveLimit = cfg.Tools.NucleiCVELimit
				}
				ids, err := repo.ListCVETemplateIDsFromMatches(ctx, nucleiProgramID, severities, cveLimit)
				if err != nil {
					return finishScanRun(ctx, repo, scanID, err, 0, 0, nil)
				}
				if len(ids) == 0 {
					if err := finishScanRun(ctx, repo, scanID, nil, 0, 0, map[string]any{
						"program_id": nucleiProgramID,
						"tool":       "nuclei",
						"from_cves":  true,
						"skipped":    "no passive CVE/template candidates",
					}); err != nil {
						return err
					}
					fmt.Fprintln(cmd.OutOrStdout(), "nuclei skipped: no medium/high/critical passive CVE template candidates for this scope")
					return nil
				}
				templateIDs = strings.Join(ids, ",")
			}
			runner := validate.NewNucleiRunner(repo, cfg.Tools.NucleiBin).
				WithPolicy(tags, severities, templateIDs, rate, concurrency, bulkSize).
				WithTemplates(nucleiTemplatePath).
				WithRuntime(retries, timeout).
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
				"from_cves":         fromCVEs,
				"template_ids":      templateIDs,
				"template_paths":    nucleiTemplatePath,
				"tags":              tags,
				"severities":        severities,
				"rate":              rate,
				"concurrency":       concurrency,
				"bulk_size":         bulkSize,
				"retries":           retries,
				"timeout":           timeout,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "nuclei scanned %d URLs, observed %d results, inserted %d new results and %d new findings\n", result.Targets, result.Results, result.Inserted, result.FindingsInserted)
			return nil
		},
	})
	cmd.Commands()[0].Flags().StringVar(&cvesProgramID, "program-id", "", "query passive CVE intel for one program id")
	cmd.Commands()[0].Flags().IntVar(&cvesLimit, "limit", 25, "maximum versioned technologies to query")
	cmd.Commands()[1].Flags().IntVar(&nucleiLimit, "limit", 0, "limit number of URLs to validate")
	cmd.Commands()[1].Flags().StringVar(&nucleiTemplateID, "template-id", "", "run only matching Nuclei template id(s)")
	cmd.Commands()[1].Flags().StringVar(&nucleiTemplatePath, "template-path", "", "run Nuclei template file/directory path(s)")
	cmd.Commands()[1].Flags().StringVar(&nucleiTags, "tags", "", "override Nuclei tags for this run")
	cmd.Commands()[1].Flags().StringVar(&nucleiSeverities, "severity", "", "override Nuclei severities for this run")
	cmd.Commands()[1].Flags().IntVar(&nucleiRate, "rate-limit", 0, "override Nuclei rate limit for this run")
	cmd.Commands()[1].Flags().IntVar(&nucleiConcurrency, "concurrency", 0, "override Nuclei concurrency for this run")
	cmd.Commands()[1].Flags().IntVar(&nucleiBulkSize, "bulk-size", 0, "override Nuclei bulk size for this run")
	cmd.Commands()[1].Flags().IntVar(&nucleiRetries, "retries", -1, "override Nuclei retries for this run")
	cmd.Commands()[1].Flags().IntVar(&nucleiTimeout, "timeout", 0, "override Nuclei timeout seconds for this run")
	cmd.Commands()[1].Flags().BoolVar(&nucleiFromCVEs, "from-cves", false, "run only Nuclei template ids linked from passive CVE matching")
	cmd.Commands()[1].Flags().BoolVar(&nucleiAllCVETemplates, "all-cve-templates", false, "ignore passive CVE matches and run configured tag/template policy")
	cmd.Commands()[1].Flags().IntVar(&nucleiCVELimit, "cve-limit", 0, "maximum passive CVE template ids to pass to Nuclei")
	cmd.Commands()[1].Flags().StringVar(&nucleiProgramID, "program-id", "", "limit Nuclei validation to one program id")
	return cmd
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
